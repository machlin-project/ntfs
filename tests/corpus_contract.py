#!/usr/bin/env python3
"""Exercise the Windows corpus transport against independent synthetic fixtures."""
from copy import deepcopy
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import fixtures
import windows_corpus as corpus

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import collect_windows_corpus as collector

HARD_LINK_COUNT = 3
UNPAIRED_HIGH_SURROGATE = 0xd800
UNPAIRED_LOW_SURROGATE = 0xdc00
WINDOWS_FILE_INFORMATION_BYTES = 52
WINDOWS_VOLUME_INFORMATION_BYTES = 96
WINDOWS_STREAM_INFORMATION_BYTES = 600
WINDOWS_MAX_NAME_UNITS = 255


def sanitizer_contracts():
    """Inspect the real launcher arguments without starting a modeled reader."""
    with patch.dict(os.environ, {'API_KEY': 'synthetic-secret', 'UNKNOWN_CREDENTIAL': 'synthetic-secret',
                                 'ASAN_OPTIONS': 'halt_on_error=0:detect_leaks=0',
                                 'UBSAN_OPTIONS': 'halt_on_error=0', 'CC': 'untrusted-compiler'}), \
            patch.object(corpus.subprocess, 'Popen', side_effect=OSError('stop before launch')) as launch:
        try:
            corpus.tool(Path('/unlaunched-reader'), Path('/unopened-image'), 'info-json')
        except OSError as error:
            assert str(error) == 'stop before launch'
        else:
            raise AssertionError('The launcher was not intercepted before execution')
        environment = launch.call_args.kwargs['env']
    assert launch.call_count == 1
    assert 'API_KEY' not in environment and 'UNKNOWN_CREDENTIAL' not in environment and 'CC' not in environment
    for kind in ('ASAN_OPTIONS', 'UBSAN_OPTIONS'):
        assert 'halt_on_error=1' in environment[kind] and 'abort_on_error=1' in environment[kind]
        assert 'halt_on_error=0' not in environment[kind] and 'detect_leaks=0' not in environment[kind]


def raw_tail_contracts(directory):
    """A complete-cluster prefix plus seven independently authored tail sectors."""
    sector, cluster = 512, 4096
    original = b'C' * cluster + b'T' * (7 * sector)

    class FakeAPI(collector.WindowsAPI):
        def __init__(self, refuse_control=False):
            self.position, self.extended, self.closed = 0, False, False
            self.reads, self.controls, self.opens = [], [], []
            self.refuse_control = refuse_control
            self.kernel = SimpleNamespace(ReadFile=self.read, DeviceIoControl=self.control)

        @contextmanager
        def open(self, source, access):
            self.opens.append((source, access))
            try:
                yield 123
            finally:
                self.closed = True

        def error(self):
            return OSError('Synthetic DASD control refusal')

        def control(self, handle, code, data, data_bytes, output, output_bytes, returned, overlap):
            self.controls.append(code)
            assert code == 0x00090083 and handle == 123
            assert data is output is overlap is None and data_bytes == output_bytes == 0
            if self.refuse_control:
                return False
            self.extended = True
            returned._obj.value = 0
            return True

        def read(self, handle, buffer, amount, returned, overlap):
            limit = len(original) if self.extended else cluster
            count = min(amount, limit - self.position)
            assert count >= 0 and handle == 123 and overlap is None
            self.reads.append((self.position, amount))
            ctypes.memmove(buffer, original[self.position:self.position + count], count)
            self.position += count
            returned._obj.value = count
            return True

    drive = r'\\.\R:'
    previous = FakeAPI()
    try:
        previous.copy(drive, directory / 'clipped.img', len(original))
    except ValueError as error:
        assert 'expected EOF' in str(error)
    else:
        raise AssertionError('The old complete-cluster clipping was not reproduced')
    assert (directory / 'clipped.img').read_bytes() == original[:cluster]
    current = FakeAPI()
    checksum = current.copy(drive, directory / 'complete.img', len(original), volume_sector_bytes=sector)
    assert checksum == hashlib.sha256(original).hexdigest()
    assert (directory / 'complete.img').read_bytes() == original
    assert current.controls == [0x00090083] and current.closed
    assert current.opens == [(drive, collector.GENERIC_READ)]
    assert all(first + length <= len(original) for first, length in current.reads)
    ordinary = FakeAPI()
    ordinary.copy(r'R:\file.bin', directory / 'ordinary.bin', cluster)
    assert not ordinary.controls and ordinary.closed
    assert (directory / 'ordinary.bin').read_bytes() == original[:cluster]
    refused = FakeAPI(refuse_control=True)
    try:
        refused.copy(drive, directory / 'refused.img', len(original), volume_sector_bytes=sector)
    except OSError:
        pass
    else:
        raise AssertionError('A rejected extended-read control was ignored')
    assert not refused.reads and refused.closed
    assert (directory / 'refused.img').read_bytes() == b''
    for source, count, unit in ((r'R:\file.bin', len(original), sector),
                                (r'\\.\PhysicalDrive0', len(original), sector),
                                (drive, len(original) - 1, sector), (drive, len(original), 0)):
        invalid = FakeAPI()
        try:
            invalid.copy(source, directory / 'invalid.img', count, volume_sector_bytes=unit)
        except ValueError:
            pass
        else:
            raise AssertionError('Invalid raw-read identity or alignment was admitted')
        assert not invalid.opens and not (directory / 'invalid.img').exists()


def native_stat(size, directory=False, links=1):
    return {'size': str(size), 'directory': directory, 'reparse': False, 'links': links,
            'file_attributes': collector.FILE_ATTRIBUTE_DIRECTORY if directory else 0,
            'created_ticks': str(fixtures.EPOCH), 'accessed_ticks': str(fixtures.EPOCH),
            'modified_ticks': str(fixtures.EPOCH + fixtures.TIMESTAMP_OFFSET_TICKS)}


def save_manifest(directory, image, entries, serial=fixtures.BOOT_SERIAL):
    image_path = directory / 'volume.img'
    image_path.write_bytes(image)
    (directory / 'payloads').mkdir()
    manifest = {'schema_version': collector.SCHEMA_VERSION,
                'provenance': 'independent synthetic fixture; not Windows-authored',
                'acquisition_status': 'complete',
                'volume': {'serial': f'{serial:016x}', 'size_bytes': str(len(image)),
                           'sector_size': fixtures.SECTOR, 'cluster_size': fixtures.CLUSTER,
                           'record_size': fixtures.RECORD, 'root_reference': f'{fixtures.ROOT_REF:016x}'},
                'image': {'file': image_path.name, 'size': str(len(image)),
                          'sha256': hashlib.sha256(image).hexdigest()}, 'entries': entries}
    for entry in entries:
        for stream in entry.get('streams', []):
            payload = stream.pop('expected')
            stream['size'] = str(len(payload))
            stream['sha256'] = hashlib.sha256(payload).hexdigest()
            stream['payload'] = 'payloads/' + entry['reference'] + '-' + ''.join(f'{unit:04x}' for unit in stream['name_utf16']) + '.bin'
            (directory / stream['payload']).write_bytes(payload)
    path = directory / 'manifest.json'
    path.write_text(json.dumps(manifest, ensure_ascii=True) + '\n', encoding='utf-8')
    return path, manifest


def standard_manifest(directory):
    image, payloads, _ = fixtures.make_image()
    entries = [{'reference': f'{fixtures.ROOT_REF:016x}', 'parent_reference': None,
                'path_utf16': [], 'name_utf16': [], 'stat': native_stat(0, True),
                'children_complete': True, 'case_sensitive': False, 'case_flags': 0}]
    for name, payload in payloads.items():
        entry = {'reference': f'{fixtures.file_reference(fixtures.FILE_RECORDS[name]):016x}',
                 'parent_reference': f'{fixtures.ROOT_REF:016x}',
                 'path_utf16': [collector.utf16_units(name)], 'name_utf16': collector.utf16_units(name),
                 'stat': native_stat(len(payload)),
                 'streams': [{'name_utf16': [], 'expected': payload}]}
        if name == 'streamed.txt':
            entry['streams'].append({'name_utf16': collector.utf16_units('notes'),
                                     'expected': b'alternate payload'})
        entries.append(entry)
    return save_manifest(directory, image, entries)


def hard_link_manifest(directory):
    image, _, _ = fixtures.make_image()
    number = fixtures.FILE_RECORDS['hello.txt']
    names = ['alias.txt', 'hello.txt', chr(UNPAIRED_HIGH_SURROGATE) + '-name.txt']
    payload = b'one inode, several independently stored names\n'
    ads_name = chr(UNPAIRED_LOW_SURROGATE) + 'metadata'
    ads = b'lossless stream-name transport'
    encoded = fixtures.file_record(number,
                                   [fixtures.standard(), fixtures.resident(fixtures.DATA, payload, 1),
                                    fixtures.resident(fixtures.DATA, ads, 2, ads_name)], links=HARD_LINK_COUNT)
    fixtures.put_record(image, number, encoded)
    index = b''.join(fixtures.entry(name, number, len(payload)) for name in names) + fixtures.entry()
    fixtures.put_record(image, fixtures.ROOT_RECORD, fixtures.directory_record(index))
    entries = [{'reference': f'{fixtures.ROOT_REF:016x}', 'parent_reference': None,
                'path_utf16': [], 'name_utf16': [], 'stat': native_stat(0, True),
                'children_complete': True}]
    for name in names:
        entries.append({'reference': f'{fixtures.file_reference(number):016x}',
                        'parent_reference': f'{fixtures.ROOT_REF:016x}',
                        'path_utf16': [collector.utf16_units(name)], 'name_utf16': collector.utf16_units(name),
                        'stat': native_stat(len(payload), links=HARD_LINK_COUNT),
                        'streams': [{'name_utf16': [], 'expected': payload},
                                    {'name_utf16': collector.utf16_units(ads_name), 'expected': ads}]})
    return save_manifest(directory, image, entries)


def helper_contracts():
    assert ctypes.sizeof(collector.FileInformation) == WINDOWS_FILE_INFORMATION_BYTES
    assert ctypes.sizeof(collector.VolumeInformation) == WINDOWS_VOLUME_INFORMATION_BYTES
    assert ctypes.sizeof(collector.StreamInformation) == WINDOWS_STREAM_INFORMATION_BYTES
    ref = f'{fixtures.file_reference(fixtures.FILE_RECORDS["hello.txt"]):016x}'
    maximum_name = [UNPAIRED_HIGH_SURROGATE] * WINDOWS_MAX_NAME_UNITS
    payload = collector.payload_name(ref, maximum_name)
    assert len(Path(payload).name) <= WINDOWS_MAX_NAME_UNITS
    assert payload != collector.payload_name(ref, maximum_name[:-1] + [UNPAIRED_LOW_SURROGATE])
    text = 'A\U0001f600' + chr(UNPAIRED_HIGH_SURROGATE) + chr(UNPAIRED_LOW_SURROGATE) + 'Ω'
    assert collector.units_text(collector.utf16_units(text)).encode('utf-16-le', errors='surrogatepass') == text.encode('utf-16-le', errors='surrogatepass')
    target = chr(UNPAIRED_HIGH_SURROGATE) + '\\target'
    encoded = fixtures.reparse_value(fixtures.REPARSE_TAG_SYMLINK, target, 'display', relative=True, print_first=True)
    observed = collector.reparse_observation(encoded)
    assert observed['substitute_utf16'] == collector.utf16_units(target)
    assert observed['print_utf16'] == collector.utf16_units('display')
    assert observed['flags'] == fixtures.REPARSE_SYMLINK_RELATIVE
    for malformed in (b'', encoded[:-1]):
        try:
            collector.reparse_observation(malformed)
        except ValueError:
            pass
        else:
            raise AssertionError('Malformed native reparse observation was accepted')


def sensitive_manifest(directory):
    image, _, _ = fixtures.make_image()
    numbers = (fixtures.FILE_RECORDS['hello.txt'], fixtures.FILE_RECORDS['middle.dat'])
    names = ('Foo.txt', 'foo.txt')
    payloads = (b'exact upper-case file', b'exact lower-case file')
    entries = [{'reference': f'{fixtures.ROOT_REF:016x}', 'parent_reference': None,
                'path_utf16': [], 'name_utf16': [], 'stat': native_stat(0, True),
                'children_complete': True, 'case_sensitive': True,
                'case_flags': collector.FILE_CS_FLAG_CASE_SENSITIVE_DIR}]
    index = b''
    for number, name, payload in zip(numbers, names, payloads):
        fixtures.put_record(image, number, fixtures.file_record(number,
                            [fixtures.standard(), fixtures.resident(fixtures.DATA, payload, 1)]))
        index += fixtures.entry(name, number, len(payload))
        entries.append({'reference': f'{fixtures.file_reference(number):016x}',
                        'parent_reference': f'{fixtures.ROOT_REF:016x}',
                        'path_utf16': [collector.utf16_units(name)],
                        'name_utf16': collector.utf16_units(name), 'stat': native_stat(len(payload)),
                        'streams': [{'name_utf16': [], 'expected': payload}]})
    fixtures.put_record(image, fixtures.ROOT_RECORD, fixtures.directory_record(index + fixtures.entry(),
                        version=collector.FILE_CS_FLAG_CASE_SENSITIVE_DIR))
    return save_manifest(directory, image, entries)


def case_contracts(directory, reader, path, manifest):
    damaged = deepcopy(manifest)
    damaged['entries'][0]['case_sensitive'] = False
    damaged['entries'][0]['case_flags'] = 0
    path.write_text(json.dumps(damaged) + '\n')
    report = corpus.verify(path, reader, directory / 'wrong-case.json')
    assert report['status'] == 'fail' and any(
        check['operation'] == 'directory-case-policy' and check['status'] == 'fail'
        for check in report['checks']), report
    damaged['entries'][0]['case_flags'] = collector.FILE_CS_FLAG_CASE_SENSITIVE_DIR << 1
    path.write_text(json.dumps(damaged) + '\n')
    report = corpus.verify(path, reader, directory / 'unknown-case.json')
    assert report['status'] == 'fail', report
    for change in ({'case_sensitive': 'true'}, {'case_flags': -1}, {'case_flags': True},
                   {'case_flags': 1 << (ctypes.sizeof(ctypes.c_uint32) * fixtures.BYTE_BITS)},
                   {'case_sensitive': False}, {'case_sensitive': None}):
        damaged = deepcopy(manifest)
        damaged['entries'][0].update(change)
        path.write_text(json.dumps(damaged) + '\n')
        try:
            corpus.validate_manifest(path)
        except ValueError:
            pass
        else:
            raise AssertionError('Malformed case-policy observation was accepted')
    for entry_index in (0, 1):
        damaged = deepcopy(manifest)
        entry = damaged['entries'][entry_index]
        if entry_index == 0:
            del entry['case_flags']
        else:
            entry.update(case_sensitive=False, case_flags=0)
        path.write_text(json.dumps(damaged) + '\n')
        try:
            corpus.validate_manifest(path)
        except ValueError:
            pass
        else:
            raise AssertionError('Partial or non-directory case policy was accepted')
    damaged = deepcopy(manifest)
    del damaged['entries'][0]['case_sensitive']
    del damaged['entries'][0]['case_flags']
    path.write_text(json.dumps(damaged) + '\n')
    report = corpus.verify(path, reader, directory / 'missing-case.json')
    assert report['status'] == 'pass' and report['missing_case_observations'] == [manifest['entries'][0]['reference']], report
    assert 'unobserved directory case policies' in report['remaining_contracts'], report


def main():
    reader = Path(sys.argv[1]).resolve()
    helper_contracts()
    sanitizer_contracts()
    with tempfile.TemporaryDirectory(prefix='ntfs-corpus-') as temporary:
        base = Path(temporary)
        raw_tail_contracts(base)
        for name, create in (('standard', standard_manifest), ('hard-links', hard_link_manifest),
                             ('case-sensitive', sensitive_manifest)):
            directory = base / name
            directory.mkdir()
            path, manifest = create(directory)
            report = corpus.verify(path, reader, directory / 'report.json')
            assert report['status'] == 'pass', report
            assert report['corpus_provenance'].startswith('independent synthetic'), report
            if name == 'case-sensitive':
                assert not report['missing_case_observations'], report
                case_contracts(directory, reader, path, manifest)
            for entry in manifest['entries']:
                observed = [json.loads(line)['name_utf16'] for line in corpus.tool(
                    reader, directory / 'volume.img', 'streams-ref',
                    entry['reference']).splitlines()]
                expected_names = sorted(stream['name_utf16'] for stream in entry.get('streams', []))
                assert observed == expected_names, (observed, expected_names)
            damaged = deepcopy(manifest)
            damaged['entries'][-1]['streams'][0]['sha256'] = '0' * len(hashlib.sha256().hexdigest())
            path.write_text(json.dumps(damaged) + '\n')
            rejected = corpus.verify(path, reader, directory / 'bad-hash.json')
            assert rejected['status'] == 'fail' and any(check['status'] == 'fail' for check in rejected['checks']), rejected
            damaged = deepcopy(manifest)
            damaged['entries'][-1]['streams'][0]['payload'] = '../outside.bin'
            path.write_text(json.dumps(damaged) + '\n')
            try:
                corpus.validate_manifest(path)
            except ValueError:
                pass
            else:
                raise AssertionError('Corpus artifact traversal was accepted')
            damaged = deepcopy(manifest)
            damaged['acquisition_status'] = 'partial'
            path.write_text(json.dumps(damaged) + '\n')
            report = corpus.verify(path, reader, directory / 'partial.json')
            assert report['status'] == 'partial', report
        try:
            corpus.tool(reader, base / 'standard/volume.img', 'stat-ref', '0000000000000005')
        except RuntimeError as error:
            assert str(error) == 'stat-ref: invalid argument', str(error)
        else:
            raise AssertionError('Unsequenced reference unexpectedly succeeded')
    print('PASS: corpus geometry, hashes, Unicode/ADS transport, hard-link names, budgets and rejection')


if __name__ == '__main__':
    main()
