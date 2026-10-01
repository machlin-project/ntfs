#!/usr/bin/env python3
"""Exercise the Windows corpus transport against independent synthetic fixtures."""
from copy import deepcopy
import ctypes
import hashlib
import json
from pathlib import Path
import sys
import tempfile

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
                'children_complete': True}]
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


def main():
    reader = Path(sys.argv[1]).resolve()
    helper_contracts()
    with tempfile.TemporaryDirectory(prefix='ntfs-corpus-') as temporary:
        base = Path(temporary)
        for name, create in (('standard', standard_manifest), ('hard-links', hard_link_manifest)):
            directory = base / name
            directory.mkdir()
            path, manifest = create(directory)
            report = corpus.verify(path, reader, directory / 'report.json')
            assert report['status'] == 'pass', report
            assert report['corpus_provenance'].startswith('independent synthetic'), report
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
