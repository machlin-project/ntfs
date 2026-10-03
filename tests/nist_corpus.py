#!/usr/bin/env python3
"""Compare pinned public NIST DFR images with documented names and NTFS-3G.

This offline test neither mounts nor modifies its inputs. Acquisition hashes are
local observation pins, not publisher signatures or proof of a Windows author.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from bounded_tool import run_tool
from secure_oracle import exported_locators, indexed_bytes

SOURCE_PAGE = 'https://cfreds-archive.nist.gov/dfr-test-images.html'
LAYOUT_URL = 'https://cfreds-archive.nist.gov/dfr-images/setup-july-10-2012.pdf'
PARTITION_BYTES = 300 * 1024 * 1024
COPY_BYTES = 1024 * 1024
OUTPUT_BYTES = 2 * 1024 * 1024
# The largest documented profile has 1,031 objects. This margin covers ten
# commands per object plus directory, store and structural-root observations.
TOOL_SECONDS, TOTAL_SECONDS, MAX_COMMANDS = 30, 1200, 12000
REFERENCE_SEQUENCE_SHIFT = 48
REFERENCE_RECORD_MASK = (1 << REFERENCE_SEQUENCE_SHIFT) - 1
DOS_NAMESPACE = 2
SECURE_RECORD = 9
ATTRIBUTE_DATA, ATTRIBUTE_STANDARD, ATTRIBUTE_INDEX_ROOT, ATTRIBUTE_REPARSE = '0x80', '0x10', '0x90', '0xc0'
ATTRIBUTE_SECURITY = '0x50'
STANDARD_INFO = struct.Struct('<QQQQIIIIIIQQ')
STANDARD_COMMON = struct.Struct('<QQQQIIII')
STANDARD_FIELDS = ('created', 'modified', 'changed', 'accessed', 'attributes',
                   'max_versions', 'version', 'class_id', 'owner_id', 'security_id', 'quota', 'usn')
REPARSE_HEADER = struct.Struct('<IHH')
SYMLINK_HEADER = struct.Struct('<HHHHI')
SYMLINK_FIELDS = ('substitute_offset', 'substitute_bytes', 'print_offset', 'print_bytes', 'flags')
SYMLINK_TAG = 0xa000000c
UTF16 = struct.Struct('<H')
FILETIME_EPOCH, TICKS_PER_SECOND, NANOSECONDS_PER_TICK = 116444736000000000, 10000000, 100
DIRECTORY_GROUPS = range(1, 10)
PINNED_IMAGES = {
    'dfr-15-ntfs': '3c533a8c79e2b8038dd70abcbfeda05fc5e6df08bac615985df0466999ab9561',
    'dfr-16-ntfs': '35af150ce62071041985befcfa0bc80175255b5a985c01c0fcb50d137ff8b13e',
    'dfr-17-ntfs': '1049b52aab816857f17484aa62dc8af2c53853cc786f3aeda4b7c79dcb107896',
}
LINK_PROFILE_NAMES = ('Archive-ntfs.txt', 'Hidden-ntfs.txt', 'NotIndexed-ntfs.txt',
                      'ReadOnly-ntfs.txt', 'System-ntfs.txt', 'hard-file.txt', 'hard-link.txt',
                      'shortcut-file.txt', 'shortcut-shortcut.lnk', 'stream-file.txt',
                      'symbolic-file.txt', 'symbolic-link.txt')
STREAM_NAME = 'Brahmaputra.txt'
NAMESPACE_LABELS = frozenset(('POSIX', 'Win32', 'DOS', 'Win32 & DOS'))


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def file_hash(path, deadline, expected_bytes=None):
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), 'A regular input file is required')
        require(info.st_size <= PARTITION_BYTES, 'Input exceeds the corpus file budget')
        require(expected_bytes is None or info.st_size == expected_bytes, 'Input size differs from the pinned profile')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            for chunk in iter(lambda: source.read(COPY_BYTES), b''):
                require(time.monotonic() < deadline, 'Corpus deadline exceeded')
                digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest()


def documented_directories(name):
    if name == 'dfr-15-ntfs':
        return {'/': {entry: False for entry in LINK_PROFILE_NAMES}}
    if name == 'dfr-16-ntfs':
        result = {'/': {f'4-dir-{group:02}': True for group in DIRECTORY_GROUPS}}
        for group in DIRECTORY_GROUPS:
            result[f'/4-dir-{group:02}'] = {
                f'4-{group:02}-{entry:05}.txt': False for entry in range(1, (1 << group) + 1)}
        return result
    result = {'/': {f'Y{group:02}': True for group in DIRECTORY_GROUPS}}
    for group in DIRECTORY_GROUPS:
        path = f'/Y{group:02}'
        for depth in range(1, group + 1):
            entries = {f'Y{group:02}F{depth:02}.TXT': False}
            if depth < group:
                entries[f'Y{group:02}L{depth:02}'] = True
            result[path] = entries
            path += f'/Y{group:02}L{depth:02}'
    return result


def utf16_units(text):
    return tuple(unit for (unit,) in UTF16.iter_unpack(text.encode('utf-16le')))


def oracle_names(raw):
    result = {}
    for line in raw.decode('utf-8').splitlines():
        match = re.fullmatch(r'\s*(\d+)\s+(.+)', line)
        require(match is not None, 'Unrecognized NTFS-3G directory output')
        number, name = int(match[1]), match[2]
        if name in ('.', '..'):
            continue
        require(name not in result, 'NTFS-3G emitted duplicate names')
        result[name] = number
    return result


class Comparison:
    def __init__(self, args, image, output, deadline, log):
        self.args, self.image, self.output, self.deadline, self.log = args, image, output, deadline, log
        self.commands = 0
        self.descriptors = {}

    def capture(self, arguments):
        self.commands += 1
        remaining = self.deadline - time.monotonic()
        require(remaining > 0 and self.commands <= MAX_COMMANDS, 'Corpus execution budget exhausted')
        command = list(map(str, arguments))
        self.log.write(json.dumps({'command': command}) + '\n')
        self.log.flush()
        try:
            raw = run_tool(command, timeout=min(TOOL_SECONDS, remaining), output_limit=OUTPUT_BYTES)
        except Exception as error:
            self.log.write(json.dumps({'failure': str(error)}) + '\n')
            self.log.flush()
            raise
        self.log.write(json.dumps({'exit': 0, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}) + '\n')
        self.log.flush()
        return raw

    def core(self, operation, *arguments):
        return self.capture([self.args.reader, self.image, operation, *arguments])

    def symlink_read_refusal(self, reference):
        try:
            self.core('cat-ref', reference)
        except RuntimeError as error:
            require(str(error).strip() == 'Diagnostic exited 1: unsupported format', 'Unexpected symlink read failure')
            return
        raise ValueError('Ordinary data reading unexpectedly admitted a symbolic link')

    def export(self, number, attribute=ATTRIBUTE_DATA, name=None):
        arguments = [self.args.tools / 'ntfscat', '-i', number, '-a', attribute]
        if name is not None:
            arguments.extend(('-n', name))
        return self.capture([*arguments, self.image])

    def security(self):
        sii = self.export(SECURE_RECORD, ATTRIBUTE_INDEX_ROOT, '$SII')
        sds = self.export(SECURE_RECORD, ATTRIBUTE_DATA, '$SDS')
        (self.output / 'sii.bin').write_bytes(sii)
        (self.output / 'sds.bin').write_bytes(sds)
        locators = exported_locators(sii)
        self.descriptors = {id_: indexed_bytes(sds, locator) for id_, locator in locators.items()}
        for id_, descriptor in self.descriptors.items():
            require(self.core('security-id', f'{id_:x}') == descriptor, 'Indexed descriptor differs from NTFS-3G')
        result = json.loads(self.core('security-store'))
        require(result['complete'] and int(result['descriptors']) == len(locators), 'Incomplete security inventory')
        return result

    def directory(self, path, reference, expected):
        long_names = oracle_names(self.capture([self.args.tools / 'ntfsls', '-a', '-s', '-i', '-p', path, self.image]))
        short_names = oracle_names(self.capture([self.args.tools / 'ntfsls', '-a', '-s', '-i', '-x', '-p', path, self.image]))
        union = dict(long_names)
        for name, number in short_names.items():
            require(name not in union or union[name] == number, 'NTFS-3G aliases disagree on identity')
            union[name] = number
        raw = self.core('ls-ref', reference)
        entries = [json.loads(line) for line in raw.splitlines()]
        (self.output / ('directory-' + reference + '.jsonl')).write_bytes(raw)
        actual = {}
        for entry in entries:
            units = tuple(entry['name_utf16'])
            if units == utf16_units('.'):
                require(path == '/' and entry['reference'] == reference, 'Invalid structural root name')
                continue
            require(units not in actual and entry['parent_reference'] == reference, 'Duplicate name or wrong parent')
            actual[units] = entry
        oracle = {utf16_units(name): number for name, number in union.items()}
        require(set(actual) == set(oracle), 'Complete physical directory names differ from NTFS-3G')
        for units, entry in actual.items():
            require(int(entry['reference'], 16) & REFERENCE_RECORD_MASK == oracle[units], 'Directory identity differs')
        visible = {name: number for name, number in long_names.items() if not name.startswith('$')}
        require(set(visible) == set(expected), 'Namespace differs from the independently documented inventory')
        primary = {units for units, entry in actual.items()
                   if entry['namespace'] != DOS_NAMESPACE and units[0] != ord('$')}
        require(primary == {utf16_units(name) for name in expected}, 'Unexpected primary or missing logical name')
        return actual

    def object(self, path, reference, directory):
        number = int(reference, 16) & REFERENCE_RECORD_MASK
        metadata = json.loads(self.core('stat-ref', reference))
        require(metadata['reference'] == reference and metadata['directory'] == directory, 'Object identity/kind differs')
        symlink = path == '/symbolic-link.txt'
        require(metadata['reparse'] == symlink, 'Reparse classification differs from the documented profile')
        original = self.export(number, ATTRIBUTE_STANDARD)
        require(len(original) in (STANDARD_COMMON.size, STANDARD_INFO.size), 'Unexpected standard-information wire layout')
        fields = dict.fromkeys(STANDARD_FIELDS, 0)
        fields.update(zip(STANDARD_FIELDS, (STANDARD_COMMON if len(original) == STANDARD_COMMON.size
                                           else STANDARD_INFO).unpack(original)))
        require(metadata['file_attributes'] == fields['attributes'] and metadata['security_id'] == fields['security_id'],
                'Standard information differs from independently exported bytes')
        for name in ('created', 'modified', 'changed', 'accessed'):
            seconds, ticks = divmod(fields[name] - FILETIME_EPOCH, TICKS_PER_SECOND)
            require(int(metadata[name]['seconds']) == seconds and metadata[name]['nanoseconds'] == ticks * NANOSECONDS_PER_TICK,
                    'Timestamp differs from independently exported bytes')
        info = self.capture([self.args.tools / 'ntfsinfo', '-t', '-i', number, self.image])
        sequence = re.search(rb'MFT Record Seq\. Numb\.:\s*(\d+)', info)
        links = re.search(rb'Number of Hard Links:\s*(\d+)', info)
        require(sequence is not None and links is not None, 'Missing independent FILE-header observations')
        require(int(sequence[1]) == int(reference, 16) >> REFERENCE_SEQUENCE_SHIFT and int(links[1]) == metadata['links'],
                'FILE sequence or physical header link count differs')
        namespaces = re.findall(rb'^\s*Namespace:\s*([^\r\n]+?)\s*$', info, re.MULTILINE)
        namespaces = [name.decode('ascii') for name in namespaces]
        require(namespaces and all(name in NAMESPACE_LABELS for name in namespaces),
                'Missing or unknown independent FILE_NAME namespace observations')
        counts = {'physical_names': len(namespaces),
                  'primary_names': sum(name != 'DOS' for name in namespaces),
                  'dos_aliases': namespaces.count('DOS')}
        require(counts['physical_names'] == metadata['links'], 'Independent filename inventory/header counts disagree')
        require(json.loads(self.core('links-ref', reference)) == counts, 'Primary/DOS counts differ from NTFS-3G')
        expected_descriptor = (self.descriptors[fields['security_id']] if fields['security_id']
                               else self.export(number, ATTRIBUTE_SECURITY))
        require(self.core('security-ref', reference) == expected_descriptor, 'Per-file descriptor differs')
        info_name, descriptor_name = f'file-{number}-info.txt', f'file-{number}-security.bin'
        (self.output / info_name).write_bytes(info)
        (self.output / descriptor_name).write_bytes(expected_descriptor)
        row = {'path': path, 'reference': reference, 'metadata': metadata, 'standard_hex': original.hex(),
               'link_counts': counts, 'info_oracle': info_name,
               'security_oracle': descriptor_name, 'security_bytes': len(expected_descriptor),
               'security_sha256': hashlib.sha256(expected_descriptor).hexdigest()}
        if not directory:
            catalog = [json.loads(line)['name_utf16'] for line in self.core('streams-ref', reference).splitlines()]
            expected_streams = [[], list(utf16_units(STREAM_NAME))] if path == '/stream-file.txt' else [[]]
            require(catalog == expected_streams, 'Stream catalog differs from documented streams')
            row['streams'] = []
            for units in catalog:
                name = ''.join(map(chr, units))
                core_arguments = (reference, name.encode('utf-16-be').hex()) if name else (reference,)
                external_bytes = self.export(number, name=name if name else None)
                if symlink:
                    require(not name and not external_bytes, 'Unexpected symlink data storage')
                    self.symlink_read_refusal(reference)
                else:
                    require(self.core('cat-ref', *core_arguments) == external_bytes,
                            'Stream content differs from independently exported bytes')
                if not name:
                    require(int(metadata['size']) == len(external_bytes), 'Current data size differs from actual content')
                stored_name = f'file-{number}-{len(row["streams"])}.bin'
                (self.output / stored_name).write_bytes(external_bytes)
                row['streams'].append({'name_utf16': units, 'bytes': len(external_bytes),
                                       'sha256': hashlib.sha256(external_bytes).hexdigest(), 'oracle': stored_name,
                                       'core_result': 'unsupported symbolic-link data' if symlink else 'exact bytes'})
        return row

    def symlink(self, reference):
        raw = self.export(int(reference, 16) & REFERENCE_RECORD_MASK, ATTRIBUTE_REPARSE)
        (self.output / 'symlink.bin').write_bytes(raw)
        tag, length, _ = REPARSE_HEADER.unpack_from(raw)
        require(tag == SYMLINK_TAG and length + REPARSE_HEADER.size == len(raw), 'Unexpected symlink framing')
        fields = dict(zip(SYMLINK_FIELDS, SYMLINK_HEADER.unpack_from(raw, REPARSE_HEADER.size)))
        names = raw[REPARSE_HEADER.size + SYMLINK_HEADER.size:]
        expected = {}
        for name in ('substitute', 'print'):
            offset, size = fields[name + '_offset'], fields[name + '_bytes']
            require(offset % UTF16.size == 0 and size % UTF16.size == 0 and offset + size <= len(names), 'Invalid symlink range')
            expected[name + '_utf16'] = list(unit for (unit,) in UTF16.iter_unpack(names[offset:offset + size]))
        actual = json.loads(self.core('reparse-ref', reference))
        require(actual['tag'] == tag and actual['flags'] == fields['flags'], 'Reparse tag/flags differ')
        require(all(actual[name] == units for name, units in expected.items()), 'Reparse names differ from original bytes')
        return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images', type=Path, required=True, help='Existing extracted public partitions')
    parser.add_argument('--tools', type=Path, default=ROOT / 'vendor/ntfs-tools/bin')
    parser.add_argument('--reader', type=Path, default=ROOT / '.build/ntfs-inspect')
    parser.add_argument('--validator', type=Path, default=ROOT / '.build/ntfs-validate')
    parser.add_argument('--profile', choices=PINNED_IMAGES, action='append', help='Default: all three images')
    parser.add_argument('--output', type=Path, required=True, help='Fresh evidence directory')
    args = parser.parse_args()
    deadline = time.monotonic() + TOTAL_SECONDS
    args.output.mkdir(parents=True, exist_ok=False)
    products = [args.reader, args.validator, *(args.tools / name for name in ('ntfsls', 'ntfsinfo', 'ntfscat'))]
    report = {'status': 'running', 'source_page': SOURCE_PAGE, 'layout_url': LAYOUT_URL,
              'hash_authority': 'local first acquisition, not a publisher signature', 'authoring_os': 'unestablished',
              'windows_acceptance': False, 'native_mount': False, 'authorization': False,
              'products': {str(path): file_hash(path, deadline) for path in products}, 'profiles': []}
    report_path = args.output / 'report.json'
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    try:
        with (args.output / 'commands.jsonl').open('x') as log:
            for name in args.profile or PINNED_IMAGES:
                image = args.images / (name + '.partition.img')
                output = args.output / name
                output.mkdir()
                row = {'name': name, 'image': str(image), 'status': 'running', 'objects': []}
                report['profiles'].append(row)
                row['sha256_before'] = file_hash(image, deadline, PARTITION_BYTES)
                require(row['sha256_before'] == PINNED_IMAGES[name], 'Image differs from the pinned public partition')
                comparison = Comparison(args, image, output, deadline, log)
                info = json.loads(comparison.core('info-json'))
                references = {'/': info['root_reference']}
                row['geometry'] = info
                row['security_store'] = comparison.security()
                row['root'] = comparison.object('/', references['/'], True)
                for path, expected in documented_directories(name).items():
                    actual = comparison.directory(path, references[path], expected)
                    for child, directory in expected.items():
                        entry = actual[utf16_units(child)]
                        lookup = json.loads(comparison.core('lookup-ref', references[path], child.encode('utf-16-be').hex()))
                        require(lookup == entry, 'Lookup differs from complete enumeration')
                        child_path = path.rstrip('/') + '/' + child
                        references[child_path] = entry['reference']
                        row['objects'].append(comparison.object(child_path, entry['reference'], directory))
                if name == 'dfr-15-ntfs':
                    require(references['/hard-file.txt'] == references['/hard-link.txt'], 'Hard-link identity differs')
                    row['symlink'] = comparison.symlink(references['/symbolic-link.txt'])
                row['validation'] = json.loads(comparison.capture([args.validator, image]))
                require(row['validation']['complete'] and row['validation']['result'] == 'success'
                        and row['validation']['deferred_dos_link_counts'] == '0', 'Whole-volume diagnostic is incomplete')
                row['sha256_after'] = file_hash(image, deadline, PARTITION_BYTES)
                require(row['sha256_before'] == row['sha256_after'], 'Read-only comparison changed the image')
                row['commands'], row['status'] = comparison.commands, 'pass'
                report_path.write_text(json.dumps(report, indent=2) + '\n')
                print(f'PASS: {name}, {len(row["objects"])} documented user objects, readable streams/link refusal and complete validation', flush=True)
        report['status'] = 'pass'
    except Exception as error:
        report['status'], report['error'] = 'failed', str(error)
        raise
    finally:
        report_path.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
