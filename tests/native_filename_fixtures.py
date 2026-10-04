#!/usr/bin/env python3
"""Prepare complete selected filenames for the existing native component authors.

Known authored I30 keys supply the exact FILE_NAME bodies. This trusted fixture
reader does not use the product to discover names or change index bytes. Other
families, including whole-volume diagnostics, remain linked to their originals.
"""
import argparse
import hashlib
import json
from pathlib import Path

import fixtures as f
import secure_fixtures as s
from filename_storage import (FILENAME_FIELDS, FilenameStorage, attr_header,
                              attr_name, mapped_bytes, mapping)
from filename_storage_fixtures import root_filename
from secure_store_fixtures import kind, resident_value

INDEX_ROOT_FIELDS = ('type', 'collation', 'block_bytes', 'clusters')
INDEX_HEADER_FIELDS = ('entries', 'used', 'allocated', 'flags')
INDEX_ENTRY_FIELDS = ('reference', 'length', 'key_length', 'flags')
INDEX_BLOCK_FIELDS = ('magic', 'usa_offset', 'usa_count', 'lsn', 'vcn')
REFERENCE_RECORD_MASK = (1 << f.REFERENCE_SEQUENCE_SHIFT) - 1
NAMESPACE_INDEX = '$I30'
INDEX_MAGIC = b'INDX'

# These are the actual native component inputs. Corrupt diagnostic/MFT authors
# remain untouched; importing every synthetic image would change their scope.
SELECTED_PREFIXES = ('native-link-', 'namespace-', 'stat-', 'wof-file-')
SELECTED_IMAGES = {
    'standard.img', 'ntfs30.img', 'namespace.img', 'nested-index.img', 'mixed-compression.img',
    'directory-ads.img', 'catalog-long-unpaired.img', 'catalog-oversized.img',
    'catalog-fragmented.img', 'case-mixed.img', 'case-mixed-sensitive-root.img',
    'case-directory-self.img', 'case-directory-two-parents.img',
    'reparse-relative.img', 'reparse-unknown.img',
}


def selected(path):
    return path.name in SELECTED_IMAGES or (
        path.suffix == '.img' and path.name.startswith(SELECTED_PREFIXES))


def stream_body(image, values):
    """Read a complete known authored stream, including listed continuations."""
    assert values
    if not attr_header(values[0])['nonresident']:
        assert len(values) == 1
        return resident_value(values[0])
    extents = [mapping(value) for value in values]
    extents.sort(key=lambda item: item[0]['lowest'])
    runs, next_vcn = [], 0
    for header, extent in extents:
        assert header['lowest'] == next_vcn
        runs.extend(extent)
        next_vcn += sum(count for count, _ in extent)
    return mapped_bytes(image, runs, 0, extents[0][0]['size'])


def index_entries(payload, header_offset):
    header = dict(zip(INDEX_HEADER_FIELDS, f.INDEX_HEADER.unpack_from(payload, header_offset)))
    first, end = header_offset + header['entries'], header_offset + header['used']
    assert f.INDEX_HEADER.size <= header['entries'] <= header['used']
    assert end <= len(payload)
    position = first
    terminal = False
    while position < end:
        assert position + f.INDEX_ENTRY.size <= end
        entry = dict(zip(INDEX_ENTRY_FIELDS, f.INDEX_ENTRY.unpack_from(payload, position)))
        assert entry['length'] >= f.INDEX_ENTRY.size
        assert position + entry['length'] <= end
        assert f.INDEX_ENTRY.size + entry['key_length'] <= entry['length']
        if entry['key_length']:
            first_key = position + f.INDEX_ENTRY.size
            body = bytes(payload[first_key:first_key + entry['key_length']])
            filename = dict(zip(FILENAME_FIELDS, f.FILENAME_HEADER.unpack_from(body)))
            assert len(body) == f.FILENAME_HEADER.size + filename['length'] * f.U16_BYTES
            yield entry['reference'], body
        position += entry['length']
        if entry['flags'] & f.END:
            terminal = True
            break
    assert terminal and position == end


def restore_index(block):
    block = bytearray(block)
    header = dict(zip(INDEX_BLOCK_FIELDS, s.INDEX_BLOCK_HEADER.unpack_from(block)))
    assert header['magic'] == INDEX_MAGIC
    assert header['usa_count'] == len(block) // f.SECTOR + 1
    for sector in range(1, header['usa_count']):
        tail = sector * f.SECTOR - f.U16_BYTES
        saved = header['usa_offset'] + sector * f.U16_BYTES
        block[tail:tail + f.U16_BYTES] = block[saved:saved + f.U16_BYTES]
    return block


def authored_names(writer):
    owners = {}
    for number, (header, values) in writer.parts.items():
        if not header['flags'] & f.FILE_IN_USE:
            continue
        owner = header['base'] or f.file_reference(number, header['sequence'])
        owners.setdefault(owner, []).extend(values)
    names = {f.ROOT_RECORD: [root_filename()]}
    for reference, values in owners.items():
        roots = [value for value in values if kind(value) == f.INDEX_ROOT and
                 attr_name(value) == NAMESPACE_INDEX]
        if not roots:
            continue
        assert len(roots) == 1
        payload = resident_value(roots[0])
        root = dict(zip(INDEX_ROOT_FIELDS, f.INDEX_ROOT_HEADER.unpack_from(payload)))
        assert root['type'] == f.FILENAME and root['collation'] == f.COLLATION_FILENAME
        entries = list(index_entries(payload, f.INDEX_ROOT_HEADER.size))
        allocation = [value for value in values if kind(value) == f.INDEX_ALLOC and
                      attr_name(value) == NAMESPACE_INDEX]
        if allocation:
            bitmap = stream_body(writer.image, [value for value in values if kind(value) == f.BITMAP and
                                               attr_name(value) == NAMESPACE_INDEX])
            blocks = stream_body(writer.image, allocation)
            for ordinal in range(len(blocks) // root['block_bytes']):
                if bitmap[ordinal // f.BYTE_BITS] & (1 << (ordinal % f.BYTE_BITS)):
                    start = ordinal * root['block_bytes']
                    block = restore_index(blocks[start:start + root['block_bytes']])
                    entries.extend(index_entries(block, s.INDEX_BLOCK_HEADER.size))
        for child, body in entries:
            number = child & REFERENCE_RECORD_MASK
            names.setdefault(number, []).append(body)
    return names


def ordinary_attributes(writer):
    """Retain exact non-list payloads independently of filename placement."""
    result = {}
    for number, (header, values) in writer.parts.items():
        if number in (f.MFT_RECORD, f.BITMAP_RECORD):
            continue
        owner = header['base'] or f.file_reference(number, header['sequence'])
        result.setdefault(owner, []).extend(value for value in values
                                            if kind(value) not in (f.FILENAME, f.ATTR_LIST))
    return {owner: sorted(values) for owner, values in result.items()}


def complete(source, *, stale_lookup=False):
    before = FilenameStorage(source)
    expected_attributes = ordinary_attributes(before)
    names = authored_names(before)
    objects = []
    invalid_targets = []
    for number, bodies in sorted(names.items()):
        if number not in before.parts or before.parts[number][0]['base'] != 0:
            # A native corruption case may index a missing/extension record.
            # Preserve that invalid object instead of manufacturing a base.
            invalid_targets.append(number)
            continue
        header, values = before.parts[number]
        assert not any(kind(value) == f.FILENAME for value in values), number
        before.filenames(number, bodies)
        reference = f.file_reference(number, header['sequence'])
        namespaces = [dict(zip(FILENAME_FIELDS, f.FILENAME_HEADER.unpack_from(body)))['namespace']
                      for body in bodies]
        invalid_nul = any(b'\0\0' == body[offset:offset + f.U16_BYTES]
                          for body in bodies for offset in range(f.FILENAME_HEADER.size,
                                                                 len(body), f.U16_BYTES))
        objects.append({'reference': f'{reference:016x}',
                        'filename_body_hashes': sorted(hashlib.sha256(body).hexdigest() for body in bodies),
                        'counts': {'physical_names': len(bodies),
                                   'primary_names': sum(ns != f.NAMESPACE_DOS for ns in namespaces),
                                   'dos_aliases': namespaces.count(f.NAMESPACE_DOS)},
                        'result': 'corrupt metadata' if invalid_nul else 'success'})
    image = before.finish()
    after = FilenameStorage(image)
    assert ordinary_attributes(after) == expected_attributes
    lookups = []
    if stale_lookup:
        lookups.append({'parent': f'{f.ROOT_REF:016x}', 'name_units': [ord(unit) for unit in 'hello.txt'],
                        'result': 'stale file reference'})
    return image, objects, before, lookups, invalid_targets


def author(source, output):
    assert source.resolve() != output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest = []
    for path in sorted(source.iterdir()):
        is_directory = path.is_dir()
        if not path.is_file() and not is_directory:
            continue
        destination = output / path.name
        if destination.is_symlink():
            destination.unlink()
        if is_directory or not selected(path):
            assert not destination.exists(), destination
            destination.symlink_to(path.resolve(), target_is_directory=is_directory)
            continue
        raw = path.read_bytes()
        original_sha = hashlib.sha256(raw).hexdigest()
        try:
            image, objects, writer, lookups, invalid_targets = complete(
                raw, stale_lookup=path.name == 'namespace-stale.img')
        except Exception as error:
            raise RuntimeError('Native filename author failed for ' + path.name) from error
        destination.write_bytes(image)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == original_sha
        manifest.append({'image': path.name, 'objects': objects, 'streams': [], 'lookup_cases': lookups,
                         'mft_record_slots': writer.mft_record_slots,
                         'new_extension_records': writer.next_record - writer.original_records,
                         'unchanged_invalid_index_targets': invalid_targets,
                         'source_sha256': original_sha, 'sha256': hashlib.sha256(image).hexdigest()})
    (output / 'filename-storage-cases.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'PASS: authored exact selected filenames for {len(manifest)} native images; '
          'original ordinary attributes, index keys and source images preserved')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('stamp', nargs='?', type=Path)
    args = parser.parse_args()
    author(args.source, args.output)
    if args.stamp:
        args.stamp.write_text('authored exact selected native filename storage\n')
