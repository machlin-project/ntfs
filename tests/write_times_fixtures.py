#!/usr/bin/env python3
"""Independent exact SI-only snapshots, with original namespace/data/security."""
from pathlib import Path
import argparse

import fixtures as f
import filename_storage as storage
import validation_fixtures as v
import secure_fixtures as s
from write_metadata_fixtures import (
    STANDARD, FILE, restored, READ_ONLY, SYSTEM, SPARSE, COMPRESSED, ENCRYPTED,
)

FIELDS = ('created', 'modified', 'changed', 'accessed')
VALUES = (0, (1 << 63) - 1, 134357146906613431, 134357146900000007)
ALL_FIELDS = (1 << len(FIELDS)) - 1
ADS_INSTANCE = 15
ADS_CONTENT = b'An independently authored named stream must not change.'


def author(destination, source):
    destination.mkdir(parents=True, exist_ok=True)
    image = bytearray((source / 'source.img').read_bytes())
    first = f.MFT_LCN * f.CLUSTER + v.HELLO_RECORD * f.RECORD
    header, attributes = storage.record_parts(image[first:first + f.RECORD])
    assert all(storage.attr_header(attr)['instance'] != ADS_INSTANCE for attr in attributes)
    attributes.append(f.resident(f.DATA, ADS_CONTENT, ADS_INSTANCE, 'notes'))
    f.put_record(image, v.HELLO_RECORD, storage.encoded_record(v.HELLO_RECORD, attributes, header))
    (destination / 'file.img').write_bytes(image)
    directory_image = (source / 'ancestor-posix.img').read_bytes()
    (destination / 'directory.img').write_bytes(directory_image)
    # The independently authored ancestry graph's first directory is the first
    # fresh base slot; find it from its actual filename, not an assumed number.
    directory_number = None
    for number in range(f.MFT_COUNT):
        first = f.MFT_LCN * f.CLUSTER + number * f.RECORD
        raw = directory_image[first:first + f.RECORD]
        if raw[:len(b'FILE')] != b'FILE':
            continue
        _, attributes = storage.record_parts(raw)
        for attribute in attributes:
            if storage.attr_header(attribute)['type'] == f.FILENAME:
                value = storage.resident_value(attribute)
                if value.endswith('AncestorDirectory'.encode('utf-16le')):
                    directory_number = number
                    break
        if directory_number is not None:
            break
    assert directory_number is not None
    profiles = (('resident', 'file.img', image, v.HELLO_RECORD),
                ('nonresident', 'file.img', image, v.FRAGMENTED_RECORD),
                ('directory', 'directory.img', directory_image, directory_number))
    rows = []
    for profile, filename, image, number in profiles:
        first = f.MFT_LCN * f.CLUSTER + number * f.RECORD
        original, _ = restored(image[first:first + f.RECORD])
        header, attributes = storage.record_parts(image[first:first + f.RECORD])
        standard = next(attr for attr in attributes if storage.attr_header(attr)['type'] == f.SI)
        si_offset = original.find(standard)
        assert si_offset >= FILE.size
        resident = dict(zip(storage.RESIDENT_FIELDS,
                            f.RESIDENT_HEADER.unpack_from(standard, f.ATTR_HEADER.size)))
        value_offset = resident['offset']
        reference = f.file_reference(number, header['sequence'])
        for mask in range(ALL_FIELDS + 1):
            expected = bytearray(original)
            for bit, (name, value) in enumerate(zip(FIELDS, VALUES)):
                if mask & (1 << bit):
                    STANDARD.put(expected, name, value, si_offset + value_offset)
            expected_name = f'{profile}-{mask}.record'
            (destination / expected_name).write_bytes(expected)
            rows.append(f'{filename} {reference} {first} {mask} {expected_name}')
    (destination / 'cases.txt').write_text('\n'.join(rows) + '\n')

    refusal_rows = []
    original = (destination / 'file.img').read_bytes()
    first = f.MFT_LCN * f.CLUSTER + v.HELLO_RECORD * f.RECORD
    header, base_attributes = storage.record_parts(original[first:first + f.RECORD])
    standard = next(attr for attr in base_attributes if storage.attr_header(attr)['type'] == f.SI)
    standard_value = storage.resident_value(standard)
    for profile in ('read-only', 'system', 'sparse', 'compressed', 'encrypted',
                    'listed', 'short-si', 'flagged-si', 'system-record'):
        image = bytearray(original)
        attributes = list(base_attributes)
        value = bytearray(standard_value)
        flags = {'read-only': READ_ONLY, 'system': SYSTEM, 'sparse': SPARSE,
                 'compressed': COMPRESSED, 'encrypted': ENCRYPTED}
        if profile in flags:
            STANDARD.put(value, 'attributes', flags[profile])
        elif profile == 'short-si':
            value = value[:f.STANDARD_INFO_COMMON.size]
        if profile == 'listed':
            attributes.append(f.resident(f.ATTR_LIST, b'', ADS_INSTANCE + 1))
        replacement = bytearray(f.resident(f.SI, value, storage.attr_header(standard)['instance']))
        if profile == 'flagged-si':
            wire = storage.attr_header(replacement)
            wire['flags'] = f.COMPRESSED
            f.ATTR_HEADER.pack_into(replacement, 0, *(wire[name] for name in s.ATTR_HEADER_FIELDS))
        attributes[attributes.index(standard)] = replacement
        f.put_record(image, v.HELLO_RECORD, storage.encoded_record(v.HELLO_RECORD, attributes, header))
        filename = f'refuse-{profile}.img'
        (destination / filename).write_bytes(image)
        reference = f.ROOT_REF if profile == 'system-record' else f.file_reference(
            v.HELLO_RECORD, header['sequence'])
        refusal_rows.append(f'{filename} {reference}')
    (destination / 'refusals.txt').write_text('\n'.join(refusal_rows) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('stamp', type=Path)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    author(args.destination, args.source)
    args.stamp.write_text('independent selected SI timestamp fixtures\n')
