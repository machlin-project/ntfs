#!/usr/bin/env python3
"""Author focused complete FILE_NAME inventories, independently of the C reader.

These images qualify selected filename storage, not whole namespace reachability.
Header and expected primary counts come from the author, never a product parser.
"""
import argparse
import json
from pathlib import Path
import struct

import fixtures as f
import secure_fixtures as s
import validation_fixtures as v
from secure_store_fixtures import attributes, kind, resident_value

LIST_INSTANCE = 7
LIST_LCN = 180
FIRST_EXTENSION = 40
NAMES_PER_EXTENSION = 4
LARGE_NAMES = 32
INVALID_NAMESPACE = 4
RESERVED_INSTANCE = (1 << (f.U16_BYTES * f.BYTE_BITS)) - 1
ATTRIBUTE_LIST_FIELDS = ('type', 'length', 'name_length', 'name_offset', 'lowest', 'reference', 'instance')
FILENAME_FIELDS = ('parent', 'created', 'modified', 'changed', 'accessed',
                   'allocated', 'size', 'attributes', 'ea', 'length', 'namespace')


def record_header(image, number):
    return dict(zip(s.FILE_HEADER_FIELDS,
                    f.FILE_HEADER.unpack_from(image, f.MFT_LCN * f.CLUSTER + number * f.RECORD)))


def rewrite(image, number, values, **changes):
    header = record_header(image, number)
    header.update(changes)
    values.sort(key=kind)
    f.put_record(image, number, f.file_record(number, values, sequence=header['sequence'],
                 links=header['links'], base=header['base'],
                 directory=bool(header['flags'] & f.FILE_IS_DIRECTORY)))


def filename_change(value, **changes):
    payload = bytearray(resident_value(value))
    fields = dict(zip(FILENAME_FIELDS, f.FILENAME_HEADER.unpack_from(payload)))
    fields.update(changes)
    f.FILENAME_HEADER.pack_into(payload, 0, *(fields[name] for name in FILENAME_FIELDS))
    instance = dict(zip(s.ATTR_HEADER_FIELDS, f.ATTR_HEADER.unpack_from(value)))['instance']
    return f.resident(f.FILENAME, payload, instance)


def attribute_change(value, **changes):
    value = bytearray(value)
    fields = dict(zip(s.ATTR_HEADER_FIELDS, f.ATTR_HEADER.unpack_from(value)))
    fields.update(changes)
    f.ATTR_HEADER.pack_into(value, 0, *(fields[name] for name in s.ATTR_HEADER_FIELDS))
    return bytes(value)


def replace_names(image, transform):
    number = v.HELLO_RECORD
    values = attributes(image, number)
    rewrite(image, number, [transform(value) if kind(value) == f.FILENAME else value for value in values])


def list_entries(image):
    value = next(value for value in attributes(image, v.HELLO_RECORD) if kind(value) == f.ATTR_LIST)
    payload = resident_value(value)
    entries, offset = [], 0
    while offset < len(payload):
        fields = dict(zip(ATTRIBUTE_LIST_FIELDS, f.ATTR_LIST_ENTRY.unpack_from(payload, offset)))
        entries.append(payload[offset:offset + fields['length']])
        offset += fields['length']
    return entries


def list_change(image, transform):
    original = list_entries(image)
    entries = [entry for entry in original
               if dict(zip(ATTRIBUTE_LIST_FIELDS, f.ATTR_LIST_ENTRY.unpack_from(entry)))['type'] != f.FILENAME]
    selected = [entry for entry in original
                if dict(zip(ATTRIBUTE_LIST_FIELDS, f.ATTR_LIST_ENTRY.unpack_from(entry)))['type'] == f.FILENAME]
    entries.extend(transform(selected))
    entries.sort(key=lambda entry: dict(zip(ATTRIBUTE_LIST_FIELDS, f.ATTR_LIST_ENTRY.unpack_from(entry)))['type'])
    values = [value for value in attributes(image, v.HELLO_RECORD) if kind(value) != f.ATTR_LIST]
    rewrite(image, v.HELLO_RECORD, values + [f.resident(f.ATTR_LIST, b''.join(entries), LIST_INSTANCE)])


def listed(source, *, large=False, nonresident=False, shuffled=False):
    image = v.build(source, 'dos-hardlinks')
    values = attributes(image, v.HELLO_RECORD)
    names = [value for value in values if kind(value) == f.FILENAME]
    values = [value for value in values if kind(value) != f.FILENAME]
    entries = []
    for value in values:
        header = dict(zip(s.ATTR_HEADER_FIELDS, f.ATTR_HEADER.unpack_from(value)))
        entries.append(f.list_entry(f.file_reference(v.HELLO_RECORD), header['instance'], 0, header['type']))
    if large:
        names = [v.filename(v.Link(f'primary-{index}' if index % 2 == 0 else f'DOS{index:02}',
                            namespace=f.NAMESPACE_WIN32 if index % 2 == 0 else f.NAMESPACE_DOS))
                 for index in range(LARGE_NAMES)]
    for offset in range(0, len(names), NAMES_PER_EXTENSION):
        number = FIRST_EXTENSION + offset // NAMES_PER_EXTENSION
        group = []
        for instance, value in enumerate(names[offset:offset + NAMES_PER_EXTENSION]):
            group.append(f.resident(f.FILENAME, resident_value(value), instance))
            entries.append(f.list_entry(f.file_reference(number), instance, 0, f.FILENAME))
        f.put_record(image, number, f.file_record(number, group, base=f.file_reference(v.HELLO_RECORD), links=0))
    # Canonical type order does not require ordering equal unnamed resident keys
    # by their location. A shuffled group exercises the private location sort.
    entries.sort(key=lambda entry: dict(zip(ATTRIBUTE_LIST_FIELDS, f.ATTR_LIST_ENTRY.unpack_from(entry)))['type'])
    if shuffled:
        entries = [entry for entry in entries if dict(zip(ATTRIBUTE_LIST_FIELDS, f.ATTR_LIST_ENTRY.unpack_from(entry)))['type'] != f.FILENAME] + [
            entry for entry in reversed(entries) if dict(zip(ATTRIBUTE_LIST_FIELDS, f.ATTR_LIST_ENTRY.unpack_from(entry)))['type'] == f.FILENAME]
    payload = b''.join(entries)
    if nonresident:
        clusters = (len(payload) + f.CLUSTER - 1) // f.CLUSTER
        values.append(f.nonresident(f.ATTR_LIST, [(clusters, LIST_LCN)], len(payload), LIST_INSTANCE))
        f.put_data(image, LIST_LCN, payload)
    else:
        values.append(f.resident(f.ATTR_LIST, payload, LIST_INSTANCE))
    rewrite(image, v.HELLO_RECORD, values, links=len(names))
    return image


def author(output, source=None):
    output.mkdir(parents=True, exist_ok=True)
    if source is None:
        source, _, _ = f.make_image()
    manifest = []

    def save(label, image, physical=0, primary=0, dos=0, result='success', number=v.HELLO_RECORD):
        name = 'links-' + label + '.img'
        (output / name).write_bytes(image)
        manifest.append({'image': name, 'reference': f'{f.file_reference(number):016x}',
                         'result': result, 'physical_names': physical, 'primary_names': primary,
                         'dos_aliases': dos})

    for label, physical, primary, dos, number in (
            ('single', 1, 1, 0, v.HELLO_RECORD), ('hardlinks', 2, 2, 0, v.HELLO_RECORD),
            ('dos', 2, 1, 1, v.HELLO_RECORD), ('dos-hardlinks', 4, 2, 2, v.HELLO_RECORD),
            ('dos-nested-hardlinks', 4, 2, 2, v.HELLO_RECORD),
            ('combined-name', 1, 1, 0, v.HELLO_RECORD),
            ('dos-directory', 2, 1, 1, v.FIRST_DIRECTORY),
            ('listed', 1, 1, 0, v.HELLO_RECORD), ('extension-filename', 1, 1, 0, v.HELLO_RECORD)):
        save(label, v.build(source, 'standard' if label == 'single' else label), physical, primary, dos, number=number)
    for label, options in (('listed-four', {}), ('listed-shuffled', {'shuffled': True}),
                           ('listed-nonresident', {'nonresident': True})):
        save(label, listed(source, **options), 4, 2, 2)
    # A resident base has limited space. The large inventory uses a nonresident
    # list and eight extension snapshots, each visited once by a cold count.
    save('listed-large', listed(source, large=True, nonresident=True, shuffled=True),
         LARGE_NAMES, LARGE_NAMES // 2, LARGE_NAMES // 2)
    for case in ('dos-only', 'dos-header-count-low', 'dos-header-count-high'):
        save(case, v.build(source, case), result='corrupt metadata')
    baseline = v.build(source, 'standard')
    for label, transform in (
            ('namespace', lambda value: filename_change(value, namespace=INVALID_NAMESPACE)),
            ('zero-length', lambda value: filename_change(value, length=0)),
            ('wrong-length', lambda value: filename_change(value, length=1)),
            ('parent-sequence', lambda value: filename_change(value, parent=f.ROOT_RECORD)),
            ('named', lambda value: f.resident(f.FILENAME, resident_value(value), v.FILENAME_INSTANCE, 'other')),
            ('truncated', lambda value: f.resident(f.FILENAME, resident_value(value)[:f.FILENAME_HEADER.size - 1], v.FILENAME_INSTANCE)),
            ('nonresident', lambda value: f.nonresident(f.FILENAME, [(1, LIST_LCN)], f.FILENAME_HEADER.size, v.FILENAME_INSTANCE)),
            ('flags', lambda value: attribute_change(value, flags=f.SPARSE))):
        image = bytearray(baseline)
        replace_names(image, transform)
        save(label, image, result='corrupt metadata')
    for label, text in (('nul', '\x00name'), ('slash', 'a/b')):
        image = bytearray(baseline)
        replace_names(image, lambda value: v.filename(v.Link(text)))
        save(label, image, result='corrupt metadata')
    image = bytearray(baseline)
    rewrite(image, v.HELLO_RECORD, [value for value in attributes(image, v.HELLO_RECORD) if kind(value) != f.FILENAME])
    save('missing', image, result='corrupt metadata')
    image = bytearray(baseline)
    rewrite(image, v.HELLO_RECORD, attributes(image, v.HELLO_RECORD), links=0)
    save('zero-header', image, result='corrupt metadata')
    image = v.build(source, 'hardlinks')
    replace_names(image, lambda value: attribute_change(value, instance=v.FILENAME_INSTANCE))
    save('duplicate-instance', image, result='corrupt metadata')
    base_list = listed(source)
    for label, transform in (
            ('list-duplicate', lambda entries: entries[:-1] + [entries[-2]]),
            ('list-missing', lambda entries: entries[:-1]),
            ('list-extra', lambda entries: entries + [entries[-1]]),
            ('list-truncated', lambda entries: entries[:-1] + [entries[-1][:-1]])):
        image = bytearray(base_list)
        list_change(image, transform)
        save(label, image, result='corrupt metadata')
    for label, changes in (('list-named', {'name_length': 1, 'name_offset': f.ATTR_LIST_ENTRY.size}),
                            ('list-lowest', {'lowest': 1}), ('list-zero-sequence', {'reference': FIRST_EXTENSION}),
                            ('list-reserved-instance', {'instance': RESERVED_INSTANCE}),
                            ('list-absent-instance', {'instance': NAMES_PER_EXTENSION})):
        def alter(entries):
            fields = dict(zip(ATTRIBUTE_LIST_FIELDS, f.ATTR_LIST_ENTRY.unpack_from(entries[-1])))
            fields.update(changes)
            replacement = bytearray(entries[-1])
            f.ATTR_LIST_ENTRY.pack_into(replacement, 0, *(fields[field] for field in ATTRIBUTE_LIST_FIELDS))
            return entries[:-1] + [bytes(replacement)]
        image = bytearray(base_list)
        list_change(image, alter)
        save(label, image, result='corrupt metadata')
    image = bytearray(base_list)
    rewrite(image, FIRST_EXTENSION, attributes(image, FIRST_EXTENSION), sequence=f.FILE_SEQUENCE + 1)
    save('list-stale', image, result='stale file reference')
    image = bytearray(base_list)
    rewrite(image, FIRST_EXTENSION, attributes(image, FIRST_EXTENSION), base=f.file_reference(v.FRAGMENTED_RECORD))
    save('list-owner', image, result='stale file reference')
    image = bytearray(base_list)
    values = attributes(image, FIRST_EXTENSION)
    rewrite(image, FIRST_EXTENSION, [attribute_change(value, instance=0) if index == 1 else value for index, value in enumerate(values)])
    save('list-duplicate-physical', image, result='corrupt metadata')
    image = bytearray(base_list)
    rewrite(image, v.HELLO_RECORD, attributes(image, v.HELLO_RECORD) + [v.filename(v.Link('unlisted'), instance=LIST_INSTANCE + 1)])
    save('list-unlisted-base', image, result='corrupt metadata')
    image = bytearray(base_list)
    rewrite(image, FIRST_EXTENSION, attributes(image, FIRST_EXTENSION) + [v.filename(v.Link('unlisted'), instance=NAMES_PER_EXTENSION)])
    save('list-unlisted-extension', image, result='corrupt metadata')
    (output / 'link-count-cases.json').write_text(json.dumps(manifest, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('stamp', type=Path)
    args = parser.parse_args()
    author(args.output)
    args.stamp.write_text('independent filename count fixtures\n')


if __name__ == '__main__':
    main()
