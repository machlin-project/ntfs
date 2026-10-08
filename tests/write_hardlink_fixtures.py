#!/usr/bin/env python3
"""Independent selected-cache hard-link input images and restored FILE goldens."""
from pathlib import Path
import argparse
import struct

import fixtures as f
import filename_storage as storage
import validation_fixtures as v
from write_metadata_fixtures import STANDARD, FILE, restored
from logfile_fixtures import Layout
from secure_fixtures import ATTR_HEADER_FIELDS

SUCCESS, CORRUPT, UNSUPPORTED, NOT_FOUND = 0, 2, 3, 6
IS_DIRECTORY, INVALID, STALE, RANGE, NO_SPACE, EXISTS = 8, 9, 10, 11, 17, 18
ADS_INSTANCE = 15
ADS_CONTENT = b'Independent ADS witness; keep every byte.'
CACHE_FIELDS = dict(created=13, modified=17, changed=19, accessed=23,
                    allocated=29, size=31, attributes=0x20, ea=37)
FILENAME = Layout(tuple(zip(storage.FILENAME_FIELDS,
    ('Q', 'Q', 'Q', 'Q', 'Q', 'Q', 'Q', 'I', 'I', 'B', 'B'))))
INDEX_RECORDS = 8
INDEX_NAME_UNITS = 200


def physical(number):
    return f.MFT_LCN * f.CLUSTER + number * f.RECORD


def parts(image, number):
    first = physical(number)
    return storage.record_parts(image[first:first + f.RECORD])


def put(image, number, header, attrs):
    f.put_record(image, number, storage.encoded_record(number, attrs, header))


def attr_of(attrs, kind, name=''):
    return next(a for a in attrs if storage.attr_header(a)['type'] == kind
                and storage.attr_name(a) == name)


def directory_entry(reference, value):
    length = f.align(f.INDEX_ENTRY.size + len(value))
    return f.INDEX_ENTRY.pack(reference, length, len(value), 0) + value + bytes(
        length - f.INDEX_ENTRY.size - len(value))


def root_with_entries(entries, external=False):
    return v.root_value(b''.join(entries) + f.entry(), external=external)


def bitmap_change(image, number, kind, change):
    header, attrs = parts(image, number)
    old = attr_of(attrs, kind)
    value = bytearray(storage.resident_value(old))
    change(value)
    attrs[attrs.index(old)] = f.resident(kind, value, storage.attr_header(old)['instance'])
    put(image, number, header, attrs)
    if number == f.MFT_RECORD:
        f.put_data(image, f.MIRROR_LCN, image[physical(number):physical(number) + f.RECORD])


def grow_directory(original, parent, template):
    image = bytearray(original)
    _, attrs = parts(image, f.MFT_RECORD)
    bitmap = storage.resident_value(attr_of(attrs, f.BITMAP))
    available = [n for n in range(24, f.MFT_COUNT)
                 if not bitmap[n // f.BYTE_BITS] & (1 << (n % f.BYTE_BITS))]
    numbers = available[:INDEX_RECORDS]
    assert len(numbers) == INDEX_RECORDS
    _, attrs = parts(image, f.BITMAP_RECORD)
    allocation = storage.resident_value(attr_of(attrs, f.DATA))
    cluster = next(n for n in range(len(image) // f.CLUSTER) if not allocation[
        n // f.BYTE_BITS] & (1 << (n % f.BYTE_BITS)))
    template_header, template_attrs = parts(image, template)
    entries = []
    for ordinal, number in enumerate(numbers):
        name = f'Filler{ordinal:02d}' + 'q' * (INDEX_NAME_UNITS - len('Filler00'))
        value = f.key(name, parent=f.file_reference(parent), namespace=f.NAMESPACE_POSIX)
        attrs = [a for a in template_attrs if storage.attr_header(a)['type'] not in (f.FILENAME, f.DATA)]
        attrs.extend((f.resident(f.FILENAME, value, 2), f.resident(f.DATA, b'', 3)))
        f.put_record(image, number, f.file_record(number, sorted(attrs,
            key=lambda a: storage.attr_header(a)['type']), links=1))
        entries.append(directory_entry(f.file_reference(number), value))
    f.put_data(image, cluster, f.index_block(0, entries))
    header, attrs = parts(image, parent)
    old = attr_of(attrs, f.INDEX_ROOT, '$I30')
    attrs[attrs.index(old)] = f.resident(f.INDEX_ROOT,
        v.root_value(f.entry(child=0), external=True), storage.attr_header(old)['instance'], '$I30')
    next_instance = header['next_instance']
    attrs += [f.nonresident(f.INDEX_ALLOC, [(1, cluster)], f.CLUSTER,
                           next_instance, '$I30'),
              f.resident(f.BITMAP, b'\x01', next_instance + 1, '$I30')]
    put(image, parent, header, attrs)
    bitmap_change(image, f.MFT_RECORD, f.BITMAP, lambda b: [
        b.__setitem__(n // f.BYTE_BITS, b[n // f.BYTE_BITS] | (1 << (n % f.BYTE_BITS)))
        for n in numbers])
    bitmap_change(image, f.BITMAP_RECORD, f.DATA, lambda b: b.__setitem__(
        cluster // f.BYTE_BITS, b[cluster // f.BYTE_BITS] | (1 << (cluster % f.BYTE_BITS))))
    return image


def author(output, source):
    output.mkdir(parents=True, exist_ok=True)
    base = bytearray((source / 'ancestor-posix.img').read_bytes())
    graph = {}
    for number in range(f.MFT_COUNT):
        raw = base[physical(number):physical(number) + f.RECORD]
        if raw[:4] != b'FILE':
            continue
        header, attrs = storage.record_parts(raw)
        if not header['flags'] & f.FILE_IN_USE:
            continue
        for attr in attrs:
            if storage.attr_header(attr)['type'] == f.FILENAME:
                value = storage.resident_value(attr)
                graph[value[f.FILENAME_HEADER.size:].decode('utf-16le')] = number
    target, parent, other = graph['data.bin'], graph['deep'], graph['right']
    # The source FILE_NAME cache deliberately differs from SI and its index key.
    header, attrs = parts(base, target)
    old = attr_of(attrs, f.FILENAME)
    value = bytearray(storage.resident_value(old))
    for field, number in CACHE_FIELDS.items():
        FILENAME.put(value, field, number)
    attrs[attrs.index(old)] = f.resident(f.FILENAME, value, storage.attr_header(old)['instance'])
    attrs.append(f.resident(f.DATA, ADS_CONTENT, ADS_INSTANCE, 'notes'))
    put(base, target, header, attrs)
    rows = []

    def add(label, image=base, *, number=target, src_parent=parent, src='data.bin',
            dst_parent=other, dst='new-link.txt', code=SUCCESS, reference=None,
            src_reference=None, dst_reference=None):
        image = bytes(image)
        (output / (label + '.img')).write_bytes(image)
        header, attrs = parts(image, number)
        reference = f.file_reference(number, header['sequence']) if reference is None else reference
        src_reference = f.file_reference(src_parent) if src_reference is None else src_reference
        dst_reference = f.file_reference(dst_parent) if dst_reference is None else dst_reference
        golden = '-'
        if code == SUCCESS:
            raw, _ = restored(image[physical(number):physical(number) + f.RECORD])
            source_attr = next(a for a in attrs if storage.attr_header(a)['type'] == f.FILENAME
                and storage.resident_value(a)[f.FILENAME_HEADER.size:].decode('utf-16le') == src)
            selected = dict(zip(storage.FILENAME_FIELDS,
                                f.FILENAME_HEADER.unpack_from(storage.resident_value(source_attr))))
            selected.update(parent=dst_reference, length=len(dst), namespace=f.NAMESPACE_POSIX)
            new_value = f.FILENAME_HEADER.pack(*(selected[k] for k in storage.FILENAME_FIELDS)) + dst.encode('utf-16le')
            new_attr = f.resident(f.FILENAME, new_value, header['next_instance'])
            # Supply an independent indexed-attribute golden using named fields.
            resident = dict(zip(storage.RESIDENT_FIELDS,
                                f.RESIDENT_HEADER.unpack_from(new_attr, f.ATTR_HEADER.size)))
            resident['indexed'] = 1
            new_attr = bytearray(new_attr)
            attr_header = storage.attr_header(new_attr)
            attr_header['name_offset'] = 0
            f.ATTR_HEADER.pack_into(new_attr, 0, *(attr_header[k] for k in ATTR_HEADER_FIELDS))
            f.RESIDENT_HEADER.pack_into(new_attr, f.ATTR_HEADER.size,
                                       *(resident[k] for k in storage.RESIDENT_FIELDS))
            insertion = header['attrs_offset'] + sum(len(a) for a in attrs
                if storage.attr_header(a)['type'] <= f.FILENAME)
            used = header['used']
            assert used + len(new_attr) <= f.RECORD
            expected = bytearray(raw[:insertion] + new_attr + raw[insertion:used] +
                                 raw[used + len(new_attr):])
            FILE.put(expected, 'used', used + len(new_attr))
            FILE.put(expected, 'links', header['links'] + 1)
            FILE.put(expected, 'next_instance', header['next_instance'] + 1)
            golden = label + '.record'
            (output / golden).write_bytes(expected)
            (output / (label + '.filename')).write_bytes(new_value)
        rows.append(f'{label} {code} {reference} {src_reference} {src} {dst_reference} {dst} {physical(number)} {golden}')

    add('cross-parent')
    add('same-parent', dst_parent=parent)
    add('long-name', dst='L' * 120)
    add('existing-destination', dst_parent=parent, dst='data.bin', code=EXISTS)
    add('folded-destination', dst_parent=parent, dst='DATA.BIN', code=EXISTS)
    add('missing-source', src='missing.bin', code=NOT_FOUND)
    add('stale-target', reference=f.file_reference(target, 2), code=STALE)
    add('stale-source', src_reference=f.file_reference(parent, 2), code=STALE)
    add('stale-destination', dst_reference=f.file_reference(other, 2), code=STALE)
    add('wrong-target', number=v.HELLO_RECORD, code=STALE)
    add('directory-target', number=other, code=IS_DIRECTORY)
    add('maximum-name-no-space', dst='L' * f.NAME_MAX_UNITS, code=NO_SPACE)
    for label, field, value, code in (('instance-collision', 'next_instance', ADS_INSTANCE, CORRUPT),
            ('instance-exhaustion', 'next_instance', (1 << 16) - 1, RANGE),
            ('bad-link-count', 'links', 2, CORRUPT),
            ('zero-link-count', 'links', 0, CORRUPT),
            ('maximum-link-count', 'links', (1 << 16) - 1, CORRUPT)):
        image = bytearray(base)
        FILE.put(image, field, value, physical(target))
        add(label, image, code=code)
    sensitive = bytearray(base)
    header, attrs = parts(sensitive, parent)
    old = attr_of(attrs, f.SI)
    value = bytearray(storage.resident_value(old))
    STANDARD.put(value, 'version', 1)
    attrs[attrs.index(old)] = f.resident(f.SI, value, storage.attr_header(old)['instance'])
    put(sensitive, parent, header, attrs)
    add('sensitive-distinct-name', sensitive, dst_parent=parent, dst='DATA.BIN')
    listed = bytearray(base)
    header, attrs = parts(listed, target)
    attrs.append(f.resident(f.ATTR_LIST, b'', ADS_INSTANCE + 1))
    put(listed, target, header, attrs)
    add('listed-target-refused', listed, code=UNSUPPORTED)
    # An existing native long/DOS pair is preserved byte-for-byte while a third
    # primary edge is added; no relationship between the two is invented.
    paired = bytearray(base)
    header, attrs = parts(paired, target)
    original = attr_of(attrs, f.FILENAME)
    value = bytearray(storage.resident_value(original))
    FILENAME.put(value, 'namespace', f.NAMESPACE_WIN32)
    attrs[attrs.index(original)] = f.resident(f.FILENAME, value, storage.attr_header(original)['instance'])
    alias = f.key('DATA~1.BIN', parent=f.file_reference(parent), namespace=f.NAMESPACE_DOS)
    attrs.append(f.resident(f.FILENAME, alias, ADS_INSTANCE + 1))
    header['links'] = 2
    put(paired, target, header, attrs)
    parent_header, parent_attrs = parts(paired, parent)
    root = attr_of(parent_attrs, f.INDEX_ROOT, '$I30')
    entries = [directory_entry(f.file_reference(target), item) for item in (value, alias)]
    entries.sort(key=lambda e: e[f.INDEX_ENTRY.size + f.FILENAME_HEADER.size:
        f.INDEX_ENTRY.size + f.INDEX_ENTRY.unpack_from(e)[2]].decode('utf-16le').upper())
    parent_attrs[parent_attrs.index(root)] = f.resident(f.INDEX_ROOT,
        root_with_entries(entries), storage.attr_header(root)['instance'], '$I30')
    put(paired, parent, parent_header, parent_attrs)
    add('paired-source', paired)
    add('dos-source-refused', paired, src='DATA~1.BIN', code=UNSUPPORTED)
    primary = bytearray(paired)
    header, attrs = parts(primary, target)
    old = next(a for a in attrs if storage.attr_header(a)['instance'] == ADS_INSTANCE + 1)
    value = bytearray(storage.resident_value(old))
    FILENAME.put(value, 'namespace', f.NAMESPACE_POSIX)
    attrs[attrs.index(old)] = f.resident(f.FILENAME, value, ADS_INSTANCE + 1)
    put(primary, target, header, attrs)
    parent_header, parent_attrs = parts(primary, parent)
    old = attr_of(parent_attrs, f.INDEX_ROOT, '$I30')
    first_value = storage.resident_value(attr_of(attrs, f.FILENAME))
    parent_attrs[parent_attrs.index(old)] = f.resident(f.INDEX_ROOT, root_with_entries([
        directory_entry(f.file_reference(target), item) for item in (first_value, value)]),
        storage.attr_header(old)['instance'], '$I30')
    put(primary, parent, parent_header, parent_attrs)
    add('existing-primary-link', primary)
    # Fragmented unnamed data and resident ADS remain entirely untouched.
    add('fragmented', number=v.FRAGMENTED_RECORD, src_parent=f.ROOT_RECORD,
        src='fragmented.bin')
    growth = grow_directory(base, other, target)
    add('index-split', growth, dst='Z' * 40)
    exhausted = bytearray(growth)
    bitmap_change(exhausted, f.BITMAP_RECORD, f.DATA,
                  lambda b: b.__setitem__(slice(None), b'\xff' * len(b)))
    add('index-no-space', exhausted, dst='Z' * 40, code=NO_SPACE)
    (output / 'cases.txt').write_text('\n'.join(rows) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('stamp', type=Path)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    author(args.output, args.source)
    args.stamp.write_text('independent hard-link preparation fixtures\n')
