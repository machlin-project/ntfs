#!/usr/bin/env python3
"""Author small NTFS parser fixtures independently of the C implementation.

These are intentionally not Windows-format acceptance: system files omitted from
these focused images are supplied by the separate mkntfs interoperability suite.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct

SECTOR = 512
CLUSTER = 4096
RECORD = 1024
IMAGE_SIZE = 8 * 1024 * 1024
BYTE_BITS = 8
BYTE_VALUES = 1 << BYTE_BITS
U16_BYTES = struct.calcsize('<H')
NAME_MAX_UNITS = 255
U64_BYTES = struct.calcsize('<Q')
U64_MAX = (1 << (U64_BYTES * BYTE_BITS)) - 1
FIXUP_SEQUENCE = 0xA55A
BOOT_SIGNATURE = 0xAA55
BOOT_SERIAL = 0x0123456789ABCDEF
BOOT_MEDIA = 0xF8
BOOT_FIELDS = {'jump': 0, 'oem': 3, 'sector_size': 11, 'cluster_sectors': 13,
               'media': 21, 'sectors': 40, 'mft': 48, 'mirror': 56,
               'record_code': 64, 'index_code': 68, 'serial': 72, 'signature': 510}
NTFS_MAJOR_VERSION, NTFS_MINOR_VERSION = 3, 1
VOLUME_DIRTY = 1
FILE_IN_USE, FILE_IS_DIRECTORY = 1, 2
FILE_UNINTERPRETED = 4
FILE_VIEW_INDEX = 8
ALLOCATED_CLUSTERS = 160
SECURITY_ID = 256
PATTERN_MULTIPLIER, PATTERN_ADDEND = 13, 7
FRAGMENTED_BYTES = 6000
INITIALIZED_BYTES = 100
LARGE_SPARSE_BYTES = 8 * 1024 * 1024 * 1024
TIMESTAMP_OFFSET_TICKS = 123456789
MFT_LCN = 4
MIRROR_LCN = 32
UPCASE_LCN = 64
INDEX_LCN = 100
MFT_COUNT = 64
REFERENCE_SEQUENCE_SHIFT = 48
SYSTEM_RECORD_LIMIT = 16
SYSTEM_SEQUENCE = 1
FILE_SEQUENCE = 7
MFT_RECORD = 0
ROOT_RECORD = 5
ROOT_REF = (SYSTEM_SEQUENCE << REFERENCE_SEQUENCE_SHIFT) | ROOT_RECORD
MFT_DATA_INSTANCE = 3
MFT_LIST_INSTANCE = 2
MFT_PREFIX_CLUSTERS = 4
MFT_SECOND_LCN = 40
MFT_FINAL_LCN = 48
MFT_LIST_LCN = 36
MFT_FIRST_EXTENSION = 12
MFT_SECOND_EXTENSION = 20
VOLUME_RECORD, BITMAP_RECORD, UPCASE_RECORD = 3, 6, 10
ATTRIBUTE_EXTENSION_RECORD = 40
FILE_RECORDS = {'hello.txt': 24, 'fragmented.bin': 25, 'compressed.bin': 26,
                'extended.bin': 27, 'middle.dat': 28, 'sparse.bin': 29,
                'streamed.txt': 30, 'tail.bin': 31, 'Ωmega.txt': 32}
DATA_LCNS = {'fragmented.bin': (128, 130), 'tail.bin': (132,),
             'sparse.bin': (136, 138), 'compressed.bin': (140,),
             'extended.bin': (144, 148)}
MIXED_RAW_LCN, MIXED_PREFIX_SECOND_LCN, MIXED_FINAL_LCN = 112, 142, 152
SI, ATTR_LIST, VOL_NAME, VOL_INFO = 0x10, 0x20, 0x60, 0x70
FILENAME = 0x30
DATA, INDEX_ROOT, INDEX_ALLOC, BITMAP = 0x80, 0x90, 0xA0, 0xB0
REPARSE_POINT = 0xC0
REPARSE_TAG_SYMLINK = 0xA000000C
REPARSE_TAG_MOUNT_POINT = 0xA0000003
REPARSE_TAG_WOF = 0x80000017
REPARSE_TAG_CLOUD = 0x9000001A
REPARSE_TAG_UNKNOWN = 0x80001234
REPARSE_TAG_THIRD_PARTY = 0x00001234
REPARSE_SYMLINK_RELATIVE = 1
REPARSE_RESERVED_FIELD = 0xABCD
REPARSE_INSTANCE = 3
REPARSE_LIST_INSTANCE = 2
REPARSE_LCNS = (150, 158)
REPARSE_LONG_NAME_UNITS = 3000
REPARSE_MAX_BYTES = 16 * 1024
REPARSE_HEADER = struct.Struct('<IHH')
REPARSE_NAMES = struct.Struct('<HHHH')
REPARSE_FLAGS = struct.Struct('<I')
GUID_HEADER = struct.Struct('<IHHQ')
REPARSE_RELATIVE_TARGET = '..\\Ω-target.txt'
REPARSE_ABSOLUTE_TARGET = '\\??\\C:\\folder\\target.txt'
REPARSE_PRINT_TARGET = 'C:\\folder\\target.txt'
ATTR_END = 0xFFFFFFFF
SPARSE, COMPRESSED = 0x8000, 1
ENCRYPTED = 0x4000
CHILD, END = 1, 2
INDEX_LARGE = 1
COLLATION_FILENAME = 1
NAMESPACE_POSIX = 0
NAMESPACE_WIN32 = 1
NAMESPACE_DOS = 2
FILE_ATTRIBUTE_DIRECTORY = 0x10000000
FILE_ATTRIBUTE_SPARSE = 0x200
FILE_ATTRIBUTE_COMPRESSED = 0x800
FILE_ATTRIBUTE_REPARSE = 0x400
FILE_ATTRIBUTE_ENCRYPTED = 0x4000
WIRE_ALIGNMENT = 8
DIR_ROOT_INSTANCE = 1
DIR_ALLOCATION_INSTANCE = 2
DIR_BITMAP_INSTANCE = 3
COMPRESSION_UNIT_SHIFT = 4
COMPRESSION_CLUSTERS = 1 << COMPRESSION_UNIT_SHIFT
COMPRESSION_UNIT_BYTES = CLUSTER * COMPRESSION_CLUSTERS
LZNT1_CHUNK_BYTES = 4096
LZNT1_SIGNATURE = 0x3000
LZNT1_COMPRESSED = 0x8000
LZNT1_MIN_MATCH = 3
LZNT1_LITERAL_THEN_MATCH = 1 << 1
ATTR_HEADER = struct.Struct('<IIBBHHH')
RESIDENT_HEADER = struct.Struct('<IHBB')
NONRESIDENT_HEADER = struct.Struct('<QQHB5xQQQ')
FILE_HEADER = struct.Struct('<4sHHQHHHHIIQHHI')
FILE_HEADER_LEGACY = struct.Struct('<4sHHQHHHHIIQH')
INDEX_HEADER = struct.Struct('<IIIB3x')
INDEX_ROOT_HEADER = struct.Struct('<IIIB3x')
INDEX_ENTRY = struct.Struct('<QHHH2x')
FILENAME_HEADER = struct.Struct('<QQQQQQQIIBB')
ATTR_LIST_ENTRY = struct.Struct('<IHBBQQH')
STANDARD_INFO = struct.Struct('<QQQQIIIIIIQQ')
STANDARD_INFO_COMMON = struct.Struct('<QQQQIIII')
EPOCH = 116444736000000000


def align(n):
    return (n + WIRE_ALIGNMENT - 1) & ~(WIRE_ALIGNMENT - 1)


def resident(kind, value, instance=0, name=''):
    name_bytes = name.encode('utf-16le', errors='surrogatepass')
    value_offset = align(ATTR_HEADER.size + RESIDENT_HEADER.size + len(name_bytes))
    length = align(value_offset + len(value))
    out = bytearray(length)
    ATTR_HEADER.pack_into(out, 0, kind, length, 0, len(name_bytes) // U16_BYTES, ATTR_HEADER.size + RESIDENT_HEADER.size, 0, instance)
    RESIDENT_HEADER.pack_into(out, ATTR_HEADER.size, len(value), value_offset, 0, 0)
    out[ATTR_HEADER.size + RESIDENT_HEADER.size:ATTR_HEADER.size + RESIDENT_HEADER.size + len(name_bytes)] = name_bytes
    out[value_offset:value_offset + len(value)] = value
    return bytes(out)


def integer_bytes(value, signed=False):
    for width in range(1, U64_BYTES + 1):
        try:
            return value.to_bytes(width, 'little', signed=signed)
        except OverflowError:
            pass
    raise ValueError(value)


def nonresident(kind, runs, size, instance=0, name='', lowest=0, initialized=None, flags=0, allocated=None):
    pairs = bytearray()
    last_lcn = 0
    for count, lcn in runs:
        count_bytes = integer_bytes(count)
        delta = b'' if lcn is None else integer_bytes(lcn - last_lcn, True)
        pairs += bytes([len(count_bytes) | len(delta) << (BYTE_BITS // 2)]) + count_bytes + delta
        if lcn is not None:
            last_lcn = lcn
    pairs += b'\0'
    name_bytes = name.encode('utf-16le', errors='surrogatepass')
    extended_header = bool(flags & (SPARSE | COMPRESSED))
    header_size = ATTR_HEADER.size + NONRESIDENT_HEADER.size + (U64_BYTES if extended_header else 0)
    mapping_offset = align(header_size + len(name_bytes))
    length = align(mapping_offset + len(pairs))
    out = bytearray(length)
    count = sum(n for n, _ in runs)
    if allocated is None:
        allocated = count * CLUSTER
    ATTR_HEADER.pack_into(out, 0, kind, length, 1, len(name_bytes) // U16_BYTES, header_size, flags, instance)
    highest = lowest + count - 1 if count else U64_MAX
    NONRESIDENT_HEADER.pack_into(out, ATTR_HEADER.size, lowest, highest, mapping_offset, COMPRESSION_UNIT_SHIFT if flags & COMPRESSED else 0, allocated, size, size if initialized is None else initialized)
    if extended_header:
        struct.pack_into('<Q', out, ATTR_HEADER.size + NONRESIDENT_HEADER.size, sum(n for n, lcn in runs if lcn is not None) * CLUSTER)
    out[header_size:header_size + len(name_bytes)] = name_bytes
    out[mapping_offset:mapping_offset + len(pairs)] = pairs
    return bytes(out)


def protect(out, usa_offset):
    struct.pack_into('<H', out, usa_offset, FIXUP_SEQUENCE)
    for sector in range(1, len(out) // SECTOR + 1):
        tail = sector * SECTOR - U16_BYTES
        out[usa_offset + sector * U16_BYTES:usa_offset + (sector + 1) * U16_BYTES] = out[tail:tail + U16_BYTES]
        struct.pack_into('<H', out, tail, FIXUP_SEQUENCE)


def file_record(number, attrs, directory=False, sequence=None, base=0, legacy=False, links=1, view=False,
                uninterpreted=False):
    sequence = sequence if sequence is not None else (SYSTEM_SEQUENCE if number < SYSTEM_RECORD_LIMIT else FILE_SEQUENCE)
    header = FILE_HEADER_LEGACY if legacy else FILE_HEADER
    usa_offset = header.size
    usa_count = RECORD // SECTOR + 1
    attrs_offset = align(usa_offset + usa_count * U16_BYTES)
    content = b''.join(attrs) + struct.pack('<II', ATTR_END, 0)
    used = attrs_offset + len(content)
    assert used <= RECORD, (number, used)
    out = bytearray(RECORD)
    fields = (b'FILE', usa_offset, usa_count, 0, sequence, links, attrs_offset,
              FILE_IN_USE | (FILE_IS_DIRECTORY if directory else 0) | (FILE_VIEW_INDEX if view else 0)
              | (FILE_UNINTERPRETED if uninterpreted else 0), used, RECORD, base, len(attrs))
    header.pack_into(out, 0, *fields, *(() if legacy else (0, number)))
    out[attrs_offset:used] = content
    protect(out, usa_offset)
    return bytes(out)


def standard(attributes=0, security_id=SECURITY_ID, *, max_versions=0, version=0, common_only=False):
    value = STANDARD_INFO.pack(EPOCH, EPOCH + TIMESTAMP_OFFSET_TICKS, EPOCH, EPOCH, attributes, max_versions, version, 0, 0, security_id, 0, 0)
    return resident(SI, value[:STANDARD_INFO_COMMON.size] if common_only else value)


def key(name, size=0, namespace=NAMESPACE_WIN32, parent=ROOT_REF, attributes=0):
    raw = name.encode('utf-16le', errors='surrogatepass')
    return FILENAME_HEADER.pack(parent, EPOCH, EPOCH, EPOCH, EPOCH, align(size), size, attributes, 0, len(raw) // U16_BYTES, namespace) + raw


def entry(name=None, number=0, size=0, child=None, namespace=NAMESPACE_WIN32, parent=ROOT_REF, attributes=0):
    value = b'' if name is None else key(name, size, namespace, parent, attributes)
    flags = (END if name is None else 0) | (CHILD if child is not None else 0)
    length = align(INDEX_ENTRY.size + len(value)) + (U64_BYTES if child is not None else 0)
    out = bytearray(length)
    INDEX_ENTRY.pack_into(out, 0, file_reference(number) if name is not None else 0, length, len(value), flags)
    out[INDEX_ENTRY.size:INDEX_ENTRY.size + len(value)] = value
    if child is not None:
        struct.pack_into('<Q', out, length - U64_BYTES, child)
    return bytes(out)


def index_block(vcn, entries, terminal_child=None):
    out = bytearray(CLUSTER)
    header_offset = struct.calcsize('<4sHHQQ')
    usa_offset = header_offset + INDEX_HEADER.size
    usa_count = CLUSTER // SECTOR + 1
    first = align(usa_offset + usa_count * U16_BYTES)
    content = b''.join(entries) + entry(child=terminal_child)
    struct.pack_into('<4sHHQQ', out, 0, b'INDX', usa_offset, usa_count, 0, vcn)
    INDEX_HEADER.pack_into(out, header_offset, first - header_offset, first + len(content) - header_offset, CLUSTER - header_offset, INDEX_LARGE if terminal_child is not None else 0)
    out[first:first + len(content)] = content
    protect(out, usa_offset)
    return out


def directory_record(entries, allocation_clusters=0, data_streams=(), legacy=False,
                     *, number=ROOT_RECORD, version=0, max_versions=0, common_only=False):
    root = INDEX_ROOT_HEADER.pack(FILENAME, COLLATION_FILENAME, CLUSTER, 1)
    root += INDEX_HEADER.pack(INDEX_HEADER.size, INDEX_HEADER.size + len(entries),
                              INDEX_HEADER.size + len(entries), INDEX_LARGE if allocation_clusters else 0)
    root += entries
    attrs = [standard(FILE_ATTRIBUTE_DIRECTORY, version=version, max_versions=max_versions,
                      common_only=common_only), *data_streams, resident(INDEX_ROOT, root, DIR_ROOT_INSTANCE, '$I30')]
    if allocation_clusters:
        bitmap = ((1 << allocation_clusters) - 1).to_bytes((allocation_clusters + BYTE_BITS - 1) // BYTE_BITS, 'little')
        attrs += [nonresident(INDEX_ALLOC, [(allocation_clusters, INDEX_LCN)],
                              allocation_clusters * CLUSTER, DIR_ALLOCATION_INSTANCE, '$I30'),
                  resident(BITMAP, bitmap, DIR_BITMAP_INSTANCE, '$I30')]
    return file_record(number, attrs, directory=True, legacy=legacy)


def list_entry(reference, instance, lowest, kind=DATA, name=''):
    encoded = name.encode('utf-16le', errors='surrogatepass')
    name_offset = ATTR_LIST_ENTRY.size if encoded else 0
    out = bytearray(align(ATTR_LIST_ENTRY.size + len(encoded)))
    ATTR_LIST_ENTRY.pack_into(out, 0, kind, len(out), len(encoded) // U16_BYTES,
                             name_offset, lowest, reference, instance)
    out[ATTR_LIST_ENTRY.size:ATTR_LIST_ENTRY.size + len(encoded)] = encoded
    return bytes(out)


def file_reference(number, sequence=None):
    if sequence is None:
        sequence = SYSTEM_SEQUENCE if number < SYSTEM_RECORD_LIMIT else FILE_SEQUENCE
    return (sequence << REFERENCE_SEQUENCE_SHIFT) | number


def reparse_value(tag, substitute='', display='', relative=False, print_first=False):
    """Independently authored MS-FSCC link buffers, retaining raw UTF-16 units."""
    substitute_bytes = substitute.encode('utf-16le', errors='surrogatepass')
    print_bytes = display.encode('utf-16le', errors='surrogatepass')
    terminator = bytes(U16_BYTES)
    if print_first:
        path = print_bytes + terminator + substitute_bytes + terminator
        print_offset, substitute_offset = 0, len(print_bytes) + len(terminator)
    else:
        path = substitute_bytes + terminator + print_bytes + terminator
        substitute_offset, print_offset = 0, len(substitute_bytes) + len(terminator)
    payload = REPARSE_NAMES.pack(substitute_offset, len(substitute_bytes),
                                 print_offset, len(print_bytes))
    if tag == REPARSE_TAG_SYMLINK:
        payload += REPARSE_FLAGS.pack(REPARSE_SYMLINK_RELATIVE if relative else 0)
    payload += path
    return REPARSE_HEADER.pack(tag, len(payload), REPARSE_RESERVED_FIELD) + payload


def reparse_fixtures(output, image):
    """Separate images exercise ownership and attribute storage, without mounts."""
    number = FILE_RECORDS['hello.txt']
    relative = reparse_value(REPARSE_TAG_SYMLINK, REPARSE_RELATIVE_TARGET,
                             REPARSE_RELATIVE_TARGET, relative=True, print_first=True)
    absolute = reparse_value(REPARSE_TAG_SYMLINK, REPARSE_ABSOLUTE_TARGET,
                             REPARSE_PRINT_TARGET)
    junction = reparse_value(REPARSE_TAG_MOUNT_POINT, REPARSE_ABSOLUTE_TARGET,
                             REPARSE_PRINT_TARGET, print_first=True)
    unpaired = reparse_value(REPARSE_TAG_SYMLINK, '\ud800x', relative=True)
    long_value = reparse_value(REPARSE_TAG_SYMLINK, 'R' * REPARSE_LONG_NAME_UNITS,
                               relative=True)
    opaque_payload = b'filter-owned payload'
    opaque = {
        'wof': REPARSE_TAG_WOF,
        'cloud': REPARSE_TAG_CLOUD,
        'unknown': REPARSE_TAG_UNKNOWN,
        'third-party': REPARSE_TAG_THIRD_PARTY,
    }
    guid_payload = b'opaque GUID payload'
    guid_value = REPARSE_HEADER.pack(REPARSE_TAG_SYMLINK, len(guid_payload), 0)
    guid_value += GUID_HEADER.pack(1, 0, 0, 0) + guid_payload
    (output / 'microsoft-guid.reparse').write_bytes(guid_value)

    def save(label, value, directory=False, attributes=None, extension=None, data=None,
             file_attributes=FILE_ATTRIBUTE_REPARSE):
        changed = bytearray(image)
        attrs = [standard(file_attributes), resident(DATA, b'not user data', 1)]
        attrs += attributes if attributes is not None else [resident(REPARSE_POINT, value, REPARSE_INSTANCE)]
        put_record(changed, number, file_record(number, attrs, directory=directory))
        if extension is not None:
            put_record(changed, ATTRIBUTE_EXTENSION_RECORD, extension)
        for lcn, payload in data or ():
            put_data(changed, lcn, payload)
        (output / ('reparse-' + label + '.img')).write_bytes(changed)
        if value is not None:
            (output / ('reparse-' + label + '.reparse')).write_bytes(value)

    save('relative', relative)
    save('absolute', absolute)
    save('junction', junction, directory=True)
    save('unpaired', unpaired)
    for label, tag in opaque.items():
        value = REPARSE_HEADER.pack(tag, len(opaque_payload), 0) + opaque_payload
        save(label, value)
    first_lcn, last_lcn = REPARSE_LCNS
    runs = [(1, first_lcn), (1, last_lcn)]
    assert CLUSTER < len(long_value) <= len(runs) * CLUSTER
    save('nonresident', long_value,
         attributes=[nonresident(REPARSE_POINT, runs, len(long_value), REPARSE_INSTANCE)],
         data=[(first_lcn, long_value[:CLUSTER]), (last_lcn, long_value[CLUSTER:])])
    entries = list_entry(file_reference(number), REPARSE_INSTANCE, 0, REPARSE_POINT)
    entries += list_entry(file_reference(ATTRIBUTE_EXTENSION_RECORD), 0, 1, REPARSE_POINT)
    extension = file_record(ATTRIBUTE_EXTENSION_RECORD,
                            [nonresident(REPARSE_POINT, [(1, last_lcn)], 0, lowest=1)],
                            base=file_reference(number))
    save('listed', long_value,
         attributes=[resident(ATTR_LIST, entries, REPARSE_LIST_INSTANCE),
                     nonresident(REPARSE_POINT, [(1, first_lcn)], len(long_value),
                                 REPARSE_INSTANCE, allocated=len(runs) * CLUSTER)],
         extension=extension,
         data=[(first_lcn, long_value[:CLUSTER]), (last_lcn, long_value[CLUSTER:])])
    entries = list_entry(file_reference(ATTRIBUTE_EXTENSION_RECORD), REPARSE_INSTANCE, 0,
                         REPARSE_POINT)
    extension = file_record(ATTRIBUTE_EXTENSION_RECORD,
                            [resident(REPARSE_POINT, relative, REPARSE_INSTANCE)],
                            base=file_reference(number))
    save('resident-extension', relative,
         attributes=[resident(ATTR_LIST, entries, REPARSE_LIST_INSTANCE)], extension=extension)
    save('unflagged-extension', relative, file_attributes=0,
         attributes=[resident(ATTR_LIST, entries, REPARSE_LIST_INSTANCE)], extension=extension)
    save('unflagged', relative, file_attributes=0)
    # Presence cannot be inferred only from the list or only from unnamed values.
    ordinary_entries = list_entry(file_reference(number), 0, 0, SI)
    ordinary_entries += list_entry(file_reference(number), 1, 0, DATA)
    save('unlisted-base', relative, file_attributes=0,
         attributes=[resident(ATTR_LIST, ordinary_entries, REPARSE_LIST_INSTANCE),
                     resident(REPARSE_POINT, relative, REPARSE_INSTANCE)])
    invalid_name = 'hidden-filter'
    save('named-unflagged', relative, file_attributes=0,
         attributes=[resident(REPARSE_POINT, relative, REPARSE_INSTANCE, invalid_name)])
    named_entries = ordinary_entries + list_entry(
        file_reference(ATTRIBUTE_EXTENSION_RECORD), REPARSE_INSTANCE, 0,
        REPARSE_POINT, invalid_name)
    named_extension = file_record(
        ATTRIBUTE_EXTENSION_RECORD,
        [resident(REPARSE_POINT, relative, REPARSE_INSTANCE, invalid_name)],
        base=file_reference(number))
    save('named-listed-unflagged', relative, file_attributes=0,
         attributes=[resident(ATTR_LIST, named_entries, REPARSE_LIST_INSTANCE)],
         extension=named_extension)
    save('missing', None, attributes=[])
    save('duplicate', relative,
         attributes=[resident(REPARSE_POINT, relative, REPARSE_INSTANCE),
                     resident(REPARSE_POINT, absolute, REPARSE_INSTANCE + 1)])
    save('short', relative[:REPARSE_HEADER.size - 1])
    save('length', relative + bytes(U16_BYTES))
    save('junction-file', junction)
    save('uninitialized', long_value,
         attributes=[nonresident(REPARSE_POINT, runs, len(long_value), REPARSE_INSTANCE,
                                 initialized=len(long_value) - 1)])
    save('sparse', long_value,
         attributes=[nonresident(REPARSE_POINT, [(len(runs), None)], len(long_value),
                                 REPARSE_INSTANCE, flags=SPARSE)])
    oversized = bytes(REPARSE_MAX_BYTES + U16_BYTES)
    clusters = (len(oversized) + CLUSTER - 1) // CLUSTER
    save('oversized', oversized,
         attributes=[nonresident(REPARSE_POINT, [(clusters, first_lcn)], len(oversized),
                                 REPARSE_INSTANCE)], data=[(first_lcn, oversized)])
    # A reparse directory carrying a plausible local index must still fail closed.
    ordinary_index = INDEX_ROOT_HEADER.pack(FILENAME, COLLATION_FILENAME, CLUSTER, 1)
    empty_entries = entry()
    ordinary_index += INDEX_HEADER.pack(INDEX_HEADER.size,
                                       INDEX_HEADER.size + len(empty_entries),
                                       INDEX_HEADER.size + len(empty_entries), 0)
    ordinary_index += empty_entries
    save('directory', junction, directory=True,
         attributes=[resident(INDEX_ROOT, ordinary_index, REPARSE_INSTANCE + 1, '$I30'),
                     resident(REPARSE_POINT, junction, REPARSE_INSTANCE)])


def catalog_fixtures(output, image, contents):
    """Independent stream-name inventories; content validation remains separate."""
    number = FILE_RECORDS['hello.txt']
    base_reference = file_reference(number)
    extension_reference = file_reference(ATTRIBUTE_EXTENSION_RECORD)
    list_instance, default_instance, named_instance = 2, 1, 3
    payload = b'catalog payload'
    names = ('$DATA', 'NOTES', 'notes', 'Ω', '\ud800')

    def save(label, attributes, extension=None):
        changed = bytearray(image)
        put_record(changed, number, file_record(number, attributes))
        if extension is not None:
            put_record(changed, ATTRIBUTE_EXTENSION_RECORD, extension)
        (output / ('catalog-' + label + '.img')).write_bytes(changed)

    common = [standard(), resident(DATA, contents['hello.txt'], default_instance)]
    save('long-unpaired', common + [
        resident(DATA, payload, named_instance, '\ud800' + 'x' * (NAME_MAX_UNITS - 1))])
    oversized_stream_bytes = 2 * 1024 * 1024
    save('oversized', common + [nonresident(
        DATA, [(oversized_stream_bytes // CLUSTER, None)], oversized_stream_bytes,
        named_instance, 'notes', flags=SPARSE)])
    fragmented_runs = [(1, lcn) for lcn in DATA_LCNS['fragmented.bin']]
    save('fragmented', common + [nonresident(
        DATA, fragmented_runs, FRAGMENTED_BYTES, named_instance, 'notes')])
    save('duplicate', common + [
        resident(DATA, payload, named_instance, 'notes'),
        resident(DATA, payload, named_instance + 1, 'notes')])
    ordinary = list_entry(base_reference, 0, 0, SI)
    ordinary += list_entry(base_reference, default_instance, 0, DATA)
    save('unlisted-base', common + [resident(ATTR_LIST, ordinary, list_instance),
                                  resident(DATA, payload, named_instance, 'notes')])
    named_entries = b''.join(list_entry(extension_reference, instance, 0, DATA, name)
                              for instance, name in enumerate(names))
    extension_attributes = [resident(DATA, payload, instance, name)
                            for instance, name in enumerate(names)]
    extension = file_record(ATTRIBUTE_EXTENSION_RECORD, extension_attributes,
                            base=base_reference)
    save('listed', common + [resident(ATTR_LIST, ordinary + named_entries, list_instance)],
         extension)
    stale_entries = ordinary + list_entry(
        file_reference(ATTRIBUTE_EXTENSION_RECORD, FILE_SEQUENCE + 1), 0, 0, DATA, names[0])
    save('stale', common + [resident(ATTR_LIST, stale_entries, list_instance)], extension)
    wrong_extension = file_record(ATTRIBUTE_EXTENSION_RECORD, extension_attributes,
                                  base=file_reference(FILE_RECORDS['middle.dat']))
    save('wrong-base', common + [
        resident(ATTR_LIST, ordinary + named_entries, list_instance)], wrong_extension)
    missing_instance = ordinary + list_entry(extension_reference, len(names), 0, DATA, names[0])
    save('instance', common + [resident(ATTR_LIST, missing_instance, list_instance)], extension)


def namespace_fixtures(output, image, contents):
    """A directory link identifies a name independently of its hard-linked inode."""
    number = FILE_RECORDS['hello.txt']
    target = file_reference(number)
    payload = contents['hello.txt']
    leaf_entries = 5  # Fits 255-unit keys in the authored 4-KiB index block.
    native_component_bytes = 255
    large_name_prefix_units = 4
    large_count = 2000  # A complete reverse manifest exceeds the 1-MiB response cap.

    def units(name):
        encoded = name.encode('utf-16le', errors='surrogatepass')
        return struct.unpack('<' + 'H' * (len(encoded) // U16_BYTES), encoded)

    def order(name):
        original = units(name)
        folded = tuple(u - ord('a') + ord('A') if ord('a') <= u <= ord('z') else u
                       for u in original)
        return folded, original

    def build(names, hidden=False, case_sensitive=False):
        blocks = []
        links = len(names)
        metadata_name, dos_name = '!metadata', 'AAA~1'
        if hidden:
            names = sorted([*names, metadata_name, dos_name], key=order)

        def link(name, child=None):
            if hidden and name == metadata_name:
                return entry(name, VOLUME_RECORD, child=child)
            namespace = NAMESPACE_DOS if hidden and name == dos_name else NAMESPACE_WIN32
            return entry(name, number, len(payload), child=child, namespace=namespace)

        def subtree(first, last):
            if last - first <= leaf_entries:
                content = [link(names[i]) for i in range(first, last)]
                terminal = None
            else:
                middle = first + (last - first) // 2
                left = subtree(first, middle)
                terminal = subtree(middle + 1, last)
                content = [link(names[middle], child=left)]
            vcn = len(blocks)
            blocks.append(index_block(vcn, content, terminal))
            return vcn

        root_child = subtree(0, len(names))
        if (INDEX_LCN + len(blocks)) * CLUSTER > IMAGE_SIZE:
            return None
        changed = bytearray(image)
        for vcn, block in enumerate(blocks):
            put_data(changed, INDEX_LCN + vcn, block)
        put_record(changed, ROOT_RECORD,
                   directory_record(entry(child=root_child), len(blocks), version=int(case_sensitive)))
        put_record(changed, number, file_record(number,
                   [standard(), resident(DATA, payload, 1)], links=links))
        bitmap = bytearray(IMAGE_SIZE // CLUSTER // BYTE_BITS)
        for cluster in range(max(ALLOCATED_CLUSTERS, INDEX_LCN + len(blocks))):
            bitmap[cluster // BYTE_BITS] |= 1 << (cluster % BYTE_BITS)
        put_record(changed, BITMAP_RECORD, file_record(BITMAP_RECORD,
                   [standard(), resident(DATA, bitmap, 1)]))
        return changed

    names = sorted(['hello.txt', 'a' * NAME_MAX_UNITS, 'Ω' * NAME_MAX_UNITS,
                    '😀' * (NAME_MAX_UNITS // 2) + 'x', 'bad\ud800name', 'bad\udc00name',
                    '~literal', '~ntfs-0007000000000018-00000000',
                    'é.txt', 'e\u0301.txt', '.', '..'], key=order)
    (output / 'namespace.img').write_bytes(build(names))
    (output / 'namespace-sensitive.img').write_bytes(build(names, case_sensitive=True))
    (output / 'namespace-hidden.img').write_bytes(build(names, hidden=True))
    expected = []
    for ordinal, name in enumerate(names):
        try:
            literal = name.encode('utf-8')
        except UnicodeEncodeError:
            literal = None
        if literal is None or len(literal) > native_component_bytes or name.startswith('~') or name in ('.', '..'):
            native = f'~ntfs-{target:016x}-{ordinal:08x}'
        else:
            native = name
        expected.append({'units': list(units(name)), 'native': native, 'reference': target,
                         'size': len(payload)})
    (output / 'namespace.json').write_text(json.dumps(expected, indent=2) + '\n')
    (output / 'namespace-invalid.img').write_bytes(build(['\0bad']))
    stale = build(names)
    put_record(stale, number, file_record(number,
               [standard(), resident(DATA, payload, 1)], sequence=FILE_SEQUENCE + 1))
    (output / 'namespace-stale.img').write_bytes(stale)
    large_names = [f'{i:04d}' + 'Ω' * (NAME_MAX_UNITS - large_name_prefix_units)
                   for i in range(large_count)]
    large = build(large_names)
    if large is not None:
        (output / 'namespace-large.img').write_bytes(large)
        large_expected = [{'units': list(units(name)),
                           'native': f'~ntfs-{target:016x}-{ordinal:08x}',
                           'reference': target, 'size': len(payload)}
                          for ordinal, name in enumerate(large_names)]
        (output / 'namespace-large.json').write_text(json.dumps(large_expected) + '\n')


def fragmented_mft(image, nonresident_list=False, damage=None):
    """Each extension reveals the mapping needed to reach the next one.

    Erase the old contiguous MFT so a parser cannot pass by guessing addresses.
    The allocation bitmap already reserves every destination cluster.
    """
    changed = bytearray(image)
    mft_bytes = MFT_COUNT * RECORD
    mft_clusters = mft_bytes // CLUSTER
    table_start = MFT_LCN * CLUSTER
    table = bytearray(image[table_start:table_start + mft_bytes])
    base = file_reference(MFT_RECORD)
    first_reference = file_reference(MFT_FIRST_EXTENSION)
    first_lowest = MFT_PREFIX_CLUSTERS
    if damage == 'stale':
        first_reference = file_reference(MFT_FIRST_EXTENSION, SYSTEM_SEQUENCE + 1)
    elif damage == 'unreachable':
        first_reference = file_reference(MFT_SECOND_EXTENSION)
    elif damage == 'gap':
        first_lowest += 1
    entries = [list_entry(base, MFT_DATA_INSTANCE, 0),
               list_entry(first_reference, 0, first_lowest),
               list_entry(file_reference(MFT_SECOND_EXTENSION), 0, MFT_PREFIX_CLUSTERS * 2)]
    if damage == 'duplicate':
        entries.insert(1, entries[0])
    elif damage == 'missing-prefix':
        entries.pop(0)
    elif damage == 'incomplete':
        entries.pop()
    value = b''.join(entries)
    if nonresident_list:
        changed[MFT_LIST_LCN * CLUSTER:MFT_LIST_LCN * CLUSTER + len(value)] = value
        attribute_list = nonresident(ATTR_LIST, [(1, MFT_LIST_LCN)], len(value), MFT_LIST_INSTANCE)
    else:
        attribute_list = resident(ATTR_LIST, value, MFT_LIST_INSTANCE)
    records = {
        MFT_RECORD: file_record(MFT_RECORD, [standard(), attribute_list,
            nonresident(DATA, [(MFT_PREFIX_CLUSTERS, MFT_LCN)], mft_bytes,
                        MFT_DATA_INSTANCE, allocated=mft_bytes)]),
        MFT_FIRST_EXTENSION: file_record(MFT_FIRST_EXTENSION,
            [nonresident(DATA, [(MFT_PREFIX_CLUSTERS, MFT_SECOND_LCN)], 0,
                         lowest=MFT_PREFIX_CLUSTERS)],
            base=ROOT_REF if damage == 'wrong-base' else base),
        MFT_SECOND_EXTENSION: file_record(MFT_SECOND_EXTENSION,
            [nonresident(DATA, [(mft_clusters - MFT_PREFIX_CLUSTERS * 2, MFT_FINAL_LCN)], 0,
                         lowest=MFT_PREFIX_CLUSTERS * 2)], base=base),
    }
    for number, record in records.items():
        table[number * RECORD:(number + 1) * RECORD] = record
    changed[table_start:table_start + mft_bytes] = bytes(mft_bytes)
    extents = [(0, MFT_PREFIX_CLUSTERS, MFT_LCN),
               (MFT_PREFIX_CLUSTERS, MFT_PREFIX_CLUSTERS, MFT_SECOND_LCN),
               (MFT_PREFIX_CLUSTERS * 2, mft_clusters - MFT_PREFIX_CLUSTERS * 2, MFT_FINAL_LCN)]
    for lowest, count, physical in extents:
        changed[physical * CLUSTER:(physical + count) * CLUSTER] = table[lowest * CLUSTER:(lowest + count) * CLUSTER]
    changed[MIRROR_LCN * CLUSTER:MIRROR_LCN * CLUSTER + RECORD] = records[MFT_RECORD]
    return changed


def put_record(image, number, encoded):
    assert len(encoded) == RECORD
    start = MFT_LCN * CLUSTER + number * RECORD
    image[start:start + RECORD] = encoded


def put_data(image, lcn, data):
    start = lcn * CLUSTER
    assert start + len(data) <= len(image)
    image[start:start + len(data)] = data


def pattern(length):
    return bytes((i * PATTERN_MULTIPLIER + PATTERN_ADDEND) % BYTE_VALUES for i in range(length))


def repeated_chunk(literal):
    payload = bytes([LZNT1_LITERAL_THEN_MATCH, literal])
    payload += struct.pack('<H', LZNT1_CHUNK_BYTES - 1 - LZNT1_MIN_MATCH)
    return struct.pack('<H', LZNT1_SIGNATURE | LZNT1_COMPRESSED | (len(payload) - 1)) + payload


def make_image(legacy=False):
    image = bytearray(IMAGE_SIZE)
    # Named byte locations are the independent fixture's boot-format definition.
    boot = BOOT_FIELDS
    jump = b'\xebR\x90'
    oem = b'NTFS    '
    image[boot['jump']:boot['jump'] + len(jump)] = jump
    image[boot['oem']:boot['oem'] + len(oem)] = oem
    struct.pack_into('<H', image, boot['sector_size'], SECTOR)
    image[boot['cluster_sectors']] = CLUSTER // SECTOR
    image[boot['media']] = BOOT_MEDIA
    struct.pack_into('<QQQ', image, boot['sectors'], IMAGE_SIZE // SECTOR, MFT_LCN, MIRROR_LCN)
    image[boot['record_code']] = -(RECORD.bit_length() - 1) % BYTE_VALUES
    image[boot['index_code']] = -(CLUSTER.bit_length() - 1) % BYTE_VALUES
    struct.pack_into('<Q', image, boot['serial'], BOOT_SERIAL)
    struct.pack_into('<H', image, boot['signature'], BOOT_SIGNATURE)
    contents = {
        'hello.txt': b'Hello from NTFS.\n',
        'fragmented.bin': pattern(FRAGMENTED_BYTES),
        'compressed.bin': b'Z' * COMPRESSION_UNIT_BYTES,
        'extended.bin': b'A' * CLUSTER + b'B' * CLUSTER,
        'middle.dat': b'B-tree separator data',
        'sparse.bin': b'S' * CLUSTER + bytes(2 * CLUSTER) + b'T' * CLUSTER,
        'streamed.txt': b'default stream',
        'tail.bin': b'I' * INITIALIZED_BYTES + bytes(2 * CLUSTER - INITIALIZED_BYTES),
        'Ωmega.txt': 'Unicode data: Ω\n'.encode(),
    }

    def store(number, attrs, **kwargs):
        put_record(image, number, file_record(number, attrs, legacy=legacy, **kwargs))

    store(MFT_RECORD, [standard(), nonresident(DATA, [(MFT_COUNT * RECORD // CLUSTER, MFT_LCN)], MFT_COUNT * RECORD, 1)])
    volume_info = bytes(U64_BYTES) + struct.pack('<BBH', NTFS_MAJOR_VERSION, 0 if legacy else NTFS_MINOR_VERSION, 0)
    store(VOLUME_RECORD, [standard(), resident(VOL_NAME, 'Machlin test'.encode('utf-16le'), 1), resident(VOL_INFO, volume_info, 2)])
    bitmap = bytearray(IMAGE_SIZE // CLUSTER // BYTE_BITS)
    for cluster in range(ALLOCATED_CLUSTERS):
        bitmap[cluster // BYTE_BITS] |= 1 << (cluster % BYTE_BITS)
    store(BITMAP_RECORD, [standard(), resident(DATA, bitmap, 1)])
    upcase = bytearray()
    for unit in range(1 << (U16_BYTES * BYTE_BITS)):
        mapped = unit - ord('a') + ord('A') if ord('a') <= unit <= ord('z') else unit
        upcase += struct.pack('<H', mapped)
    put_data(image, UPCASE_LCN, upcase)
    store(UPCASE_RECORD, [standard(), nonresident(DATA, [(len(upcase) // CLUSTER, UPCASE_LCN)], len(upcase), 1)])
    separator = 'middle.dat'
    left = sorted((n for n in contents if n.upper() < separator.upper()), key=str.upper)
    right = sorted((n for n in contents if n.upper() > separator.upper()), key=str.upper)
    for vcn, names in enumerate((left, right)):
        put_data(image, INDEX_LCN + vcn, index_block(vcn, [entry(n, FILE_RECORDS[n], len(contents[n])) for n in names]))
    root_entries = entry(separator, FILE_RECORDS[separator], len(contents[separator]), child=0) + entry(child=1)
    put_record(image, ROOT_RECORD, directory_record(root_entries, allocation_clusters=2, legacy=legacy))
    for name in ('hello.txt', separator, 'Ωmega.txt'):
        store(FILE_RECORDS[name], [standard(), resident(DATA, contents[name], 1)])
    fragmented = contents['fragmented.bin']
    first, second = DATA_LCNS['fragmented.bin']
    put_data(image, first, fragmented[:CLUSTER])
    put_data(image, second, fragmented[CLUSTER:])
    store(FILE_RECORDS['fragmented.bin'], [standard(), nonresident(DATA, [(1, first), (1, second)], len(fragmented), 1)])
    tail_lcn, = DATA_LCNS['tail.bin']
    put_data(image, tail_lcn, b'I' * len(contents['tail.bin']))
    store(FILE_RECORDS['tail.bin'], [standard(), nonresident(DATA, [(2, tail_lcn)], len(contents['tail.bin']), 1, initialized=INITIALIZED_BYTES)])
    sparse_first, sparse_last = DATA_LCNS['sparse.bin']
    sparse_hole_clusters = 2
    put_data(image, sparse_first, b'S' * CLUSTER)
    put_data(image, sparse_last, b'T' * CLUSTER)
    store(FILE_RECORDS['sparse.bin'], [standard(FILE_ATTRIBUTE_SPARSE), nonresident(DATA, [(1, sparse_first), (sparse_hole_clusters, None), (1, sparse_last)], len(contents['sparse.bin']), 1, flags=SPARSE)])
    compressed_lcn, = DATA_LCNS['compressed.bin']
    compressed = repeated_chunk(ord('Z')) * (COMPRESSION_UNIT_BYTES // LZNT1_CHUNK_BYTES)
    put_data(image, compressed_lcn, compressed)
    store(FILE_RECORDS['compressed.bin'], [standard(FILE_ATTRIBUTE_COMPRESSED), nonresident(DATA, [(1, compressed_lcn), (COMPRESSION_CLUSTERS - 1, None)], len(contents['compressed.bin']), 1, flags=COMPRESSED)])
    store(FILE_RECORDS['streamed.txt'], [standard(), resident(DATA, contents['streamed.txt'], 1), resident(DATA, b'alternate payload', 2, 'notes')])
    extended_first, extended_last = DATA_LCNS['extended.bin']
    put_data(image, extended_first, b'A' * CLUSTER)
    put_data(image, extended_last, b'B' * CLUSTER)
    extended_record = FILE_RECORDS['extended.bin']
    data_instance, list_instance = 3, 2
    attribute_list = list_entry(file_reference(extended_record), data_instance, 0) + list_entry(file_reference(ATTRIBUTE_EXTENSION_RECORD), 0, 1)
    store(extended_record, [standard(), resident(ATTR_LIST, attribute_list, list_instance), nonresident(DATA, [(1, extended_first)], len(contents['extended.bin']), data_instance, allocated=len(contents['extended.bin']))])
    store(ATTRIBUTE_EXTENSION_RECORD, [nonresident(DATA, [(1, extended_last)], 0, lowest=1)], base=file_reference(extended_record))
    put_data(image, MIRROR_LCN, image[MFT_LCN * CLUSTER:MFT_LCN * CLUSTER + RECORD])
    return image, contents, boot


def main():
    global IMAGE_SIZE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('stamp', nargs='?', type=Path)
    parser.add_argument('--image-bytes', type=int, default=IMAGE_SIZE,
                        help='Base data span; complete diagnostics also retain a reserved boot sector')
    args = parser.parse_args()
    if args.image_bytes < ALLOCATED_CLUSTERS * CLUSTER or args.image_bytes % (CLUSTER * BYTE_BITS):
        parser.error('image size must cover reserved clusters and a whole allocation-bitmap byte')
    IMAGE_SIZE = args.image_bytes
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    image, contents, boot = make_image()
    reparse_fixtures(output, image)
    catalog_fixtures(output, image, contents)
    namespace_fixtures(output, image, contents)
    from case_fixtures import author as case_fixtures
    case_fixtures(output, image)
    from stat_fixtures import author as stat_fixtures
    stat_fixtures(output, image)
    from native_link_fixtures import author as native_link_fixtures
    native_link_fixtures(output, image)
    from wof_file_fixtures import author as wof_file_fixtures
    wof_file_fixtures(output, image)
    from validation_fixtures import author as validation_fixtures
    validation_fixtures(output, image)
    from secure_fixtures import author as secure_fixtures
    secure_fixtures(output, image, contents)
    (output / 'standard.img').write_bytes(image)
    legacy_image, _, _ = make_image(legacy=True)
    (output / 'ntfs30.img').write_bytes(legacy_image)
    expected = output / 'expected'
    expected.mkdir(exist_ok=True)
    for name, data in contents.items():
        (expected / name).write_bytes(data)
    manifest = {n: hashlib.sha256(data).hexdigest() for n, data in contents.items()}
    (output / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    corrupt = bytearray(image)
    corrupt[MFT_LCN * CLUSTER + SECTOR - U16_BYTES] ^= 1
    (output / 'torn-mft.img').write_bytes(corrupt)
    corrupt = bytearray(image)
    struct.pack_into('<Q', corrupt, boot['sectors'], 1 << (U64_BYTES * BYTE_BITS - 1))
    (output / 'overflow.img').write_bytes(corrupt)
    corrupt = bytearray(image)
    corrupt[INDEX_LCN * CLUSTER + SECTOR - U16_BYTES] ^= 1
    (output / 'torn-index.img').write_bytes(corrupt)
    (output / 'truncated.img').write_bytes(image[:RECORD])
    cases = []

    def image_case(name, changed, arguments, error=None, expected=None):
        (output / name).write_bytes(changed)
        cases.append({'image': name, 'arguments': arguments, 'error': error,
                      'sha256': hashlib.sha256(expected).hexdigest() if expected is not None else None})

    def variant(name, records, arguments, error=None, expected=None):
        changed = bytearray(image)
        for number, encoded in records.items():
            put_record(changed, number, encoded)
        image_case(name, changed, arguments, error, expected)

    hello = FILE_RECORDS['hello.txt']
    fragmented = FILE_RECORDS['fragmented.bin']
    compressed = FILE_RECORDS['compressed.bin']
    middle = FILE_RECORDS['middle.dat']
    extended = FILE_RECORDS['extended.bin']
    tail = FILE_RECORDS['tail.bin']
    fragmented_runs = [(1, lcn) for lcn in DATA_LCNS['fragmented.bin']]
    extension_lcn = DATA_LCNS['extended.bin'][-1]
    tail_size = len(contents['tail.bin'])
    tail_runs = [(tail_size // CLUSTER, DATA_LCNS['tail.bin'][0])]
    for label, major, flags, error in [('dirty', NTFS_MAJOR_VERSION, VOLUME_DIRTY, 'recovery'),
                                     ('version', NTFS_MAJOR_VERSION + 1, 0, 'unsupported')]:
        info = bytes(U64_BYTES) + struct.pack('<BBH', major, NTFS_MINOR_VERSION, flags)
        variant(label + '.img', {VOLUME_RECORD: file_record(VOLUME_RECORD, [standard(), resident(VOL_INFO, info, 1)])}, ['info'], error)
    variant('stale.img', {hello: file_record(hello, [standard(), resident(DATA, contents['hello.txt'], 1)], sequence=FILE_SEQUENCE + 1)}, ['cat', '/hello.txt'], 'stale')
    variant('bad-extension.img', {ATTRIBUTE_EXTENSION_RECORD: file_record(ATTRIBUTE_EXTENSION_RECORD, [nonresident(DATA, [(1, extension_lcn)], 0, lowest=1)], base=file_reference(middle))}, ['cat', '/extended.bin'], 'stale')
    # Continuation instance is intentionally different from the list's zero:
    # lowest VCN selects continuation attributes; instance selects the base.
    variant('extent-instance.img', {ATTRIBUTE_EXTENSION_RECORD: file_record(ATTRIBUTE_EXTENSION_RECORD, [nonresident(DATA, [(1, extension_lcn)], 0, instance=1, lowest=1)], base=file_reference(extended))}, ['cat', '/extended.bin'], expected=contents['extended.bin'])
    variant('negative-lcn.img', {fragmented: file_record(fragmented, [standard(), nonresident(DATA, [(len(fragmented_runs), -1)], FRAGMENTED_BYTES, 1)])}, ['cat', '/fragmented.bin'], 'corrupt')
    variant('bad-vdl.img', {tail: file_record(tail, [standard(), nonresident(DATA, tail_runs, tail_size, 1, initialized=tail_size + 1)])}, ['cat', '/tail.bin'], 'corrupt')
    variant('compressed-tail.img', {fragmented: file_record(fragmented, [standard(), nonresident(DATA, fragmented_runs, FRAGMENTED_BYTES, 1, flags=COMPRESSED)])}, ['cat', '/fragmented.bin'], expected=contents['fragmented.bin'])
    encrypted_default = nonresident(DATA, fragmented_runs, FRAGMENTED_BYTES, 1, flags=ENCRYPTED)
    variant('encrypted.img', {hello: file_record(hello, [standard(FILE_ATTRIBUTE_ENCRYPTED), encrypted_default])}, ['cat', '/hello.txt'], 'unsupported')
    payload = b'independent stream payload'
    variant('independent-ads.img', {hello: file_record(hello, [standard(FILE_ATTRIBUTE_ENCRYPTED), encrypted_default, resident(DATA, payload, 2, 'notes')])}, ['cat', '/hello.txt', 'notes'], expected=payload)
    variant('directory-ads.img', {ROOT_RECORD: directory_record(entry(), data_streams=[resident(DATA, payload, DIR_BITMAP_INSTANCE + 1, 'notes')])}, ['cat', '/', 'notes'], expected=payload)
    variant('reparse.img', {hello: file_record(hello, [standard(FILE_ATTRIBUTE_REPARSE), resident(DATA, contents['hello.txt'], 1)])}, ['cat', '/hello.txt'], 'corrupt')
    variant('empty-stream.img', {hello: file_record(hello, [standard(), resident(DATA, b'', 1)])}, ['cat', '/hello.txt'], expected=b'')
    variant('empty-nonresident.img', {hello: file_record(hello, [standard(), nonresident(DATA, [], 0, 1)])}, ['cat', '/hello.txt'], expected=b'')
    large_sparse = bytearray(image)
    put_record(large_sparse, fragmented, file_record(fragmented, [standard(FILE_ATTRIBUTE_SPARSE), nonresident(DATA, [(LARGE_SPARSE_BYTES // CLUSTER, None)], LARGE_SPARSE_BYTES, 1, flags=SPARSE)]))
    (output / 'large-sparse.img').write_bytes(large_sparse)

    # A fragmented compressed prefix, raw unit, hole unit and partial final unit.
    mixed = bytearray(image)
    compressed_prefix = struct.pack('<H', LZNT1_SIGNATURE | (LZNT1_CHUNK_BYTES - 1)) + pattern(LZNT1_CHUNK_BYTES)
    compressed_prefix += repeated_chunk(ord('Z')) * (COMPRESSION_UNIT_BYTES // LZNT1_CHUNK_BYTES - 1)
    prefix_clusters = (len(compressed_prefix) + CLUSTER - 1) // CLUSTER
    assert prefix_clusters == 2
    prefix_lcn = DATA_LCNS['compressed.bin'][0]
    put_data(mixed, prefix_lcn, compressed_prefix[:CLUSTER])
    put_data(mixed, MIXED_PREFIX_SECOND_LCN, compressed_prefix[CLUSTER:])
    put_data(mixed, MIXED_RAW_LCN, pattern(COMPRESSION_UNIT_BYTES))
    put_data(mixed, MIXED_FINAL_LCN, pattern(FRAGMENTED_BYTES))
    mixed_contents = pattern(LZNT1_CHUNK_BYTES) + b'Z' * (COMPRESSION_UNIT_BYTES - LZNT1_CHUNK_BYTES)
    mixed_contents += pattern(COMPRESSION_UNIT_BYTES) + bytes(COMPRESSION_UNIT_BYTES) + pattern(FRAGMENTED_BYTES)
    final_clusters = (FRAGMENTED_BYTES + CLUSTER - 1) // CLUSTER
    mixed_runs = [(1, prefix_lcn), (1, MIXED_PREFIX_SECOND_LCN), (COMPRESSION_CLUSTERS - prefix_clusters, None),
                  (COMPRESSION_CLUSTERS, MIXED_RAW_LCN), (COMPRESSION_CLUSTERS, None), (final_clusters, MIXED_FINAL_LCN)]
    put_record(mixed, compressed, file_record(compressed, [standard(FILE_ATTRIBUTE_COMPRESSED), nonresident(DATA, mixed_runs, len(mixed_contents), 1, flags=COMPRESSED)]))
    image_case('mixed-compression.img', mixed, ['cat', '/compressed.bin'], expected=mixed_contents)
    (expected / 'mixed-compression.bin').write_bytes(mixed_contents)

    repeated = entry('middle.dat', middle, len(contents['middle.dat']), 0) + entry(child=0)
    variant('repeated-index.img', {ROOT_RECORD: directory_record(repeated, allocation_clusters=2)}, ['ls'], 'corrupt')
    for label, vcn, bad_name, query in [('upper', 0, 'z-outside.txt', '/hello.txt'), ('lower', 1, 'a-outside.txt', '/tail.bin')]:
        changed = bytearray(image)
        put_data(changed, INDEX_LCN + vcn, index_block(vcn, [entry(bad_name, hello)]))
        image_case(f'index-{label}-bound.img', changed, ['ls'], 'corrupt')
        image_case(f'lookup-{label}-bound.img', changed, ['cat', query], 'corrupt')

    nested = bytearray(image)
    root_entries = entry('middle.dat', middle, len(contents['middle.dat']), 0) + entry(child=1)
    root_record = directory_record(root_entries, allocation_clusters=4)
    put_record(nested, ROOT_RECORD, root_record)
    blocks = {
        0: index_block(0, [entry('extended.bin', extended, len(contents['extended.bin']), 2)], terminal_child=3),
        2: index_block(2, [entry('compressed.bin', compressed, len(contents['compressed.bin']))]),
        3: index_block(3, [entry('fragmented.bin', fragmented, len(contents['fragmented.bin'])), entry('hello.txt', hello, len(contents['hello.txt']))]),
    }
    for vcn, block in blocks.items():
        put_data(nested, INDEX_LCN + vcn, block)
    (output / 'nested-index.img').write_bytes(nested)
    last_grandchild = 3
    put_data(nested, INDEX_LCN + last_grandchild, index_block(last_grandchild, [entry('z-ancestor-escape.txt', hello)]))
    image_case('index-ancestor-bound.img', nested, ['ls'], 'corrupt')

    duplicate = entry('hello.txt', hello) + entry('hello.txt', hello) + entry()
    variant('index-duplicate-name.img', {ROOT_RECORD: directory_record(duplicate)}, ['ls'], 'corrupt')
    collision = entry('HELLO.TXT', fragmented, namespace=NAMESPACE_POSIX) + entry('hello.txt', hello, namespace=NAMESPACE_POSIX) + entry()
    variant('index-case-collision.img', {ROOT_RECORD: directory_record(collision)}, ['cat', '/hello.txt'], 'unsupported')
    split = bytearray(image)
    split_root = directory_record(entry('hello.txt', hello, child=0, namespace=NAMESPACE_POSIX) + entry(child=1), allocation_clusters=2)
    put_record(split, ROOT_RECORD, split_root)
    put_data(split, INDEX_LCN, index_block(0, [entry('HELLO.TXT', fragmented, namespace=NAMESPACE_POSIX)]))
    put_data(split, INDEX_LCN + 1, index_block(1, []))
    image_case('index-split-case-collision.img', split, ['cat', '/HELLO.TXT'], 'unsupported')
    for nonresident_list in (False, True):
        name = 'mft-nonresident-list.img' if nonresident_list else 'mft-resident-list.img'
        (output / name).write_bytes(fragmented_mft(image, nonresident_list))
    metadata = bytearray(image)
    metadata_list = list_entry(ROOT_REF, 0, 0, kind=SI)
    metadata_list += list_entry(ROOT_REF, DIR_ROOT_INSTANCE, 0, kind=INDEX_ROOT, name='$I30')
    put_data(metadata, MFT_LIST_LCN, metadata_list)
    put_record(metadata, ROOT_RECORD, directory_record(entry(), data_streams=[
        nonresident(ATTR_LIST, [(1, MFT_LIST_LCN)], len(metadata_list), DIR_BITMAP_INSTANCE + 1)]))
    (output / 'metadata-presence-list.img').write_bytes(metadata)
    for damage in ('stale', 'wrong-base', 'unreachable', 'gap', 'duplicate', 'missing-prefix', 'incomplete'):
        name = f'mft-{damage}.img'
        (output / name).write_bytes(fragmented_mft(image, damage=damage))
        cases.append({'image': name, 'arguments': ['info'],
                      'error': 'stale' if damage in ('stale', 'wrong-base') else 'corrupt'})
    (output / 'cases.json').write_text(json.dumps(cases, indent=2) + '\n')
    if args.stamp:
        args.stamp.write_text('generated\n')


if __name__ == '__main__':
    # Imported authors must observe the same geometry as the CLI entry point.
    import fixtures as fixture_module
    fixture_module.main()
