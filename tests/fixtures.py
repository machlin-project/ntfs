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
U64_BYTES = struct.calcsize('<Q')
U64_MAX = (1 << (U64_BYTES * BYTE_BITS)) - 1
FIXUP_SEQUENCE = 0xA55A
BOOT_SIGNATURE = 0xAA55
BOOT_SERIAL = 0x0123456789ABCDEF
BOOT_MEDIA = 0xF8
NTFS_MAJOR_VERSION, NTFS_MINOR_VERSION = 3, 1
VOLUME_DIRTY = 1
FILE_IN_USE, FILE_IS_DIRECTORY = 1, 2
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
ATTR_END = 0xFFFFFFFF
SPARSE, COMPRESSED = 0x8000, 1
ENCRYPTED = 0x4000
CHILD, END = 1, 2
INDEX_LARGE = 1
COLLATION_FILENAME = 1
NAMESPACE_POSIX = 0
NAMESPACE_WIN32 = 1
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
EPOCH = 116444736000000000


def align(n):
    return (n + WIRE_ALIGNMENT - 1) & ~(WIRE_ALIGNMENT - 1)


def resident(kind, value, instance=0, name=''):
    name_bytes = name.encode('utf-16le')
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
    name_bytes = name.encode('utf-16le')
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


def file_record(number, attrs, directory=False, sequence=None, base=0, legacy=False):
    sequence = sequence if sequence is not None else (SYSTEM_SEQUENCE if number < SYSTEM_RECORD_LIMIT else FILE_SEQUENCE)
    header = FILE_HEADER_LEGACY if legacy else FILE_HEADER
    usa_offset = header.size
    usa_count = RECORD // SECTOR + 1
    attrs_offset = align(usa_offset + usa_count * U16_BYTES)
    content = b''.join(attrs) + struct.pack('<II', ATTR_END, 0)
    used = attrs_offset + len(content)
    assert used <= RECORD, (number, used)
    out = bytearray(RECORD)
    fields = (b'FILE', usa_offset, usa_count, 0, sequence, 1, attrs_offset,
              FILE_IN_USE | (FILE_IS_DIRECTORY if directory else 0), used, RECORD, base, len(attrs))
    header.pack_into(out, 0, *fields, *(() if legacy else (0, number)))
    out[attrs_offset:used] = content
    protect(out, usa_offset)
    return bytes(out)


def standard(attributes=0):
    return resident(SI, STANDARD_INFO.pack(EPOCH, EPOCH + TIMESTAMP_OFFSET_TICKS, EPOCH, EPOCH, attributes, 0, 0, 0, 0, SECURITY_ID, 0, 0))


def key(name, size=0, namespace=NAMESPACE_WIN32):
    raw = name.encode('utf-16le')
    return FILENAME_HEADER.pack(ROOT_REF, EPOCH, EPOCH, EPOCH, EPOCH, align(size), size, 0, 0, len(raw) // U16_BYTES, namespace) + raw


def entry(name=None, number=0, size=0, child=None, namespace=NAMESPACE_WIN32):
    value = b'' if name is None else key(name, size, namespace)
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


def directory_record(entries, allocation_clusters=0, data_streams=(), legacy=False):
    root = INDEX_ROOT_HEADER.pack(FILENAME, COLLATION_FILENAME, CLUSTER, 1)
    root += INDEX_HEADER.pack(INDEX_HEADER.size, INDEX_HEADER.size + len(entries),
                              INDEX_HEADER.size + len(entries), INDEX_LARGE if allocation_clusters else 0)
    root += entries
    attrs = [standard(FILE_ATTRIBUTE_DIRECTORY), *data_streams, resident(INDEX_ROOT, root, DIR_ROOT_INSTANCE, '$I30')]
    if allocation_clusters:
        bitmap = ((1 << allocation_clusters) - 1).to_bytes((allocation_clusters + BYTE_BITS - 1) // BYTE_BITS, 'little')
        attrs += [nonresident(INDEX_ALLOC, [(allocation_clusters, INDEX_LCN)],
                              allocation_clusters * CLUSTER, DIR_ALLOCATION_INSTANCE, '$I30'),
                  resident(BITMAP, bitmap, DIR_BITMAP_INSTANCE, '$I30')]
    return file_record(ROOT_RECORD, attrs, directory=True, legacy=legacy)


def list_entry(reference, instance, lowest):
    out = bytearray(align(ATTR_LIST_ENTRY.size))
    ATTR_LIST_ENTRY.pack_into(out, 0, DATA, len(out), 0, 0, lowest, reference, instance)
    return bytes(out)


def file_reference(number, sequence=None):
    if sequence is None:
        sequence = SYSTEM_SEQUENCE if number < SYSTEM_RECORD_LIMIT else FILE_SEQUENCE
    return (sequence << REFERENCE_SEQUENCE_SHIFT) | number


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
    boot = {'jump': 0, 'oem': 3, 'sector_size': 11, 'cluster_sectors': 13,
            'media': 21, 'sectors': 40, 'mft': 48, 'mirror': 56,
            'record_code': 64, 'index_code': 68, 'serial': 72, 'signature': 510}
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
                        help='Physical image size; payload placement and logical stream sizes stay fixed')
    args = parser.parse_args()
    if args.image_bytes < ALLOCATED_CLUSTERS * CLUSTER or args.image_bytes % (CLUSTER * BYTE_BITS):
        parser.error('image size must cover reserved clusters and a whole allocation-bitmap byte')
    IMAGE_SIZE = args.image_bytes
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    image, contents, boot = make_image()
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
    variant('reparse.img', {hello: file_record(hello, [standard(FILE_ATTRIBUTE_REPARSE), resident(DATA, contents['hello.txt'], 1)])}, ['cat', '/hello.txt'], 'unsupported')
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
    for damage in ('stale', 'wrong-base', 'unreachable', 'gap', 'duplicate', 'missing-prefix', 'incomplete'):
        name = f'mft-{damage}.img'
        (output / name).write_bytes(fragmented_mft(image, damage=damage))
        cases.append({'image': name, 'arguments': ['info'],
                      'error': 'stale' if damage in ('stale', 'wrong-base') else 'corrupt'})
    (output / 'cases.json').write_text(json.dumps(cases, indent=2) + '\n')
    if args.stamp:
        args.stamp.write_text('generated\n')


if __name__ == '__main__':
    main()
