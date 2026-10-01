#!/usr/bin/env python3
"""Author small NTFS parser fixtures independently of the C implementation.

These are intentionally not Windows-format acceptance: system files omitted from
these focused images are supplied by the separate mkntfs interoperability suite.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

SECTOR = 512
CLUSTER = 4096
RECORD = 1024
IMAGE_SIZE = 8 * 1024 * 1024
MFT_LCN = 4
MIRROR_LCN = 32
UPCASE_LCN = 64
INDEX_LCN = 100
MFT_COUNT = 64
ROOT_REF = (1 << 48) | 5
SI, ATTR_LIST, VOL_NAME, VOL_INFO = 0x10, 0x20, 0x60, 0x70
DATA, INDEX_ROOT, INDEX_ALLOC, BITMAP = 0x80, 0x90, 0xA0, 0xB0
ATTR_END = 0xFFFFFFFF
SPARSE, COMPRESSED = 0x8000, 1
CHILD, END = 1, 2
ATTR_HEADER = struct.Struct('<IIBBHHH')
RESIDENT_HEADER = struct.Struct('<IHBB')
NONRESIDENT_HEADER = struct.Struct('<QQHHIQQQ')
FILE_HEADER = struct.Struct('<4sHHQHHHHIIQHHI')
INDEX_HEADER = struct.Struct('<IIIB3x')
INDEX_ENTRY = struct.Struct('<QHHH2x')
FILENAME_HEADER = struct.Struct('<QQQQQQQIIBB')
ATTR_LIST_ENTRY = struct.Struct('<IHBBQQH')
EPOCH = 116444736000000000


def align(n):
    return (n + 7) & ~7


def resident(kind, value, instance=0, name=''):
    name_bytes = name.encode('utf-16le')
    value_offset = align(ATTR_HEADER.size + RESIDENT_HEADER.size + len(name_bytes))
    length = align(value_offset + len(value))
    out = bytearray(length)
    ATTR_HEADER.pack_into(out, 0, kind, length, 0, len(name_bytes) // 2, ATTR_HEADER.size + RESIDENT_HEADER.size, 0, instance)
    RESIDENT_HEADER.pack_into(out, ATTR_HEADER.size, len(value), value_offset, 0, 0)
    out[ATTR_HEADER.size + RESIDENT_HEADER.size:ATTR_HEADER.size + RESIDENT_HEADER.size + len(name_bytes)] = name_bytes
    out[value_offset:value_offset + len(value)] = value
    return bytes(out)


def integer_bytes(value, signed=False):
    for width in range(1, 9):
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
        pairs += bytes([len(count_bytes) | len(delta) << 4]) + count_bytes + delta
        if lcn is not None:
            last_lcn = lcn
    pairs += b'\0'
    name_bytes = name.encode('utf-16le')
    header_size = ATTR_HEADER.size + NONRESIDENT_HEADER.size + (8 if flags else 0)
    mapping_offset = align(header_size + len(name_bytes))
    length = align(mapping_offset + len(pairs))
    out = bytearray(length)
    count = sum(n for n, _ in runs)
    if allocated is None:
        allocated = count * CLUSTER
    ATTR_HEADER.pack_into(out, 0, kind, length, 1, len(name_bytes) // 2, header_size, flags, instance)
    NONRESIDENT_HEADER.pack_into(out, ATTR_HEADER.size, lowest, lowest + count - 1, mapping_offset, 4 if flags & COMPRESSED else 0, 0, allocated, size, size if initialized is None else initialized)
    if flags:
        struct.pack_into('<Q', out, ATTR_HEADER.size + NONRESIDENT_HEADER.size, sum(n for n, lcn in runs if lcn is not None) * CLUSTER)
    out[header_size:header_size + len(name_bytes)] = name_bytes
    out[mapping_offset:mapping_offset + len(pairs)] = pairs
    return bytes(out)


def protect(out, usa_offset):
    signature = 0xA55A
    struct.pack_into('<H', out, usa_offset, signature)
    for sector in range(1, len(out) // SECTOR + 1):
        tail = sector * SECTOR - 2
        out[usa_offset + sector * 2:usa_offset + sector * 2 + 2] = out[tail:tail + 2]
        struct.pack_into('<H', out, tail, signature)


def file_record(number, attrs, directory=False, sequence=None, base=0):
    sequence = sequence if sequence is not None else (1 if number < 16 else 7)
    usa_offset = FILE_HEADER.size
    usa_count = RECORD // SECTOR + 1
    attrs_offset = align(usa_offset + usa_count * 2)
    content = b''.join(attrs) + struct.pack('<II', ATTR_END, 0)
    used = attrs_offset + len(content)
    assert used <= RECORD, (number, used)
    out = bytearray(RECORD)
    FILE_HEADER.pack_into(out, 0, b'FILE', usa_offset, usa_count, 0, sequence, 1, attrs_offset, 3 if directory else 1, used, RECORD, base, len(attrs), 0, number)
    out[attrs_offset:used] = content
    protect(out, usa_offset)
    return bytes(out)


def standard(attributes=0):
    return resident(SI, struct.pack('<QQQQIIIIIIQQ', EPOCH, EPOCH + 123456789, EPOCH, EPOCH, attributes, 0, 0, 0, 0, 256, 0, 0))


def key(name, size=0):
    raw = name.encode('utf-16le')
    return FILENAME_HEADER.pack(ROOT_REF, EPOCH, EPOCH, EPOCH, EPOCH, align(size), size, 0, 0, len(raw) // 2, 1) + raw


def entry(name=None, number=0, size=0, child=None):
    value = b'' if name is None else key(name, size)
    flags = (END if name is None else 0) | (CHILD if child is not None else 0)
    length = align(INDEX_ENTRY.size + len(value)) + (8 if child is not None else 0)
    out = bytearray(length)
    INDEX_ENTRY.pack_into(out, 0, (7 << 48) | number if name is not None else 0, length, len(value), flags)
    out[INDEX_ENTRY.size:INDEX_ENTRY.size + len(value)] = value
    if child is not None:
        struct.pack_into('<Q', out, length - 8, child)
    return bytes(out)


def index_block(vcn, entries):
    out = bytearray(CLUSTER)
    header_offset = struct.calcsize('<4sHHQQ')
    usa_offset = header_offset + INDEX_HEADER.size
    usa_count = CLUSTER // SECTOR + 1
    first = align(usa_offset + usa_count * 2)
    content = b''.join(entries) + entry()
    struct.pack_into('<4sHHQQ', out, 0, b'INDX', usa_offset, usa_count, 0, vcn)
    INDEX_HEADER.pack_into(out, header_offset, first - header_offset, first + len(content) - header_offset, CLUSTER - header_offset, 0)
    out[first:first + len(content)] = content
    protect(out, usa_offset)
    return out


def list_entry(reference, instance, lowest):
    out = bytearray(align(ATTR_LIST_ENTRY.size))
    ATTR_LIST_ENTRY.pack_into(out, 0, DATA, len(out), 0, 0, lowest, reference, instance)
    return bytes(out)


def make_image():
    image = bytearray(IMAGE_SIZE)
    # Byte locations are named boot fields, separate from C wire definitions.
    boot = {'jump': 0, 'oem': 3, 'sector_size': 11, 'cluster_sectors': 13,
            'media': 21, 'sectors': 40, 'mft': 48, 'mirror': 56,
            'record_code': 64, 'index_code': 68, 'serial': 72, 'signature': 510}
    image[boot['jump']:boot['jump'] + 3] = b'\xebR\x90'
    image[boot['oem']:boot['oem'] + 8] = b'NTFS    '
    struct.pack_into('<H', image, boot['sector_size'], SECTOR)
    image[boot['cluster_sectors']] = CLUSTER // SECTOR
    image[boot['media']] = 0xF8
    struct.pack_into('<QQQ', image, boot['sectors'], IMAGE_SIZE // SECTOR, MFT_LCN, MIRROR_LCN)
    image[boot['record_code']] = 256 - 10
    image[boot['index_code']] = 256 - 12
    struct.pack_into('<Q', image, boot['serial'], 0x0123456789ABCDEF)
    struct.pack_into('<H', image, boot['signature'], 0xAA55)
    contents = {
        'hello.txt': b'Hello from NTFS.\n',
        'fragmented.bin': bytes((i * 13 + 7) % 256 for i in range(6000)),
        'compressed.bin': b'Z' * 65536,
        'extended.bin': b'A' * CLUSTER + b'B' * CLUSTER,
        'middle.dat': b'B-tree separator data',
        'sparse.bin': b'S' * CLUSTER + bytes(2 * CLUSTER) + b'T' * CLUSTER,
        'streamed.txt': b'default stream',
        'tail.bin': b'I' * 100 + bytes(2 * CLUSTER - 100),
        'Ωmega.txt': 'Unicode data: Ω\n'.encode(),
    }
    numbers = {'hello.txt': 24, 'fragmented.bin': 25, 'compressed.bin': 26,
               'extended.bin': 27, 'middle.dat': 28, 'sparse.bin': 29,
               'streamed.txt': 30, 'tail.bin': 31, 'Ωmega.txt': 32}

    def store_record(number, attrs, **kwargs):
        start = MFT_LCN * CLUSTER + number * RECORD
        image[start:start + RECORD] = file_record(number, attrs, **kwargs)

    store_record(0, [standard(), nonresident(DATA, [(MFT_COUNT * RECORD // CLUSTER, MFT_LCN)], MFT_COUNT * RECORD, 1)])
    store_record(3, [standard(), resident(VOL_NAME, 'Machlin test'.encode('utf-16le'), 1), resident(VOL_INFO, bytes(8) + bytes([3, 1, 0, 0]), 2)])
    bitmap = bytearray(IMAGE_SIZE // CLUSTER // 8)
    for cluster in range(160):
        bitmap[cluster // 8] |= 1 << (cluster % 8)
    store_record(6, [standard(), resident(DATA, bitmap, 1)])
    upcase = bytearray()
    for unit in range(65536):
        mapped = unit - 32 if ord('a') <= unit <= ord('z') else unit
        upcase += struct.pack('<H', mapped)
    image[UPCASE_LCN * CLUSTER:UPCASE_LCN * CLUSTER + len(upcase)] = upcase
    store_record(10, [standard(), nonresident(DATA, [(len(upcase) // CLUSTER, UPCASE_LCN)], len(upcase), 1)])
    left = sorted(n for n in contents if n.upper() < 'MIDDLE.DAT')
    right = sorted((n for n in contents if n.upper() > 'MIDDLE.DAT'), key=str.upper)
    for vcn, names in enumerate((left, right)):
        image[(INDEX_LCN + vcn) * CLUSTER:(INDEX_LCN + vcn + 1) * CLUSTER] = index_block(vcn, [entry(n, numbers[n], len(contents[n])) for n in names])
    root_entries = entry('middle.dat', 28, len(contents['middle.dat']), 0) + entry(child=1)
    root = struct.pack('<IIIB3x', 0x30, 1, CLUSTER, 1) + INDEX_HEADER.pack(INDEX_HEADER.size, INDEX_HEADER.size + len(root_entries), INDEX_HEADER.size + len(root_entries), 1) + root_entries
    store_record(5, [standard(0x10000000), resident(INDEX_ROOT, root, 1, '$I30'), nonresident(INDEX_ALLOC, [(2, INDEX_LCN)], 2 * CLUSTER, 2, '$I30'), resident(BITMAP, b'\x03', 3, '$I30')], directory=True)
    for name in ('hello.txt', 'middle.dat', 'Ωmega.txt'):
        store_record(numbers[name], [standard(), resident(DATA, contents[name], 1)])
    fragmented = contents['fragmented.bin']
    image[128 * CLUSTER:129 * CLUSTER] = fragmented[:CLUSTER]
    image[130 * CLUSTER:130 * CLUSTER + len(fragmented[CLUSTER:])] = fragmented[CLUSTER:]
    store_record(25, [standard(), nonresident(DATA, [(1, 128), (1, 130)], len(fragmented), 1)])
    image[132 * CLUSTER:134 * CLUSTER] = b'I' * (2 * CLUSTER)
    store_record(31, [standard(), nonresident(DATA, [(2, 132)], 2 * CLUSTER, 1, initialized=100)])
    image[136 * CLUSTER:137 * CLUSTER] = b'S' * CLUSTER
    image[138 * CLUSTER:139 * CLUSTER] = b'T' * CLUSTER
    store_record(29, [standard(0x200), nonresident(DATA, [(1, 136), (2, None), (1, 138)], 4 * CLUSTER, 1, flags=SPARSE)])
    compressed = (struct.pack('<H', 0xB003) + bytes([2, ord('Z')]) + struct.pack('<H', 4096 - 4)) * 16
    image[140 * CLUSTER:140 * CLUSTER + len(compressed)] = compressed
    store_record(26, [standard(0x800), nonresident(DATA, [(1, 140), (15, None)], 65536, 1, flags=COMPRESSED)])
    store_record(30, [standard(), resident(DATA, contents['streamed.txt'], 1), resident(DATA, b'alternate payload', 2, 'notes')])
    image[144 * CLUSTER:145 * CLUSTER] = b'A' * CLUSTER
    image[148 * CLUSTER:149 * CLUSTER] = b'B' * CLUSTER
    attribute_list = list_entry((7 << 48) | 27, 3, 0) + list_entry((7 << 48) | 40, 0, 1)
    store_record(27, [standard(), resident(ATTR_LIST, attribute_list, 2), nonresident(DATA, [(1, 144)], 8192, 3, allocated=8192)])
    store_record(40, [nonresident(DATA, [(1, 148)], 0, lowest=1)], base=(7 << 48) | 27)
    image[MIRROR_LCN * CLUSTER:MIRROR_LCN * CLUSTER + RECORD] = image[MFT_LCN * CLUSTER:MFT_LCN * CLUSTER + RECORD]
    return image, contents, boot


def main():
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    image, contents, boot = make_image()
    (output / 'standard.img').write_bytes(image)
    expected = output / 'expected'
    expected.mkdir(exist_ok=True)
    for name, data in contents.items():
        (expected / name).write_bytes(data)
    manifest = {n: hashlib.sha256(data).hexdigest() for n, data in contents.items()}
    (output / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    corrupt = bytearray(image)
    corrupt[MFT_LCN * CLUSTER + SECTOR - 2] ^= 1
    (output / 'torn-mft.img').write_bytes(corrupt)
    corrupt = bytearray(image)
    struct.pack_into('<Q', corrupt, boot['sectors'], (1 << 63))
    (output / 'overflow.img').write_bytes(corrupt)
    corrupt = bytearray(image)
    corrupt[INDEX_LCN * CLUSTER + SECTOR - 2] ^= 1
    (output / 'torn-index.img').write_bytes(corrupt)
    (output / 'truncated.img').write_bytes(image[:1024])
    cases = []

    def variant(name, records, arguments, error=None, expected=None):
        changed = bytearray(image)
        for number, encoded in records.items():
            start = MFT_LCN * CLUSTER + number * RECORD
            changed[start:start + RECORD] = encoded
        (output / name).write_bytes(changed)
        cases.append({'image': name, 'arguments': arguments, 'error': error,
                      'sha256': hashlib.sha256(expected).hexdigest() if expected is not None else None})

    for label, major, flags, error in [('dirty', 3, 1, 'recovery'), ('version', 4, 0, 'unsupported')]:
        variant(label + '.img', {3: file_record(3, [standard(), resident(VOL_INFO, bytes(8) + struct.pack('<BBH', major, 1, flags), 1)])}, ['info'], error)
    variant('stale.img', {24: file_record(24, [standard(), resident(DATA, contents['hello.txt'], 1)], sequence=8)}, ['cat', '/hello.txt'], 'stale')
    variant('bad-extension.img', {40: file_record(40, [nonresident(DATA, [(1, 148)], 0, lowest=1)], base=(7 << 48) | 28)}, ['cat', '/extended.bin'], 'stale')
    # Continuation instance is intentionally different from the list's zero:
    # lowest VCN selects continuation attributes; instance selects the base.
    variant('extent-instance.img', {40: file_record(40, [nonresident(DATA, [(1, 148)], 0, instance=9, lowest=1)], base=(7 << 48) | 27)}, ['cat', '/extended.bin'], expected=contents['extended.bin'])
    variant('negative-lcn.img', {25: file_record(25, [standard(), nonresident(DATA, [(2, -1)], 6000, 1)])}, ['cat', '/fragmented.bin'], 'corrupt')
    variant('bad-vdl.img', {31: file_record(31, [standard(), nonresident(DATA, [(2, 132)], 8192, 1, initialized=8193)])}, ['cat', '/tail.bin'], 'corrupt')
    variant('compressed-tail.img', {25: file_record(25, [standard(), nonresident(DATA, [(1, 128), (1, 130)], 6000, 1, flags=COMPRESSED)])}, ['cat', '/fragmented.bin'], expected=contents['fragmented.bin'])
    variant('encrypted.img', {24: file_record(24, [standard(0x4000), nonresident(DATA, [(1, 128)], 16, 1, flags=0x4000)])}, ['cat', '/hello.txt'], 'unsupported')
    variant('reparse.img', {24: file_record(24, [standard(0x400), resident(DATA, contents['hello.txt'], 1)])}, ['cat', '/hello.txt'], 'unsupported')
    variant('empty-stream.img', {24: file_record(24, [standard(), resident(DATA, b'', 1)])}, ['cat', '/hello.txt'], expected=b'')
    repeated = entry('middle.dat', 28, len(contents['middle.dat']), 0) + entry(child=0)
    root = struct.pack('<IIIB3x', 0x30, 1, CLUSTER, 1) + INDEX_HEADER.pack(INDEX_HEADER.size, INDEX_HEADER.size + len(repeated), INDEX_HEADER.size + len(repeated), 1) + repeated
    root_record = file_record(5, [standard(), resident(INDEX_ROOT, root, 1, '$I30'), nonresident(INDEX_ALLOC, [(2, INDEX_LCN)], 2 * CLUSTER, 2, '$I30'), resident(BITMAP, b'\x03', 3, '$I30')], directory=True)
    variant('repeated-index.img', {5: root_record}, ['ls'], 'corrupt')
    (output / 'cases.json').write_text(json.dumps(cases, indent=2) + '\n')
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('generated\n')


if __name__ == '__main__':
    main()
