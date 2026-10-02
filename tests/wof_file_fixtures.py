"""Author WOF file storage independently of provider/core code."""
import struct
import fixtures as f
import wof_fixtures as x
from stat_fixtures import change_header, change_flags

FILE_RECORD = f.FILE_RECORDS['hello.txt']
BACKING_EXTENSION = f.MFT_COUNT - 1
REPARSE_EXTENSION = f.MFT_COUNT - 2
DATA_INSTANCE, BACKING_INSTANCE, ADS_INSTANCE = 1, 2, 3
REPARSE_INSTANCE, LIST_INSTANCE = 4, 5
BACKING_NAME = 'WofCompressedData'
BACKING_FIRST_LCN, BACKING_SECOND_LCN = 160, 208
REPARSE_LCN, LIST_LCN = 154, 156
TABLE_PAGE_BYTES = 4096
PAGE_SPILL_CHUNKS = 76
PAGE_CHUNKS = TABLE_PAGE_BYTES // struct.calcsize('<I') + PAGE_SPILL_CHUNKS
DEFAULT_CHUNKS = 3
LISTED_CHUNKS = 20
RAW_PATTERN_MULTIPLIER, RAW_PATTERN_ADDEND = 37, 11
FINAL_BYTES = 777
UNKNOWN_FLAG = 0x2000
CHUNK_WORK_BUDGET = 1048576
TOO_MANY_CHUNKS = CHUNK_WORK_BUDGET + 1
ADS_PAYLOAD = b'independent WOF notes'
MANIFEST_HEADER = struct.Struct('<8sIIQ')
MANIFEST_ENTRY = struct.Struct('<IHH')
MANIFEST_VERSION = 1
MANIFEST_RESERVED = 0
MANIFEST_NAMED_COUNT = 2
BACKING_ORDINAL, NOTES_ORDINAL = 1, 2
UNIFORM = {symbol: (symbol, x.UNIFORM_CODE_BITS) for symbol in range(x.SYMBOLS)}
UNIT_8K, UNIT_16K = 8192, 16384
UNITS = {x.WOF_XPRESS_4K: x.UNIT_4K, x.WOF_LZX_32K: x.UNIT_32K,
         x.WOF_XPRESS_8K: UNIT_8K, x.WOF_XPRESS_16K: UNIT_16K}


def contents(algorithm, chunks=DEFAULT_CHUNKS, partial=True, mixed=True):
    unit = UNITS[algorithm]
    originals, packets, offsets = [], [], []
    packed_bytes = 0
    for index in range(chunks):
        size = FINAL_BYTES if partial and index == chunks - 1 else unit
        value = ord('A') + index % len(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        original = bytes([value]) * size
        if mixed and index == 1:
            original = bytes((i * RAW_PATTERN_MULTIPLIER + RAW_PATTERN_ADDEND) % f.BYTE_VALUES for i in range(size))
            packet = original
        elif algorithm == x.WOF_LZX_32K:
            # Valid raw chunk framing; this does not author or qualify LZX codes.
            packet = original
        else:
            packet = x.encode(UNIFORM, [x.literal(value), x.match(1, size - 1)])
            if len(packet) >= size:
                packet = original
        if index:
            offsets.append(packed_bytes)
        originals.append(original)
        packets.append(packet)
        packed_bytes += len(packet)
    original = b''.join(originals)
    width = '<I' if len(original) < (1 << 32) else '<Q'
    table = b''.join(struct.pack(width, offset) for offset in offsets)
    return original, table + b''.join(packets)


def author(output, source):
    cases = []

    def save(label, algorithm=x.WOF_XPRESS_4K, chunks=DEFAULT_CHUNKS, partial=True, mixed=True,
             resident=False, listed=False, reparse_listed=False, nonresident_list=False,
             vdl_zero=True, mutation=None):
        image = bytearray(source)
        original, packed = contents(algorithm, chunks, partial, mixed) if chunks else (b'', b'')
        payload = x.WOF_FILE.pack(x.WOF_VERSION, x.WOF_PROVIDER_FILE, x.WOF_FILE_VERSION, algorithm)
        packet = x.REPARSE.pack(x.WOF_TAG, len(payload), 0) + payload
        if mutation == 'codec':
            value = bytearray(packed)
            table_bytes = (chunks - 1) * struct.calcsize('<I')
            value[table_bytes:table_bytes + x.TABLE_BYTES] = bytes(x.TABLE_BYTES)
            packed = bytes(value)
        elif mutation in ('duplicate', 'descending', 'final-span'):
            value = bytearray(packed)
            first = struct.unpack_from('<I', value)[0]
            offset = first if mutation == 'duplicate' else first - 1
            if mutation == 'final-span':
                offset = len(packed) - (chunks - 1) * struct.calcsize('<I') - FINAL_BYTES - 1
            struct.pack_into('<I', value, struct.calcsize('<I'), offset)
            packed = bytes(value)
        elif mutation == 'out-of-range':
            value = bytearray(packed)
            struct.pack_into('<I', value, 0, (1 << 32) - 1)
            packed = bytes(value)
        count = (len(packed) + f.CLUSTER - 1) // f.CLUSTER
        split = max(1, count // 2) if count else 0
        runs = [(split, BACKING_FIRST_LCN)] if split else []
        if count > split:
            runs.append((count - split, BACKING_SECOND_LCN))
        physical = 0 if resident else count * f.CLUSTER
        placeholder = f.nonresident(f.DATA,
            [((len(original) + f.CLUSTER - 1) // f.CLUSTER, None)] if original else [],
            len(original), DATA_INSTANCE, initialized=0 if vdl_zero else len(original), flags=f.SPARSE)
        backing = (f.resident(f.DATA, packed, BACKING_INSTANCE, BACKING_NAME) if resident else
                   f.nonresident(f.DATA, runs, len(packed), BACKING_INSTANCE, BACKING_NAME))
        if mutation == 'placeholder-resident':
            placeholder = f.resident(f.DATA, b'invented plaintext', DATA_INSTANCE)
        elif mutation == 'placeholder-physical':
            placeholder = f.nonresident(f.DATA, [(1, BACKING_FIRST_LCN)], len(original), DATA_INSTANCE, flags=f.SPARSE)
        elif mutation == 'placeholder-encoding':
            placeholder = change_flags(placeholder, f.SPARSE | f.ENCRYPTED)
        elif mutation == 'backing-vdl':
            backing = change_header(backing, initialized=len(packed) - 1)
        elif mutation == 'backing-flags':
            backing = change_flags(backing, UNKNOWN_FLAG)
        elif mutation == 'backing-efs':
            backing = change_flags(backing, f.ENCRYPTED)
        elif mutation == 'work-limit':
            placeholder = f.nonresident(f.DATA, [(TOO_MANY_CHUNKS, None)],
                TOO_MANY_CHUNKS * x.UNIT_4K, DATA_INSTANCE, flags=f.SPARSE)
        rp = f.resident(f.REPARSE_POINT, packet, REPARSE_INSTANCE)
        if mutation == 'unknown-provider':
            payload = x.WOF_FILE.pack(x.WOF_VERSION, x.WOF_PROVIDER_FILE + 1, x.WOF_FILE_VERSION, algorithm)
            packet = x.REPARSE.pack(x.WOF_TAG, len(payload), 0) + payload
            rp = f.resident(f.REPARSE_POINT, packet, REPARSE_INSTANCE)
        attributes = [f.standard(f.FILE_ATTRIBUTE_REPARSE | f.FILE_ATTRIBUTE_SPARSE), placeholder]
        if mutation == 'cleared-reparse':
            attributes[0] = f.standard(f.FILE_ATTRIBUTE_SPARSE)
        if listed:
            backing = f.nonresident(f.DATA, runs[:1], len(packed), BACKING_INSTANCE,
                BACKING_NAME, allocated=count * f.CLUSTER)
            continuation = f.nonresident(f.DATA, runs[1:], 0, name=BACKING_NAME, lowest=split)
            f.put_record(image, BACKING_EXTENSION, f.file_record(BACKING_EXTENSION, [continuation],
                base=f.file_reference(FILE_RECORD), sequence=f.FILE_SEQUENCE + (mutation == 'stale-extension')))
        if reparse_listed:
            rp = f.nonresident(f.REPARSE_POINT, [(1, REPARSE_LCN)], len(packet), REPARSE_INSTANCE)
            f.put_data(image, REPARSE_LCN, packet)
            f.put_record(image, REPARSE_EXTENSION, f.file_record(REPARSE_EXTENSION, [rp], base=f.file_reference(FILE_RECORD)))
        else:
            attributes.append(rp)
        if mutation != 'missing-backing':
            attributes.append(backing)
        attributes.append(f.resident(f.DATA, ADS_PAYLOAD, ADS_INSTANCE, 'notes'))
        if listed or reparse_listed:
            listing = f.list_entry(f.file_reference(FILE_RECORD), 0, 0, kind=f.SI)
            listing += f.list_entry(f.file_reference(FILE_RECORD), DATA_INSTANCE, 0)
            listing += f.list_entry(f.file_reference(FILE_RECORD), BACKING_INSTANCE, 0, name=BACKING_NAME)
            listing += f.list_entry(f.file_reference(FILE_RECORD), ADS_INSTANCE, 0, name='notes')
            listing += f.list_entry(f.file_reference(REPARSE_EXTENSION if reparse_listed else FILE_RECORD),
                REPARSE_INSTANCE, 0, kind=f.REPARSE_POINT)
            if listed:
                listing += f.list_entry(f.file_reference(BACKING_EXTENSION), 0, split, name=BACKING_NAME)
            listing_attr = (f.nonresident(f.ATTR_LIST, [(1, LIST_LCN)], len(listing), LIST_INSTANCE)
                if nonresident_list else f.resident(f.ATTR_LIST, listing, LIST_INSTANCE))
            attributes.insert(1, listing_attr)
            if nonresident_list:
                f.put_data(image, LIST_LCN, listing)
        f.put_record(image, FILE_RECORD, f.file_record(FILE_RECORD, attributes,
            directory=mutation == 'directory'))
        if not resident:
            position = 0
            for length, lcn in runs:
                span = length * f.CLUSTER
                f.put_data(image, lcn, packed[position:position + span])
                position += span
        bitmap = bytearray((len(image) // f.CLUSTER + f.BYTE_BITS - 1) // f.BYTE_BITS)
        for index in range(f.ALLOCATED_CLUSTERS):
            bitmap[index // f.BYTE_BITS] |= 1 << (index % f.BYTE_BITS)
        for length, lcn in runs:
            for index in range(lcn, lcn + length):
                bitmap[index // f.BYTE_BITS] |= 1 << (index % f.BYTE_BITS)
        f.put_record(image, f.BITMAP_RECORD, f.file_record(f.BITMAP_RECORD, [f.standard(), f.resident(f.DATA, bitmap)]))
        (output / f'wof-file-{label}.img').write_bytes(image)
        (output / f'wof-file-{label}.data').write_bytes(original)
        (output / f'wof-file-{label}.reparse').write_bytes(packet)
        manifest = MANIFEST_HEADER.pack(b'NTFSADS\0', MANIFEST_VERSION,
            MANIFEST_NAMED_COUNT, f.file_reference(FILE_RECORD))
        for ordinal, name in ((BACKING_ORDINAL, BACKING_NAME), (NOTES_ORDINAL, 'notes')):
            manifest += MANIFEST_ENTRY.pack(ordinal, len(name), MANIFEST_RESERVED) + name.encode('utf-16le')
        (output / f'wof-file-{label}.streams').write_bytes(manifest)
        cases.append((label, len(original), physical))

    for label, algorithm in (('4k', x.WOF_XPRESS_4K), ('8k', x.WOF_XPRESS_8K), ('16k', x.WOF_XPRESS_16K)):
        save(label, algorithm)
    save('resident', chunks=1, partial=False, mixed=False, resident=True)
    save('empty', chunks=0, resident=True)
    save('exact', partial=False)
    save('vdl-full', vdl_zero=False)
    save('pages', chunks=PAGE_CHUNKS, mixed=False)
    save('listed', chunks=LISTED_CHUNKS, listed=True, reparse_listed=True)
    save('nonresident-list', chunks=LISTED_CHUNKS, listed=True, nonresident_list=True)
    save('stale', chunks=LISTED_CHUNKS, listed=True, mutation='stale-extension')
    save('lzx', x.WOF_LZX_32K)
    for mutation in ('codec', 'duplicate', 'descending', 'out-of-range', 'final-span',
                     'placeholder-resident', 'placeholder-physical', 'placeholder-encoding',
                     'backing-vdl', 'backing-flags', 'backing-efs', 'missing-backing',
                     'cleared-reparse', 'work-limit', 'unknown-provider', 'directory'):
        save(mutation, mutation=mutation)
    return cases
