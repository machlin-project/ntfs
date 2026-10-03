"""Author independent NTFS endpoints for rename plus resident-to-extent publication.

The transaction model is not imported. Complete FILE/INDX records are authored
with a new USA sequence before their sector snapshots are supplied to the model.
"""
from dataclasses import dataclass
import fixtures as f
import validation_fixtures as v

OLD_NAME = 'hello.txt'
NEW_NAME = 'renamed.txt'
OLD_DATA = v.HELLO_DATA
NEW_DATA = b'recovered nonresident contents\n'
NEW_DATA_LCN = v.ORPHAN_LCN
NEW_FIXUP_SEQUENCE = f.FIXUP_SEQUENCE + 1


@dataclass(frozen=True)
class Endpoints:
    before: bytes
    after: bytes
    # Named domains and complete native page ranges, independent of model types.
    metadata: tuple
    initialized: tuple


def author():
    source, _, _ = f.make_image()
    before = bytes(v.build(source, 'standard'))
    after = bytearray(before)
    occupied = {v.BOOT_LCN, f.INDEX_LCN, v.FIRST_DATA_LCN, v.SECOND_DATA_LCN,
                NEW_DATA_LCN}
    occupied.update(range(f.MFT_LCN, f.MFT_LCN + v.MFT_BYTES // f.CLUSTER))
    occupied.update(range(f.MIRROR_LCN, f.MIRROR_LCN + v.MIRROR_RECORDS * f.RECORD // f.CLUSTER))
    occupied.update(range(f.UPCASE_LCN, f.UPCASE_LCN + v.UPCASE_UNITS * f.U16_BYTES // f.CLUSTER))
    bitmap = bytearray(f.IMAGE_SIZE // f.CLUSTER // f.BYTE_BITS)
    for cluster in occupied:
        bitmap[cluster // f.BYTE_BITS] |= 1 << (cluster % f.BYTE_BITS)
    new_link = v.Link(NEW_NAME, size=len(NEW_DATA))
    items = [(f.MFT_RECORD, v.Link('$MFT'), False),
             (v.MIRROR_RECORD, v.Link('$MFTMirr'), False),
             (f.VOLUME_RECORD, v.Link('$Volume'), False),
             (f.BITMAP_RECORD, v.Link('$Bitmap'), False),
             (v.BOOT_RECORD, v.Link('$Boot'), False),
             (f.UPCASE_RECORD, v.Link('$UpCase'), False),
             (v.FRAGMENTED_RECORD, v.Link('fragmented.bin'), False),
             (v.HELLO_RECORD, new_link, False)]
    items.sort(key=v.collation)
    previous_sequence = f.FIXUP_SEQUENCE
    try:
        f.FIXUP_SEQUENCE = NEW_FIXUP_SEQUENCE
        f.put_record(after, v.HELLO_RECORD, f.file_record(v.HELLO_RECORD, [
            f.standard(), v.filename(new_link),
            f.nonresident(f.DATA, [(1, NEW_DATA_LCN)], len(NEW_DATA), v.DATA_INSTANCE)]))
        f.put_record(after, f.BITMAP_RECORD, f.file_record(f.BITMAP_RECORD, [
            f.standard(), v.filename(v.Link('$Bitmap')),
            f.resident(f.DATA, bytes(bitmap), v.DATA_INSTANCE)]))
        f.put_data(after, f.INDEX_LCN, f.index_block(0, [
            v.index_entry(number, link, directory) for number, link, directory in items]))
    finally:
        f.FIXUP_SEQUENCE = previous_sequence
    data_page = NEW_DATA + bytes(f.CLUSTER - len(NEW_DATA))
    f.put_data(after, NEW_DATA_LCN, data_page)
    metadata = (('MFT', f.MFT_LCN * f.CLUSTER + v.HELLO_RECORD * f.RECORD, f.RECORD),
                ('BITMAP', f.MFT_LCN * f.CLUSTER + f.BITMAP_RECORD * f.RECORD, f.RECORD),
                ('INDEX', f.INDEX_LCN * f.CLUSTER, f.CLUSTER))
    initialized = ((NEW_DATA_LCN * f.CLUSTER, f.CLUSTER),)
    expected = bytearray(before)
    for address, length in (*[(address, length) for _, address, length in metadata], *initialized):
        expected[address:address + length] = after[address:address + length]
    assert expected == after
    assert before[NEW_DATA_LCN * f.CLUSTER:NEW_DATA_LCN * f.CLUSTER + f.CLUSTER] == bytes(f.CLUSTER)
    return Endpoints(before, bytes(after), metadata, initialized)
