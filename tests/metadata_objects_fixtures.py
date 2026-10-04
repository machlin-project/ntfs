#!/usr/bin/env python3
"""Author independent-file metadata/cache controls, without Windows qualification.

Selected root/user names and resident streams have exact byte oracles. Legacy
system stores and unselected objects are inherited; whole-volume consistency is
not claimed. A separate MFT extent leaves inherited stream bytes untouched.
"""
import argparse
import hashlib
import json
from pathlib import Path

import fixtures as f


REFERENCE_CACHE_ENTRIES = 64
FIT_OBJECTS = REFERENCE_CACHE_ENTRIES // 2
PRESSURE_OBJECTS = REFERENCE_CACHE_ENTRIES * 4
# Keep the fitting user range away from the root's default direct-map slot.
FIRST_OBJECT_RECORD = f.MFT_COUNT + f.SYSTEM_RECORD_LIMIT
INDEX_ALLOCATION_LCN = f.ALLOCATED_CLUSTERS
INDEX_RESERVED_CLUSTERS = 16  # The largest control tree uses at most fifteen blocks.
MFT_EXTENSION_LCN = INDEX_ALLOCATION_LCN + INDEX_RESERVED_CLUSTERS
INDEX_BLOCK_CLUSTERS = 1
LEAF_ENTRIES = 32  # Short keys fit comfortably in one authored 4-KiB index block.
FILENAME_INSTANCE = f.DIR_BITMAP_INSTANCE + 1
FILE_DATA_INSTANCE = 1
FILE_NAME_INSTANCE = FILE_DATA_INSTANCE + 1
REPARSE_INSTANCE = FILE_NAME_INSTANCE + 1
COLLIDING_OBJECT_ORDINAL = REFERENCE_CACHE_ENTRIES
PAYLOAD_PREFIX = b'unique NTFS object '


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    source, _, _ = f.make_image()
    cases = []
    for label, count in (('fit', FIT_OBJECTS), ('pressure', PRESSURE_OBJECTS)):
        image = bytearray(source)
        inventory, objects, streams, records, blocks = [], [], [], [], []

        def expected_name(number, payload):
            return {'reference': f'{f.file_reference(number):016x}',
                    'filename_body_hashes': [hashlib.sha256(payload).hexdigest()],
                    'counts': {'physical_names': 1, 'primary_names': 1, 'dos_aliases': 0},
                    'result': 'success'}

        for ordinal in range(count):
            number = FIRST_OBJECT_RECORD + ordinal
            name = f'object{ordinal:04d}.dat'
            payload = PAYLOAD_PREFIX + f'{ordinal:04d}\n'.encode('ascii')
            filename = f.key(name, len(payload))
            records.append(f.file_record(number, [f.standard(),
                           f.resident(f.FILENAME, filename, FILE_NAME_INSTANCE),
                           f.resident(f.DATA, payload, FILE_DATA_INSTANCE)]))
            inventory.append({'units': [ord(unit) for unit in name], 'native': name,
                              'reference': f.file_reference(number), 'size': len(payload)})
            objects.append(expected_name(number, filename))
            streams.append({'reference': f'{f.file_reference(number):016x}',
                            'hex': payload.hex()})

        def link(ordinal, child=None):
            value = inventory[ordinal]
            return f.entry(value['native'], FIRST_OBJECT_RECORD + ordinal,
                           value['size'], child=child)

        def subtree(first, last):
            if last - first <= LEAF_ENTRIES:
                entries = [link(ordinal) for ordinal in range(first, last)]
                terminal = None
            else:
                middle = first + (last - first) // 2
                left = subtree(first, middle)
                terminal = subtree(middle + 1, last)
                entries = [link(middle, child=left)]
            vcn = len(blocks)
            blocks.append(f.index_block(vcn, entries, terminal))
            return vcn

        child = subtree(0, count)
        assert len(blocks) <= INDEX_RESERVED_CLUSTERS
        root_entries = f.entry(child=child)
        root = f.INDEX_ROOT_HEADER.pack(f.FILENAME, f.COLLATION_FILENAME, f.CLUSTER,
                                       INDEX_BLOCK_CLUSTERS)
        root += f.INDEX_HEADER.pack(f.INDEX_HEADER.size,
                                   f.INDEX_HEADER.size + len(root_entries),
                                   f.INDEX_HEADER.size + len(root_entries), f.INDEX_LARGE)
        root += root_entries
        index_bitmap = ((1 << len(blocks)) - 1).to_bytes(
            (len(blocks) + f.BYTE_BITS - 1) // f.BYTE_BITS, 'little')
        root_name = f.key('.', namespace=f.NAMESPACE_WIN32_DOS,
                          attributes=f.FILE_ATTRIBUTE_DIRECTORY)
        f.put_record(image, f.ROOT_RECORD, f.file_record(f.ROOT_RECORD, [
            f.standard(f.FILE_ATTRIBUTE_DIRECTORY),
            f.resident(f.FILENAME, root_name, FILENAME_INSTANCE),
            f.resident(f.INDEX_ROOT, root, f.DIR_ROOT_INSTANCE, '$I30'),
            f.nonresident(f.INDEX_ALLOC, [(len(blocks), INDEX_ALLOCATION_LCN)],
                          len(blocks) * f.CLUSTER, f.DIR_ALLOCATION_INSTANCE, '$I30'),
            f.resident(f.BITMAP, index_bitmap, f.DIR_BITMAP_INSTANCE, '$I30')], directory=True))
        objects.insert(0, expected_name(f.ROOT_RECORD, root_name))
        for vcn, block in enumerate(blocks):
            f.put_data(image, INDEX_ALLOCATION_LCN + vcn, block)

        original_clusters = f.MFT_COUNT * f.RECORD // f.CLUSTER
        added_records = FIRST_OBJECT_RECORD + count - f.MFT_COUNT
        added_bytes = added_records * f.RECORD
        assert added_bytes % f.CLUSTER == 0
        added_clusters = added_bytes // f.CLUSTER
        assert (MFT_EXTENSION_LCN + added_clusters) * f.CLUSTER <= f.IMAGE_SIZE
        table = bytearray(added_bytes)
        for ordinal, record in enumerate(records):
            offset = (FIRST_OBJECT_RECORD + ordinal - f.MFT_COUNT) * f.RECORD
            table[offset:offset + f.RECORD] = record
        f.put_data(image, MFT_EXTENSION_LCN, table)
        mft = f.file_record(f.MFT_RECORD, [f.standard(), f.nonresident(f.DATA,
                            [(original_clusters, f.MFT_LCN),
                             (added_clusters, MFT_EXTENSION_LCN)],
                            (f.MFT_COUNT + added_records) * f.RECORD, FILE_DATA_INSTANCE)])
        f.put_record(image, f.MFT_RECORD, mft)
        f.put_data(image, f.MIRROR_LCN, mft)

        bitmap = bytearray(f.IMAGE_SIZE // f.CLUSTER // f.BYTE_BITS)
        for first, clusters in ((0, f.ALLOCATED_CLUSTERS),
                                (MFT_EXTENSION_LCN, added_clusters),
                                (INDEX_ALLOCATION_LCN, len(blocks))):
            for cluster in range(first, first + clusters):
                bitmap[cluster // f.BYTE_BITS] |= 1 << (cluster % f.BYTE_BITS)
        f.put_record(image, f.BITMAP_RECORD, f.file_record(f.BITMAP_RECORD,
                     [f.standard(), f.resident(f.DATA, bitmap, FILE_DATA_INSTANCE)]))
        image_name = 'metadata-objects-' + label + '.img'
        (output / image_name).write_bytes(image)
        (output / ('metadata-objects-' + label + '.json')).write_text(
            json.dumps(inventory, indent=2) + '\n')
        cases.append({'image': image_name, 'objects': objects, 'streams': streams,
                      'sha256': hashlib.sha256(image).hexdigest(),
                      'source_sha256': hashlib.sha256(source).hexdigest(),
                      'objects_in_inventory': count,
                      'mft_record_slots': f.MFT_COUNT + added_records})
        if label == 'pressure':
            # The colliding object has valid FILE framing and names, but a
            # cleared standard flag cannot hide its separately stored reparse.
            rejected = bytearray(image)
            ordinal = COLLIDING_OBJECT_ORDINAL
            number = FIRST_OBJECT_RECORD + ordinal
            value = inventory[ordinal]
            payload = bytes.fromhex(streams[ordinal]['hex'])
            packet = f.reparse_value(f.REPARSE_TAG_SYMLINK, 'target', relative=True)
            record = f.file_record(number, [f.standard(),
                                  f.resident(f.FILENAME, f.key(value['native'], value['size']),
                                             FILE_NAME_INSTANCE),
                                  f.resident(f.DATA, payload, FILE_DATA_INSTANCE),
                                  f.resident(f.REPARSE_POINT, packet, REPARSE_INSTANCE)])
            physical = MFT_EXTENSION_LCN * f.CLUSTER + (number - f.MFT_COUNT) * f.RECORD
            rejected[physical:physical + f.RECORD] = record
            (output / 'metadata-objects-rejected.img').write_bytes(rejected)
    (output / 'metadata-objects-cases.json').write_text(json.dumps(cases, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('stamp', nargs='?', type=Path)
    parser.add_argument('--image-bytes', type=int, default=f.IMAGE_SIZE)
    args = parser.parse_args()
    required_bytes = MFT_EXTENSION_LCN * f.CLUSTER + (
        FIRST_OBJECT_RECORD + PRESSURE_OBJECTS - f.MFT_COUNT) * f.RECORD
    if (not required_bytes <= args.image_bytes <= f.IMAGE_SIZE or
            args.image_bytes % f.CLUSTER != 0):
        parser.error('Image geometry must contain the bounded layout and use whole clusters')
    f.IMAGE_SIZE = args.image_bytes
    author(args.output)
    if args.stamp:
        args.stamp.write_text('authored independent metadata object controls\n')
