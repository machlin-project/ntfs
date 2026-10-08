#!/usr/bin/env python3
"""Author virtual-volume prefixes for large mutation bitmap tests.

Unstored bytes read as zero. Occupied space outside the original small image is
synthetic: these fixtures exercise planning, not full-volume/native acceptance.
"""
from pathlib import Path
import argparse
import json
import struct

import fixtures as f
import filename_storage as storage

BITMAP_LCN = 4096
LARGE_BITMAP_BYTES = 2 * 1024 * 1024
FREE_CLUSTERS = 1024
BOUNDARY_PREFIX_CLUSTERS = 128
TAIL_UNUSED_BITS = 3
UNUSED_STORAGE = 0xa6
MFT_BITMAP_LCN = 6144
MFT_TAIL_LCN = 8192
MFT_PAGE_RECORDS = f.CLUSTER * f.BYTE_BITS


def author(output, source):
    output.mkdir(parents=True, exist_ok=True)
    original = source.read_bytes()
    record_offset = f.MFT_LCN * f.CLUSTER + f.BITMAP_RECORD * f.RECORD
    header, attributes = storage.record_parts(original[record_offset:record_offset + f.RECORD])
    slot = next(i for i, attr in enumerate(attributes)
                if storage.attr_header(attr)['type'] == f.DATA)
    previous = storage.resident_value(attributes[slot])
    rows = []
    assert len(original) <= BITMAP_LCN * f.CLUSTER
    for profile in ('early', 'late', 'boundary', 'mft-paged', 'mft-grow'):
        bitmap_bytes = 2 * f.CLUSTER + 3 if profile == 'boundary' else LARGE_BITMAP_BYTES
        clusters = bitmap_bytes * f.BYTE_BITS - TAIL_UNUSED_BITS
        bitmap = (bytearray(bitmap_bytes) if profile in ('early', 'mft-paged', 'mft-grow')
                  else bytearray([0xff]) * bitmap_bytes)
        if profile in ('early', 'mft-paged', 'mft-grow'):
            bitmap[:len(previous)] = previous
        else:
            first = (f.CLUSTER * f.BYTE_BITS - BOUNDARY_PREFIX_CLUSTERS
                     if profile == 'boundary' else clusters - 2 * FREE_CLUSTERS)
            for bit in range(first, first + FREE_CLUSTERS):
                bitmap[bit // f.BYTE_BITS] &= ~(1 << (bit % f.BYTE_BITS))
        storage_clusters = (bitmap_bytes + f.CLUSTER - 1) // f.CLUSTER
        for bit in (*range(BITMAP_LCN, BITMAP_LCN + storage_clusters), clusters - 1):
            bitmap[bit // f.BYTE_BITS] |= 1 << (bit % f.BYTE_BITS)
        image = bytearray(original)
        image.extend(bytes((BITMAP_LCN + storage_clusters) * f.CLUSTER - len(image)))
        struct.pack_into('<Q', image, f.BOOT_FIELDS['sectors'], clusters * f.CLUSTER // f.SECTOR)
        if profile.startswith('mft-'):
            first = f.MFT_LCN * f.CLUSTER
            mft_header, mft_attrs = storage.record_parts(original[first:first + f.RECORD])
            data_slot = next(i for i, a in enumerate(mft_attrs) if storage.attr_header(a)['type'] == f.DATA)
            bits_slot = next(i for i, a in enumerate(mft_attrs) if storage.attr_header(a)['type'] == f.BITMAP)
            old_data, runs = storage.mapping(mft_attrs[data_slot])
            records = MFT_PAGE_RECORDS + (f.CLUSTER // f.RECORD if profile == 'mft-paged' else 0)
            mft_bytes = records * f.RECORD
            tail_clusters = (mft_bytes - old_data['allocated']) // f.CLUSTER
            runs.append((tail_clusters, MFT_TAIL_LCN))
            mft_attrs[data_slot] = f.nonresident(f.DATA, runs, mft_bytes,
                storage.attr_header(mft_attrs[data_slot])['instance'])
            bits = bytearray([0xff]) * ((records + f.BYTE_BITS - 1) // f.BYTE_BITS)
            if profile == 'mft-paged':
                for bit in range(MFT_PAGE_RECORDS, records):
                    bits[bit // f.BYTE_BITS] &= ~(1 << (bit % f.BYTE_BITS))
            bits_clusters = (len(bits) + f.CLUSTER - 1) // f.CLUSTER
            mft_attrs[bits_slot] = f.nonresident(f.BITMAP, [(bits_clusters, MFT_BITMAP_LCN)], len(bits),
                storage.attr_header(mft_attrs[bits_slot])['instance'])
            encoded = storage.encoded_record(f.MFT_RECORD, mft_attrs, mft_header)
            f.put_record(image, f.MFT_RECORD, encoded)
            f.put_data(image, f.MIRROR_LCN, encoded)
            image.extend(bytes((MFT_BITMAP_LCN + bits_clusters) * f.CLUSTER - len(image)))
            f.put_data(image, MFT_BITMAP_LCN, bits + bytes([UNUSED_STORAGE]) * (bits_clusters * f.CLUSTER - len(bits)))
            for bit in (*range(MFT_BITMAP_LCN, MFT_BITMAP_LCN + bits_clusters),
                        *range(MFT_TAIL_LCN, MFT_TAIL_LCN + tail_clusters)):
                bitmap[bit // f.BYTE_BITS] |= 1 << (bit % f.BYTE_BITS)
        attrs = list(attributes)
        attrs[slot] = f.nonresident(f.DATA, [(storage_clusters, BITMAP_LCN)], bitmap_bytes,
            storage.attr_header(attributes[slot])['instance'],
            allocated=storage_clusters * f.CLUSTER, initialized=bitmap_bytes)
        f.put_record(image, f.BITMAP_RECORD, storage.encoded_record(f.BITMAP_RECORD, attrs, header))
        data = bitmap + bytes([UNUSED_STORAGE]) * (storage_clusters * f.CLUSTER - bitmap_bytes)
        f.put_data(image, BITMAP_LCN, data)
        (output / (profile + '.img')).write_bytes(image)
        rows.append(dict(profile=profile, clusters=clusters, bitmapBytes=bitmap_bytes,
                         prefixBytes=len(image), virtualBytes=clusters * f.CLUSTER))
    (output / 'manifest.json').write_text(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('stamp', nargs='?', type=Path)
    parser.add_argument('--source', required=True, type=Path)
    args = parser.parse_args()
    author(args.output, args.source)
    if args.stamp:
        args.stamp.write_text('large mutation bitmap virtual prefixes\n')
