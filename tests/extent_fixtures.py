#!/usr/bin/env python3
"""Author original fragmented stream workloads and independent content oracles."""
from pathlib import Path
import argparse
import hashlib
import json
import struct

import fixtures as f

IMAGE_BYTES = 16 * 1024 * 1024
LOGICAL_CLUSTERS = 1024
FIRST_DATA_LCN = 192
PHYSICAL_GAP_CLUSTERS = 1
# Ninety-six three-byte pairs and eleven list entries fit the 1-KiB base record.
RUNS_PER_ATTRIBUTE = 96
FIRST_EXTENSION_RECORD = 41
DATA_INSTANCE = 3
LIST_INSTANCE = 2
BITMAP_DATA_INSTANCE = 1
SPARSE_PERIOD_RUNS = 2
TAIL_UNINITIALIZED_CLUSTERS = 2
TAIL_INITIALIZED_BYTES = 17
FILE_NAME = 'fragmented.bin'
FILE_RECORD = f.FILE_RECORDS[FILE_NAME]
PROFILES = ('contiguous', 'runs-16', 'runs-256', 'runs-1024',
            'sparse-1024', 'uninitialized-1024')


def make_profile(profile):
    if profile not in PROFILES:
        raise ValueError(profile)
    previous_size = f.IMAGE_SIZE
    try:
        f.IMAGE_SIZE = IMAGE_BYTES
        image, _, _ = f.make_image()
    finally:
        f.IMAGE_SIZE = previous_size
    count = 1 if profile == 'contiguous' else int(profile.rsplit('-', 1)[1])
    length = LOGICAL_CLUSTERS // count
    sparse = profile.startswith('sparse-')
    flags = f.SPARSE if sparse else 0
    size = LOGICAL_CLUSTERS * f.CLUSTER
    initialized = (size - TAIL_UNINITIALIZED_CLUSTERS * f.CLUSTER + TAIL_INITIALIZED_BYTES
                   if profile.startswith('uninitialized-') else size)
    runs, original, lowest, occupied = [], bytearray(), 0, set()
    for ordinal in range(count):
        lcn = (None if sparse and ordinal % SPARSE_PERIOD_RUNS else
               FIRST_DATA_LCN + ordinal * (length + PHYSICAL_GAP_CLUSTERS))
        # Independent SHAKE blocks distinguish every logical extent and byte.
        payload = hashlib.shake_256(f'NTFS extent workload {ordinal}'.encode()).digest(
            length * f.CLUSTER)
        if lcn is None:
            payload = bytes(len(payload))
        else:
            f.put_data(image, lcn, payload)
            occupied.update(range(lcn, lcn + length))
        runs.append((length, lcn))
        original.extend(payload)
    original[initialized:] = bytes(size - initialized)
    groups = [runs[start:start + RUNS_PER_ATTRIBUTE]
              for start in range(0, len(runs), RUNS_PER_ATTRIBUTE)]
    physical_bytes = len(occupied) * f.CLUSTER
    attribute_list = bytearray()
    for ordinal, group in enumerate(groups):
        number = FILE_RECORD if ordinal == 0 else FIRST_EXTENSION_RECORD + ordinal - 1
        instance = DATA_INSTANCE if ordinal == 0 else 0
        assert number < f.MFT_COUNT
        attribute_list.extend(f.list_entry(f.file_reference(number), instance, lowest))
        if ordinal != 0:
            f.put_record(image, number, f.file_record(number, [f.nonresident(
                f.DATA, group, 0, instance, lowest=lowest, flags=flags)],
                base=f.file_reference(FILE_RECORD)))
        lowest += sum(run_length for run_length, _ in group)
    attributes = [f.standard(f.FILE_ATTRIBUTE_SPARSE if sparse else 0),
                  f.resident(f.FILENAME, f.key(FILE_NAME, size))]
    if len(groups) != 1:
        attributes.append(f.resident(f.ATTR_LIST, attribute_list, LIST_INSTANCE))
    attributes.append(f.nonresident(
        f.DATA, groups[0], size, DATA_INSTANCE, initialized=initialized,
        flags=flags, allocated=size))
    if sparse:
        # The sparse physical-size field describes the complete stream.
        first = bytearray(attributes[-1])
        struct.pack_into('<Q', first, f.ATTR_HEADER.size + f.NONRESIDENT_HEADER.size,
                         physical_bytes)
        attributes[-1] = bytes(first)
    f.put_record(image, FILE_RECORD, f.file_record(FILE_RECORD, attributes))
    f.put_record(image, f.ROOT_RECORD, f.directory_record(
        f.entry(FILE_NAME, FILE_RECORD, size) + f.entry()))
    bitmap = bytearray(IMAGE_BYTES // f.CLUSTER // f.BYTE_BITS)
    occupied.update(range(f.ALLOCATED_CLUSTERS))
    for lcn in occupied:
        bitmap[lcn // f.BYTE_BITS] |= 1 << (lcn % f.BYTE_BITS)
    f.put_record(image, f.BITMAP_RECORD, f.file_record(f.BITMAP_RECORD, [
        f.standard(), f.resident(f.DATA, bitmap, BITMAP_DATA_INSTANCE)]))
    return image, bytes(original), {
        'profile': profile, 'file': '/' + FILE_NAME,
        'reference': f.file_reference(FILE_RECORD), 'cluster_bytes': f.CLUSTER,
        'run_count': count, 'attribute_count': len(groups),
        'initialized_bytes': initialized, 'logical_bytes': size,
        'physical_bytes': physical_bytes, 'runs': runs,
        'windows_qualified': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('stamp', type=Path, nargs='?')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for profile in PROFILES:
        image, original, manifest = make_profile(profile)
        manifest['image_sha256'] = hashlib.sha256(image).hexdigest()
        manifest['data_sha256'] = hashlib.sha256(original).hexdigest()
        (args.output / (profile + '.img')).write_bytes(image)
        (args.output / (profile + '.data')).write_bytes(original)
        (args.output / (profile + '.json')).write_text(json.dumps(manifest, indent=2) + '\n')
    if args.stamp is not None:
        args.stamp.write_text('original extent workloads\n')


if __name__ == '__main__':
    main()
