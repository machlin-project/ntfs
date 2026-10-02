#!/usr/bin/env python3
"""Original NTFS stream/continuation layouts around independently authored logs."""
from pathlib import Path
import json
import sys
import fixtures as f

LOGFILE_RECORD = 2
EXTENSION_RECORD = f.MFT_COUNT - 1
DATA_INSTANCE = 1
LIST_INSTANCE = 2
REPARSE_INSTANCE = 3
FIRST_EXTENT_CLUSTERS = 1
CONTINUATION_VCN = FIRST_EXTENT_CLUSTERS
GAP_VCN = CONTINUATION_VCN + 1
LOGFILE_LCN = 176
FRAGMENT_LCN = 208
FINAL_LCN = 224
LIST_LCN = 250
LOGFILE_HIDDEN = 0x0002
LOGFILE_SYSTEM = 0x0004
FILE_ATTRIBUTES = LOGFILE_HIDDEN | LOGFILE_SYSTEM
SUCCESS, CORRUPT, UNSUPPORTED, NOT_FOUND, STALE = 0, 2, 3, 6, 10


def mark_clusters(image, runs):
    bitmap = bytearray(f.IMAGE_SIZE // f.CLUSTER // f.BYTE_BITS)
    for cluster in range(f.ALLOCATED_CLUSTERS):
        bitmap[cluster // f.BYTE_BITS] |= 1 << (cluster % f.BYTE_BITS)
    for count, first in runs:
        if first is not None:
            for cluster in range(first, first + count):
                bitmap[cluster // f.BYTE_BITS] |= 1 << (cluster % f.BYTE_BITS)
    f.put_record(image, f.BITMAP_RECORD, f.file_record(f.BITMAP_RECORD,
        [f.standard(), f.resident(f.DATA, bitmap, DATA_INSTANCE)]))


def _author(output, source_directory, name_prefix):
    output.mkdir(parents=True, exist_ok=True)
    base, _, _ = f.make_image()
    source_cases = {case['path']: case for case in json.loads(
        (source_directory / 'manifest.json').read_text())['cases']}
    cases = []
    skipped = []
    names = set()

    def add(name, source_name='equal', *, fragmented=False, listed=False, nonresident_list=False,
            stale=False, wrong_base=False, gap=False, directory=False, reparse=False,
            view=False, uninterpreted=False, data_flags=0, file_flags=0,
            partial=False, missing=False, verdict=SUCCESS):
        assert name not in names
        names.add(name)
        source_case = source_cases[source_name + '.journal']
        data = (source_directory / source_case['path']).read_bytes()
        image = bytearray(base)
        clusters = (len(data) + f.CLUSTER - 1) // f.CLUSTER
        runs = [(clusters, LOGFILE_LCN)]
        if fragmented or listed:
            runs = [(FIRST_EXTENT_CLUSTERS, LOGFILE_LCN),
                    (FIRST_EXTENT_CLUSTERS, FRAGMENT_LCN),
                    (clusters - 2 * FIRST_EXTENT_CLUSTERS, FINAL_LCN)]
        if any(first + count > f.IMAGE_SIZE // f.CLUSTER for count, first in runs):
            skipped.append(dict(path=name_prefix + name + '.img',
                                reason='physical journal extents exceed authored geometry'))
            return
        position = 0
        for count, lcn in runs:
            size = count * f.CLUSTER
            f.put_data(image, lcn, data[position:position + size])
            position += size
        attribute = f.nonresident(f.DATA, runs, len(data), DATA_INSTANCE,
            initialized=len(data) - f.U16_BYTES if partial else len(data),
            allocated=clusters * f.CLUSTER, flags=data_flags)
        attributes = [f.standard(FILE_ATTRIBUTES | file_flags), attribute]
        if missing:
            attributes = attributes[:1]
        if reparse:
            attributes[0] = f.standard(FILE_ATTRIBUTES | f.FILE_ATTRIBUTE_REPARSE)
            attributes.append(f.resident(f.REPARSE_POINT,
                f.reparse_value(f.REPARSE_TAG_SYMLINK, 'target', relative=True), REPARSE_INSTANCE))
        if listed:
            owner = f.file_reference(LOGFILE_RECORD)
            next_vcn = GAP_VCN if gap else CONTINUATION_VCN
            extension = f.nonresident(f.DATA, runs[1:], len(data), instance=0, lowest=next_vcn,
                                      allocated=clusters * f.CLUSTER)
            f.put_record(image, EXTENSION_RECORD, f.file_record(EXTENSION_RECORD, [extension],
                base=f.file_reference(f.FILE_RECORDS['hello.txt']) if wrong_base else owner))
            extension_reference = f.file_reference(EXTENSION_RECORD,
                f.FILE_SEQUENCE + 1 if stale else f.FILE_SEQUENCE)
            listing = f.list_entry(owner, 0, 0, kind=f.SI)
            listing += f.list_entry(owner, DATA_INSTANCE, 0)
            listing += f.list_entry(extension_reference, 0, next_vcn)
            attributes[1] = f.nonresident(f.DATA, runs[:1], len(data), DATA_INSTANCE,
                                         allocated=clusters * f.CLUSTER)
            if nonresident_list:
                list_attribute = f.nonresident(f.ATTR_LIST, [(1, LIST_LCN)], len(listing), LIST_INSTANCE)
                f.put_data(image, LIST_LCN, listing)
                runs.append((1, LIST_LCN))
            else:
                list_attribute = f.resident(f.ATTR_LIST, listing, LIST_INSTANCE)
            attributes.insert(1, list_attribute)
        f.put_record(image, LOGFILE_RECORD, f.file_record(LOGFILE_RECORD, attributes,
            directory=directory, view=view, uninterpreted=uninterpreted))
        mark_clusters(image, runs)
        filename = name_prefix + name + '.img'
        (output / filename).write_bytes(image)
        journal_reached = verdict == SUCCESS or name == 'conflicting-copies'
        case = dict(path=filename, code=verdict, source=source_case['path'],
                    source_expected=source_case if journal_reached else None)
        cases.append(case)

    add('contiguous')
    add('fragmented', 'system-4096', fragmented=True)
    add('listed', 'system-4096', listed=True)
    add('nonresident-list', 'system-4096', listed=True, nonresident_list=True)
    add('ordinary-4096', 'ordinary-4096', fragmented=True)
    add('maximum-page', 'maximum-page', fragmented=True)
    add('fast', 'fast', fragmented=True)
    add('torn-first', 'torn-first', fragmented=True)
    add('conflicting-copies', 'equal-lsn-conflict', verdict=UNSUPPORTED)
    add('stale-extension', listed=True, stale=True, verdict=STALE)
    # The shared extent resolver reports mismatched sequence or base ownership
    # as STALE, separately from malformed mapping/continuation framing.
    add('wrong-extension-owner', listed=True, wrong_base=True, verdict=STALE)
    add('continuation-gap', listed=True, gap=True, verdict=CORRUPT)
    add('directory', directory=True, verdict=UNSUPPORTED)
    add('reparse', reparse=True, verdict=UNSUPPORTED)
    add('view-record', view=True, verdict=UNSUPPORTED)
    add('uninterpreted-record', uninterpreted=True, verdict=UNSUPPORTED)
    add('encrypted-flag', file_flags=f.FILE_ATTRIBUTE_ENCRYPTED, verdict=UNSUPPORTED)
    add('compressed-flag', file_flags=f.FILE_ATTRIBUTE_COMPRESSED, verdict=UNSUPPORTED)
    add('sparse-flag', file_flags=f.FILE_ATTRIBUTE_SPARSE, verdict=UNSUPPORTED)
    add('encrypted-attribute', data_flags=f.ENCRYPTED, verdict=UNSUPPORTED)
    add('compressed-attribute', data_flags=f.COMPRESSED, verdict=UNSUPPORTED)
    add('sparse-attribute', data_flags=f.SPARSE, verdict=UNSUPPORTED)
    add('partial-initialization', partial=True, verdict=UNSUPPORTED)
    add('missing-stream', missing=True, verdict=NOT_FOUND)
    (output / 'manifest.json').write_text(json.dumps(dict(image_bytes=f.IMAGE_SIZE,
        cases=cases, skipped=skipped), indent=2) + '\n')
    (output / 'cases.tsv').write_text('\n'.join(
        f"{case['path']}\t{case['code']}\t{case['source']}" for case in cases) + '\n')
    return cases


def author(output, source_directory, image_bytes=None, name_prefix=''):
    previous = f.IMAGE_SIZE
    if image_bytes is not None:
        assert image_bytes > 0 and image_bytes % (f.CLUSTER * f.BYTE_BITS) == 0
        f.IMAGE_SIZE = image_bytes
    try:
        return _author(output, source_directory, name_prefix)
    finally:
        f.IMAGE_SIZE = previous


if __name__ == '__main__':
    author(Path(sys.argv[1]), Path(sys.argv[2]))
    if len(sys.argv) > 3:
        Path(sys.argv[3]).write_text('original-logfile-volume-layouts\n')
