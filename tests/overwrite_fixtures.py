#!/usr/bin/env python3
"""Original complete NTFS images for the bounded physical overwrite owner.

These author the complete allocation, namespace and quiet-log inputs separately
from the implementation; native Windows recovery remains a separate acceptance.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

import fixtures as f
import filename_storage as storage
import validation_fixtures as v
import logfile_fixtures as w
from logfile_checkpoint_fixtures import CLIENT_RESTART, CLIENT_ATTRIBUTES_MAJOR, CLIENT_MINOR
from logfile_source_fixtures import restart
from secure_store_fixtures import resident_value

LOG_BYTES = 256 * 1024
LOG_LCN = 176
LOG_CLUSTERS = LOG_BYTES // f.CLUSTER
LOG_HOME = (w.RESTART_PAGES + w.LEGACY_TAIL_PAGES) * w.PAGE_BYTES
LOG_CLIENT_RESTART_FLAG = 2
NOOP = 0
OPAQUE_WORDS = (w.UNUSED_LCN_SLOT, w.BASE_LSN, w.BASE_LSN + w.ALIGNMENT)
RESTART_EXTENSION_BYTES = 48
HIBERNATION_RECORD = v.EXTRA_RECORD
READ_ONLY_ATTRIBUTE = 1
SUCCESS, CORRUPT, UNSUPPORTED, DIRTY = 0, 2, 3, 13


def get_record(image, number):
    first = f.MFT_LCN * f.CLUSTER + number * f.RECORD
    return storage.record_parts(image[first:first + f.RECORD])


def set_record(image, number, header, values):
    f.put_record(image, number, storage.encoded_record(number, values, header))


def replace_attribute(image, number, kind, value):
    header, values = get_record(image, number)
    index = next(index for index, attr in enumerate(values)
                 if storage.attr_header(attr)['type'] == kind and not storage.attr_name(attr))
    values[index] = value
    set_record(image, number, header, values)


def quiet_log(*, clean=True, mutating=False):
    first = w.lsn_at(LOG_HOME + w.PAGE_DATA_OFFSET, LOG_BYTES)
    bootstrap_body = w.UPDATE.pack(dict(redo_operation=w.UPDATE_RESIDENT if mutating else NOOP,
                                      undo_operation=NOOP))
    bootstrap_body += struct.pack('<' + 'Q' * len(OPAQUE_WORDS), *OPAQUE_WORDS)
    bootstrap = w.RECORD.pack(dict(lsn=first, data_bytes=len(bootstrap_body),
        client_sequence=w.CLIENT_SEQUENCE, type=w.UPDATE_TYPE, transaction=w.TRANSACTION))
    bootstrap += bootstrap_body
    restart_offset = w.aligned(w.PAGE_DATA_OFFSET + len(bootstrap))
    last = w.lsn_at(LOG_HOME + restart_offset, LOG_BYTES)
    checkpoint_body = CLIENT_RESTART.pack(dict(major=CLIENT_ATTRIBUTES_MAJOR,
        minor=CLIENT_MINOR, analysis_lsn=first)) + bytes([0x7d]) * RESTART_EXTENSION_BYTES
    checkpoint = w.RECORD.pack(dict(lsn=last, data_bytes=len(checkpoint_body),
        client_sequence=w.CLIENT_SEQUENCE, type=w.RESTART_TYPE, transaction=0)) + checkpoint_body
    restart_page, _ = restart(system=w.PAGE_BYTES, log=w.PAGE_BYTES, file_bytes=LOG_BYTES,
        current=last, clients=[w.client(oldest=first, restart=last)], flags=w.CLEAN if clean else 0)
    journal = bytearray(LOG_BYTES)
    for slot in range(w.RESTART_PAGES):
        journal[slot * w.PAGE_BYTES:(slot + 1) * w.PAGE_BYTES] = restart_page
    page = bytearray(w.PAGE_BYTES)
    page[:w.PAGE.size] = w.PAGE.pack(dict(magic=b'RCRD', usa_offset=w.PAGE.size,
        copy_value=last, last_end_lsn=last, flags=w.RECORD_END | LOG_CLIENT_RESTART_FLAG,
        page_count=1, page_position=1,
        next_record_offset=w.aligned(restart_offset + len(checkpoint))))
    page[w.PAGE_DATA_OFFSET:w.PAGE_DATA_OFFSET + len(bootstrap)] = bootstrap
    page[restart_offset:restart_offset + len(checkpoint)] = checkpoint
    raw, _ = w.protect(page, w.PAGE)
    journal[LOG_HOME:LOG_HOME + w.PAGE_BYTES] = raw
    return journal


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    original, _, _ = f.make_image()
    cases = []
    for name in ('ordinary', 'hibernation', 'not-clean', 'mutating-log', 'dirty',
                 'overlap', 'read-only-file', 'uninitialized-file'):
        overrides = ({HIBERNATION_RECORD: [v.Link('hiberfil.sys')]}
                     if name == 'hibernation' else None)
        image = v.build(original, 'logfile-empty', links_override=overrides)
        journal = quiet_log(clean=name != 'not-clean', mutating=name == 'mutating-log')
        f.put_data(image, LOG_LCN, journal)
        replace_attribute(image, v.LOGFILE_RECORD, f.DATA,
            f.nonresident(f.DATA, [(LOG_CLUSTERS, LOG_LCN)], LOG_BYTES, v.DATA_INSTANCE))
        header, values = get_record(image, f.BITMAP_RECORD)
        bitmap = bytearray(resident_value(next(attr for attr in values
            if storage.attr_header(attr)['type'] == f.DATA)))
        for cluster in range(LOG_LCN, LOG_LCN + LOG_CLUSTERS):
            assert not bitmap[cluster // f.BYTE_BITS] & 1 << (cluster % f.BYTE_BITS)
            bitmap[cluster // f.BYTE_BITS] |= 1 << (cluster % f.BYTE_BITS)
        replace_attribute(image, f.BITMAP_RECORD, f.DATA,
                          f.resident(f.DATA, bitmap, v.DATA_INSTANCE))
        if name == 'hibernation':
            f.put_record(image, HIBERNATION_RECORD, f.file_record(HIBERNATION_RECORD,
                [v.standard(), v.filename(v.Link('hiberfil.sys')), v.security(),
                 f.resident(f.DATA, b'', v.DATA_INSTANCE)]))
            header, values = get_record(image, f.MFT_RECORD)
            mft_bitmap = bytearray(resident_value(next(attr for attr in values
                if storage.attr_header(attr)['type'] == f.BITMAP)))
            mft_bitmap[HIBERNATION_RECORD // f.BYTE_BITS] |= 1 << (HIBERNATION_RECORD % f.BYTE_BITS)
            replace_attribute(image, f.MFT_RECORD, f.BITMAP,
                              f.resident(f.BITMAP, mft_bitmap, v.MFT_BITMAP_INSTANCE))
        if name == 'dirty':
            replace_attribute(image, f.VOLUME_RECORD, f.VOL_INFO,
                f.resident(f.VOL_INFO, v.VOLUME_INFORMATION.pack(f.NTFS_MAJOR_VERSION,
                    f.NTFS_MINOR_VERSION, f.VOLUME_DIRTY), v.VOLUME_INFO_INSTANCE))
        if name == 'read-only-file':
            replace_attribute(image, v.FRAGMENTED_RECORD, f.SI, v.standard(READ_ONLY_ATTRIBUTE))
        if name in ('overlap', 'uninitialized-file'):
            replace_attribute(image, v.FRAGMENTED_RECORD, f.DATA,
                f.nonresident(f.DATA, [(1, f.UPCASE_LCN if name == 'overlap' else v.FIRST_DATA_LCN),
                    (1, v.SECOND_DATA_LCN)], f.FRAGMENTED_BYTES, v.DATA_INSTANCE,
                    initialized=0 if name == 'uninitialized-file' else f.FRAGMENTED_BYTES))
        mft_first = f.MFT_LCN * f.CLUSTER
        f.put_data(image, f.MIRROR_LCN, image[mft_first:mft_first + v.MIRROR_RECORDS * f.RECORD])
        filename = name + '.img'
        (output / filename).write_bytes(image)
        open_code = (CORRUPT if name == 'overlap' else DIRTY if name == 'dirty' else
                     UNSUPPORTED if name in ('hibernation', 'not-clean', 'mutating-log') else SUCCESS)
        cases.append(dict(path=filename, open_code=open_code,
                          sha256=hashlib.sha256(image).hexdigest()))
    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    (output / 'cases.rows').write_text(''.join(f"{case['path']} {case['open_code']}\n"
                                            for case in cases))
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('original physical overwrite owner inputs\n')
