#!/usr/bin/env python3
"""Independent LFS ring placement and complete continuation-page byte goldens."""
from pathlib import Path
import json
import struct
import sys

import logfile_fixtures as f

PACKET_BYTES = f.RECORD.size + f.UPDATE.size + f.LSN_BYTES + 2 * f.PAGE_BYTES
RING_PAGES = f.MIN_RECORD_PAGES
DATA_BYTES = f.PAGE_BYTES - f.PAGE_DATA_OFFSET
EPOCH = 11
FIRST_PRIVATE_USA = 1
ORDINARY_PACKET_BYTES = 128
CLIENT_RESTART_COMMON_BYTES = 64
CLIENT_RESTART_PAGE = 0x00000002
OPEN_ATTRIBUTE_KEY = 24
TRANSACTION_KEY = 64
UPDATE_NONRESIDENT = 8
INDEX_TARGET = 8
FIRST_TARGET_LCN = 500
MAX_PACKETS = 4096
NO_LINK = -1
WIRE_LSN_MASK = (1 << f.LSN_BITS) - 1


def protect(logical):
    """Author a canonical private marker; actual predecessor guarding is separate."""
    raw = bytearray(logical)
    count = len(raw) // f.USA_STRIDE + 1
    f.PAGE.put(raw, 'usa_count', count)
    usa = f.PAGE.size
    struct.pack_into('<H', raw, usa, FIRST_PRIVATE_USA)
    for sector in range(1, count):
        tail = sector * f.USA_STRIDE - f.WORD_BYTES
        raw[usa + sector * f.WORD_BYTES:usa + (sector + 1) * f.WORD_BYTES] = raw[
            tail:tail + f.WORD_BYTES]
        struct.pack_into('<H', raw, tail, FIRST_PRIVATE_USA)
    return bytes(raw)


def payload_bytes(length, ordinal):
    if length == PACKET_BYTES:
        redo = bytes((index * 17 + 5) & 0xff for index in range(f.PAGE_BYTES))
        undo = bytes((index * 29 + 7) & 0xff for index in range(f.PAGE_BYTES))
        return (f.UPDATE.pack(dict(redo_operation=UPDATE_NONRESIDENT,
            undo_operation=UPDATE_NONRESIDENT, redo_offset=f.UPDATE.size + f.LSN_BYTES,
            redo_bytes=len(redo), undo_offset=f.UPDATE.size + f.LSN_BYTES + len(redo),
            undo_bytes=len(undo), target_attribute=OPEN_ATTRIBUTE_KEY, lcns=1,
            attribute_flags=INDEX_TARGET, target_vcn=ordinal)) +
            struct.pack('<Q', FIRST_TARGET_LCN + ordinal) + redo + undo)
    return bytes((index * 13 + ordinal) & 0xff for index in range(length - f.RECORD.size))


def author_case(output, label, floor_page, tail_page, lengths, expected,
                old_bytes=ORDINARY_PACKET_BYTES, epoch=EPOCH, kind=f.UPDATE_TYPE,
                ring_pages=RING_PAGES, absolute_links=False):
    root = output / label
    root.mkdir(exist_ok=True)
    circular = (f.RESTART_PAGES + f.LEGACY_TAIL_PAGES) * f.PAGE_BYTES
    file_bytes = circular + ring_pages * f.PAGE_BYTES
    sequence_bits = f.LSN_BITS + f.OFFSET_SHIFT - file_bytes.bit_length()
    offset_bits = f.LSN_BITS - sequence_bits
    maximum_epoch = (1 << sequence_bits) - 1
    if epoch == 'maximum':
        epoch = maximum_epoch
    floor = circular + floor_page * f.PAGE_BYTES
    tail = circular + tail_page * f.PAGE_BYTES
    tail_lsn = f.lsn_at(tail + f.PAGE_DATA_OFFSET, file_bytes, epoch, sequence_bits)
    floor_epoch = epoch - (floor_page > tail_page)
    floor_lsn = f.lsn_at(floor + f.PAGE_DATA_OFFSET, file_bytes, floor_epoch, sequence_bits)
    restart, _ = f.restart(file_bytes=file_bytes, current=tail_lsn,
        sequence_bits=sequence_bits, clients=[f.client(floor_lsn, tail_lsn)])
    restart, _ = f.protect(restart, f.RESTART_HEADER)
    (root / 'restart.input').write_bytes(restart)
    source = bytearray(file_bytes)
    for page in range(f.RESTART_PAGES):
        start = page * f.PAGE_BYTES
        source[start:start + f.PAGE_BYTES] = restart

    def lsn_at(page, sequence, within=f.PAGE_DATA_OFFSET):
        return (sequence << offset_bits) | ((page + within) >> f.OFFSET_SHIFT)

    def frame_packet(packet, lsn, position, page_epoch, packet_kind):
        pages = []
        used = 0
        while used < len(packet):
            if position == file_bytes:
                position = circular
                page_epoch += 1
            take = min(len(packet) - used, DATA_BYTES)
            end = used + take == len(packet)
            flags = f.RECORD_END if end else 0
            if packet_kind == f.RESTART_TYPE and used == 0:
                flags |= CLIENT_RESTART_PAGE
            logical = bytearray(f.PAGE_BYTES)
            logical[:f.PAGE.size] = f.PAGE.pack(dict(magic=b'RCRD',
                usa_offset=f.PAGE.size, copy_value=(lsn & WIRE_LSN_MASK) if used == 0 else 0,
                flags=flags, page_count=1, page_position=1,
                next_record_offset=f.aligned(f.PAGE_DATA_OFFSET + take) if end
                    else f.PAGE_DATA_OFFSET,
                last_end_lsn=(lsn & WIRE_LSN_MASK) if end else 0))
            logical[f.PAGE_DATA_OFFSET:f.PAGE_DATA_OFFSET + take] = packet[used:used + take]
            pages.append(dict(offset=position, raw=protect(logical)))
            used += take
            last = position
            position += f.PAGE_BYTES
        end_within = f.aligned(f.PAGE_DATA_OFFSET + take)
        if end_within + f.RECORD.size > f.PAGE_BYTES:
            next_page = position
            next_epoch = page_epoch
            if next_page == file_bytes:
                next_page = circular
                next_epoch += 1
            cursor = lsn_at(next_page, next_epoch)
        else:
            cursor = lsn_at(last, page_epoch, end_within)
        return pages, position, page_epoch, cursor

    retained_page = floor
    retained_epoch = floor_epoch
    while retained_page != tail:
        retained_lsn = lsn_at(retained_page, retained_epoch)
        retained_payload = payload_bytes(ORDINARY_PACKET_BYTES, MAX_PACKETS)
        retained_packet = bytes(f.RECORD.pack(dict(lsn=retained_lsn,
            data_bytes=len(retained_payload), client_sequence=f.CLIENT_SEQUENCE,
            type=f.UPDATE_TYPE, transaction=TRANSACTION_KEY))) + retained_payload
        retained_frames, _, _, _ = frame_packet(retained_packet, retained_lsn,
            retained_page, retained_epoch, f.UPDATE_TYPE)
        assert len(retained_frames) == 1
        source[retained_page:retained_page + f.PAGE_BYTES] = retained_frames[0]['raw']
        retained_page += f.PAGE_BYTES
        if retained_page == file_bytes:
            retained_page = circular
            retained_epoch += 1

    old_payload = payload_bytes(old_bytes, MAX_PACKETS)
    old = bytes(f.RECORD.pack(dict(lsn=tail_lsn, data_bytes=len(old_payload),
        client_sequence=f.CLIENT_SEQUENCE, type=f.UPDATE_TYPE, transaction=TRANSACTION_KEY,
        flags=f.MULTI_PAGE if old_bytes > DATA_BYTES else 0))) + old_payload
    old_pages, _, _, next_lsn = frame_packet(old, tail_lsn, tail, epoch, f.UPDATE_TYPE)
    for page in old_pages:
        source[page['offset']:page['offset'] + f.PAGE_BYTES] = page['raw']
    (root / 'source.log').write_bytes(source)
    manifest = dict(name=label, floor=floor_lsn, tail=tail_lsn, next=next_lsn,
        file_bytes=file_bytes, code=expected, records=[], pages=[])
    cursor_offset = (next_lsn & ((1 << offset_bits) - 1)) << f.OFFSET_SHIFT
    position = cursor_offset // f.PAGE_BYTES * f.PAGE_BYTES
    page_epoch = next_lsn >> offset_bits
    if cursor_offset % f.PAGE_BYTES != f.PAGE_DATA_OFFSET:
        position += f.PAGE_BYTES
    previous = 0
    protected_hit = False
    sequence_exhausted = False
    final_cursor = 0
    for ordinal, length in enumerate(lengths):
        if position == file_bytes:
            position = circular
            page_epoch += 1
        lsn = lsn_at(position, page_epoch)
        payload = payload_bytes(length, ordinal)
        flags = f.MULTI_PAGE if length > DATA_BYTES else 0
        absolute = tail_lsn if absolute_links and ordinal == 0 else 0
        prior = previous if ordinal else absolute
        wire_lsn = lsn & WIRE_LSN_MASK
        packet = bytes(f.RECORD.pack(dict(lsn=wire_lsn, previous_lsn=prior,
            undo_next_lsn=prior, data_bytes=len(payload), client_sequence=f.CLIENT_SEQUENCE,
            type=kind, transaction=TRANSACTION_KEY, flags=flags))) + payload
        assert len(packet) == length
        (root / f'payload-{ordinal}.input').write_bytes(payload)
        (root / f'packet-{ordinal}.expected').write_bytes(packet)
        manifest['records'].append(dict(lsn=wire_lsn, bytes=length, type=kind, flags=0,
            previous=ordinal - 1 if ordinal else NO_LINK,
            undo_next=ordinal - 1 if ordinal else NO_LINK,
            previous_lsn=absolute, undo_next_lsn=absolute))
        framed, position, page_epoch, final_cursor = frame_packet(
            packet, lsn, position, page_epoch, kind)
        for page in framed:
            protected_hit |= page['offset'] == floor
            name = f'page-{len(manifest["pages"])}.expected'
            (root / name).write_bytes(page['raw'])
            manifest['pages'].append(dict(offset=page['offset'], packet=ordinal, file=name))
        sequence_exhausted |= page_epoch > maximum_epoch or final_cursor >> offset_bits > maximum_epoch
        previous = wire_lsn
    manifest['next_expected'] = final_cursor if final_cursor <= WIRE_LSN_MASK else 0
    if expected == 'success':
        assert not protected_hit and not sequence_exhausted
    elif expected == 'no-space':
        assert protected_hit
    elif expected == 'range':
        assert sequence_exhausted
    else:
        assert expected == 'unsupported' and kind == f.RESTART_TYPE and lengths[0] > DATA_BYTES
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    rows = [f'{floor_lsn} {tail_lsn} {next_lsn} {file_bytes} {len(lengths)} '
            f'{len(manifest["pages"])} {expected} {manifest["next_expected"]}']
    rows.extend(f'{entry["lsn"]} {entry["bytes"]} {entry["type"]} {entry["flags"]} '
                f'{entry["previous"]} {entry["undo_next"]} {entry["previous_lsn"]} '
                f'{entry["undo_next_lsn"]}' for entry in manifest['records'])
    rows.extend(f'{page["offset"]} {page["packet"]}' for page in manifest['pages'])
    (root / 'case.rows').write_text('\n'.join(rows) + '\n')


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = (
        ('one', 0, 0, [ORDINARY_PACKET_BYTES], 'success', {}),
        ('empty-payload', 0, 0, [f.RECORD.size], 'success', {}),
        ('continuation', 0, 0, [PACKET_BYTES], 'success', {}),
        ('exact-page', 0, 0, [DATA_BYTES], 'success', {}),
        ('one-byte-continuation', 0, 0, [DATA_BYTES + 1], 'success', {}),
        ('restart', 0, 0, [f.RECORD.size + CLIENT_RESTART_COMMON_BYTES], 'success',
            dict(kind=f.RESTART_TYPE)),
        ('spanning-restart', 0, 0, [PACKET_BYTES], 'unsupported', dict(kind=f.RESTART_TYPE)),
        ('wrap', RING_PAGES - 2, RING_PAGES - 2, [PACKET_BYTES, ORDINARY_PACKET_BYTES], 'success', {}),
        ('floor-protected', 4, 0, [PACKET_BYTES, ORDINARY_PACKET_BYTES], 'no-space', {}),
        ('exact-free-window', 5, 0, [PACKET_BYTES, ORDINARY_PACKET_BYTES], 'success', {}),
        ('exhausted-window', 1, 0, [ORDINARY_PACKET_BYTES], 'no-space', {}),
        ('many-transfers', 0, 0, [ORDINARY_PACKET_BYTES] * (RING_PAGES - 1), 'success', {}),
        ('too-many-transfers', 0, 0, [ORDINARY_PACKET_BYTES] * RING_PAGES, 'no-space', {}),
        ('continued-tail', 0, 0, [ORDINARY_PACKET_BYTES], 'success', dict(old_bytes=PACKET_BYTES)),
        ('continued-tail-wrap', RING_PAGES - 2, RING_PAGES - 2, [ORDINARY_PACKET_BYTES],
            'success', dict(old_bytes=PACKET_BYTES)),
        ('continued-tail-floor', 1, RING_PAGES - 2, [ORDINARY_PACKET_BYTES],
            'no-space', dict(old_bytes=PACKET_BYTES)),
        ('cursor-at-start', 0, 0, [ORDINARY_PACKET_BYTES], 'success', dict(old_bytes=DATA_BYTES)),
        ('tail-wrap-exact', RING_PAGES - 2, RING_PAGES - 2, [ORDINARY_PACKET_BYTES],
            'success', dict(old_bytes=2 * DATA_BYTES)),
        ('absolute-retained-links', 0, 0, [ORDINARY_PACKET_BYTES, ORDINARY_PACKET_BYTES],
            'success', dict(absolute_links=True)),
        ('sequence-last-partial', RING_PAGES - 2, RING_PAGES - 2, [ORDINARY_PACKET_BYTES],
            'success', dict(epoch='maximum')),
        ('sequence-complete-end', RING_PAGES - 2, RING_PAGES - 2, [DATA_BYTES],
            'range', dict(epoch='maximum')),
        ('sequence-spanning', RING_PAGES - 2, RING_PAGES - 2, [PACKET_BYTES],
            'range', dict(epoch='maximum')),
        ('sequence-next-packet', RING_PAGES - 2, RING_PAGES - 2,
            [ORDINARY_PACKET_BYTES, ORDINARY_PACKET_BYTES], 'range', dict(epoch='maximum')),
        ('maximum-transfers', 0, 0, [ORDINARY_PACKET_BYTES] * MAX_PACKETS, 'success',
            dict(ring_pages=MAX_PACKETS + 1)),
    )
    for label, floor_page, tail_page, lengths, expected, options in cases:
        author_case(output, label, floor_page, tail_page, lengths, expected, **options)
    (output / 'cases.rows').write_text(''.join(label + '\n' for label, *_ in cases))


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) == 3:
        Path(sys.argv[2]).write_text('independent LFS batch ring page expectations\n')
