#!/usr/bin/env python3
"""Author native checkpoint table/entry bytes from independent named fields."""
from pathlib import Path
import hashlib
import itertools
import json
import struct
import sys

from logfile_fixtures import Layout

TABLE = Layout((('entry_bytes', 'H'), ('entries', 'H'), ('allocated', 'H'),
    ('reserved', '6s'), ('free_goal', 'I'), ('first_free', 'I'), ('last_free', 'I')))
OPEN_BASE = Layout((('allocated', 'I'), ('attribute_offset', 'I'), ('reference', 'Q'),
    ('open_lsn', 'Q'), ('reserved', '4s'), ('attribute_type', 'I'),
    ('name_pointer', 'Q'), ('index_buffer_bytes', 'I')))
OPEN = Layout((('allocated', 'I'), ('index_buffer_bytes', 'I'), ('attribute_type', 'I'),
    ('dirty_pages', 'B'), ('reserved', '3s'), ('reference', 'Q'), ('open_lsn', 'Q'),
    ('name_pointer', 'Q')))
DIRTY_BASE = Layout((('allocated', 'I'), ('target_attribute', 'I'), ('transfer_bytes', 'I'),
    ('lcns', 'I'), ('reserved', '4s'), ('vcn', 'Q'), ('oldest_lsn', 'Q')))
DIRTY = Layout((('allocated', 'I'), ('target_attribute', 'I'), ('transfer_bytes', 'I'),
    ('lcns', 'I'), ('vcn', 'Q'), ('oldest_lsn', 'Q')))
TRANSACTION = Layout((('allocated', 'I'), ('state', 'I'), ('first_lsn', 'Q'),
    ('previous_lsn', 'Q'), ('undo_next_lsn', 'Q'), ('undo_records', 'I'), ('undo_bytes', 'I')))
LINK = struct.Struct('<I')
LCN = struct.Struct('<Q')
BITS_PER_BYTE = 8
ALLOCATED = (1 << (LINK.size * BITS_PER_BYTE)) - 1
MAX_ENTRIES = (1 << (struct.calcsize('<H') * BITS_PER_BYTE)) - 1
MAX_BYTES = 1024 * 1024
SUMMARY_VALUES = 12
SMALL_TOPOLOGY_ENTRIES = 4
TABLE_SUMMARY_FREE_GOAL = 3
DIRTY_SUMMARY_UNUSED_BYTES = 8
MFT_SEQUENCE_SHIFT = 48
TABLE_KIND, OPEN_KIND, DIRTY_KIND, TRANSACTION_KIND = range(4)
SUCCESS, CORRUPT, UNSUPPORTED, NOT_FOUND, RANGE = 0, 2, 3, 6, 11
REFERENCE = (7 << MFT_SEQUENCE_SHIFT) | 137
OPEN_LSN = 0x23456789012340
FIRST_LSN = 0x12345678902040
PREVIOUS_LSN = 0x12345678903048
UNDO_LSN = 0x12345678902850
ATTRIBUTE_TYPE = 0xa0
INDEX_BYTES = 4096
LEGACY_ATTRIBUTE_OFFSET = 104
TARGET_ATTRIBUTE = TABLE.size + OPEN.size
TRANSFER_BYTES = 12288
TARGET_VCN = 17
LCNS = (86129, 4, 170023)
OPAQUE_POINTER = 0xffff812345678900
STALE_BYTE = 0xed
UNKNOWN_STATE = 4
UNDO_RECORDS = 31
UNDO_BYTES = 17280


def summary(*values):
    assert len(values) <= SUMMARY_VALUES
    return (*(int(value) for value in values), *([0] * (SUMMARY_VALUES - len(values))))


def table(entry_bytes, count, free_order):
    offsets = [TABLE.size + ordinal * entry_bytes for ordinal in range(count)]
    free = [offsets[ordinal] for ordinal in free_order]
    data = TABLE.pack(dict(entry_bytes=entry_bytes, entries=count,
        allocated=count - len(free), free_goal=ALLOCATED,
        first_free=free[0] if free else 0, last_free=free[-1] if free else 0))
    data += bytes([STALE_BYTE]) * (entry_bytes * count)
    for offset in offsets:
        LINK.pack_into(data, offset, ALLOCATED)
    for ordinal, offset in enumerate(free):
        LINK.pack_into(data, offset, free[ordinal + 1] if ordinal + 1 < len(free) else 0)
    expected = summary(entry_bytes, count, count - len(free), ALLOCATED,
        free[0] if free else 0, free[-1] if free else 0, TABLE.size, count * entry_bytes)
    return data, expected


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []

    def add(name, kind, data, code=SUCCESS, major=0, minor=0, expected=None):
        expected = summary() if expected is None else expected
        assert len(expected) == SUMMARY_VALUES
        if code != SUCCESS:
            assert not any(expected)
        raw = bytes(data)
        (output / (name + '.input')).write_bytes(raw)
        (output / (name + '.expected')).write_text(' '.join(map(str, expected)) + '\n')
        cases.append(dict(name=name, kind=kind, major=major, minor=minor, code=code,
            bytes=len(raw), input_sha256=hashlib.sha256(raw).hexdigest(), expected=expected))

    # Every free subset/order is constructed directly, independently of a decoder.
    for count in range(SMALL_TOPOLOGY_ENTRIES + 1):
        for free_count in range(count + 1):
            for order in itertools.permutations(range(count), free_count):
                data, expected = table(TRANSACTION.size, count, order)
                order_name = '-'.join(map(str, order)) if order else 'allocated'
                add(f'topology-{count}-{order_name}', TABLE_KIND, data, expected=expected)
    for entry_bytes in (LINK.size, LINK.size + 1, OPEN_BASE.size, 1000):
        data, expected = table(entry_bytes, SMALL_TOPOLOGY_ENTRIES, (3, 0, 2))
        add(f'entry-size-{entry_bytes}', TABLE_KIND, data, expected=expected)
    for count, order in ((MAX_ENTRIES, ()),
                         (MAX_ENTRIES, tuple(reversed(range(MAX_ENTRIES))))):
        data, expected = table(LINK.size, count, order)
        suffix = 'free-reverse' if order else 'allocated'
        add('maximum-entries-' + suffix, TABLE_KIND, data, expected=expected)
    long_cycle = bytearray(data)
    LINK.pack_into(long_cycle, TABLE.size, TABLE.size)
    add('maximum-entries-final-cycle', TABLE_KIND, long_cycle, CORRUPT)

    data, expected = table(TRANSACTION.size, SMALL_TOPOLOGY_ENTRIES, (3, 0, 2))
    offsets = [TABLE.size + ordinal * TRANSACTION.size for ordinal in range(SMALL_TOPOLOGY_ENTRIES)]
    for length in range(TABLE.size):
        add(f'table-short-prefix-{length}', TABLE_KIND, data[:length], CORRUPT)
    add('table-truncated-entry', TABLE_KIND, data[:-1], CORRUPT)
    add('table-extra-byte', TABLE_KIND, data + b'\x00', CORRUPT)
    add('table-policy-limit', TABLE_KIND, bytes(MAX_BYTES + 1), RANGE)
    for name, field, value in (
            ('entry-size-zero', 'entry_bytes', 0),
            ('entry-size-short-link', 'entry_bytes', LINK.size - 1),
            ('entry-count-extra', 'entries', SMALL_TOPOLOGY_ENTRIES + 1),
            ('entry-count-short', 'entries', SMALL_TOPOLOGY_ENTRIES - 1),
            ('allocated-count-wrong', 'allocated', 0),
            ('allocated-count-overflow', 'allocated', SMALL_TOPOLOGY_ENTRIES + 1),
            ('first-in-header', 'first_free', TABLE.size - LINK.size),
            ('first-unaligned', 'first_free', offsets[0] + 1),
            ('first-past-end', 'first_free', len(data)),
            ('first-allocated', 'first_free', offsets[1]),
            ('first-absent', 'first_free', 0),
            ('last-in-header', 'last_free', TABLE.size - LINK.size),
            ('last-unaligned', 'last_free', offsets[0] + 1),
            ('last-past-end', 'last_free', len(data)),
            ('last-mismatch', 'last_free', offsets[3]),
            ('last-absent', 'last_free', 0)):
        changed = bytearray(data)
        TABLE.put(changed, field, value)
        add(name, TABLE_KIND, changed, CORRUPT)
    for name, ordinal, value in (
            ('link-in-header', 0, TABLE.size - LINK.size),
            ('link-unaligned', 0, offsets[2] + 1),
            ('link-past-end', 0, len(data)),
            ('link-maximum-offset', 0, ALLOCATED - 1),
            ('link-to-allocated', 0, offsets[1]),
            ('link-self-cycle', 0, offsets[0]),
            ('link-tail-cycle', 2, offsets[3]),
            ('link-lost-entry', 0, 0),
            ('disconnected-free-entry', 1, 0)):
        changed = bytearray(data)
        LINK.pack_into(changed, offsets[ordinal], value)
        add(name, TABLE_KIND, changed, CORRUPT)
    for goal in (0, TABLE.size, ALLOCATED - 1):
        changed = bytearray(data)
        TABLE.put(changed, 'free_goal', goal)
        values = list(expected)
        values[TABLE_SUMMARY_FREE_GOAL] = goal
        add(f'opaque-free-goal-{goal}', TABLE_KIND, changed, expected=values)

    for major, layout in ((0, OPEN_BASE), (1, OPEN)):
        fields = dict(allocated=ALLOCATED, reference=REFERENCE, open_lsn=OPEN_LSN,
            attribute_type=ATTRIBUTE_TYPE, index_buffer_bytes=INDEX_BYTES,
            attribute_offset=LEGACY_ATTRIBUTE_OFFSET, name_pointer=OPAQUE_POINTER,
            dirty_pages=1)
        data = layout.pack(fields)
        expected = summary(REFERENCE, OPEN_LSN, ATTRIBUTE_TYPE, INDEX_BYTES,
            LEGACY_ATTRIBUTE_OFFSET if major == 0 else 0, major == 1, major == 1)
        add(f'open-client-{major}', OPEN_KIND, data, major=major, expected=expected)
        for length in range(layout.size):
            add(f'open-client-{major}-prefix-{length}', OPEN_KIND, data[:length], CORRUPT, major=major)
        add(f'open-client-{major}-extra', OPEN_KIND, data + b'\x00', CORRUPT, major=major)
        free = bytearray([STALE_BYTE] * layout.size)
        layout.put(free, 'allocated', 0)
        add(f'open-client-{major}-free-stale', OPEN_KIND, free, NOT_FOUND, major=major)
        add(f'open-client-{major}-unknown-minor', OPEN_KIND, data, UNSUPPORTED, major=major, minor=1)
        if major == 1:
            layout.put(data, 'dirty_pages', 0)
            add('open-client-1-clean', OPEN_KIND, data, major=major,
                expected=summary(REFERENCE, OPEN_LSN, ATTRIBUTE_TYPE, INDEX_BYTES, 0, True, False))
            for dirty_byte in (2, (1 << BITS_PER_BYTE) - 1):
                layout.put(data, 'dirty_pages', dirty_byte)
                add(f'open-client-1-dirty-byte-{dirty_byte}', OPEN_KIND, data, major=major,
                    expected=summary(REFERENCE, OPEN_LSN, ATTRIBUTE_TYPE, INDEX_BYTES,
                        0, True, dirty_byte))
    add('open-unknown-major', OPEN_KIND, data, UNSUPPORTED, major=2)

    for major, layout in ((0, DIRTY_BASE), (1, DIRTY)):
        fields = dict(allocated=ALLOCATED, target_attribute=TARGET_ATTRIBUTE,
            transfer_bytes=TRANSFER_BYTES, lcns=len(LCNS), vcn=TARGET_VCN, oldest_lsn=FIRST_LSN)
        data = layout.pack(fields) + b''.join(LCN.pack(lcn) for lcn in LCNS)
        expected = summary(TARGET_VCN, FIRST_LSN, TARGET_ATTRIBUTE, TRANSFER_BYTES, len(LCNS),
            layout.size, len(LCNS) * LCN.size, len(data), 0)
        add(f'dirty-client-{major}', DIRTY_KIND, data, major=major, expected=expected)
        for length in range(layout.size):
            add(f'dirty-client-{major}-prefix-{length}', DIRTY_KIND, data[:length], CORRUPT, major=major)
        add(f'dirty-client-{major}-incomplete-lcn', DIRTY_KIND, data[:-1], CORRUPT, major=major)
        add(f'dirty-client-{major}-vector-short', DIRTY_KIND, data[:-LCN.size], CORRUPT, major=major)
        over = bytearray(data)
        layout.put(over, 'lcns', ALLOCATED)
        add(f'dirty-client-{major}-vector-overflow', DIRTY_KIND, over, CORRUPT, major=major)
        extra = data + LCN.pack(OPAQUE_POINTER)
        extra_expected = list(expected)
        extra_expected[DIRTY_SUMMARY_UNUSED_BYTES] = LCN.size
        add(f'dirty-client-{major}-unused-capacity', DIRTY_KIND, extra, major=major, expected=extra_expected)
        no_vector = layout.pack(dict(fields, lcns=0))
        add(f'dirty-client-{major}-empty-vector', DIRTY_KIND, no_vector, major=major,
            expected=summary(TARGET_VCN, FIRST_LSN, TARGET_ATTRIBUTE, TRANSFER_BYTES, 0,
                layout.size, 0, layout.size, 0))
        free = bytearray([STALE_BYTE] * len(data))
        layout.put(free, 'allocated', 0)
        add(f'dirty-client-{major}-free-stale', DIRTY_KIND, free, NOT_FOUND, major=major)
        add(f'dirty-client-{major}-unknown-minor', DIRTY_KIND, data, UNSUPPORTED, major=major, minor=1)
    add('dirty-unknown-major', DIRTY_KIND, data, UNSUPPORTED, major=2)
    add('dirty-policy-limit', DIRTY_KIND, bytes(MAX_BYTES + 1), RANGE)

    for state in range(UNKNOWN_STATE):
        data = TRANSACTION.pack(dict(allocated=ALLOCATED, state=state,
            first_lsn=FIRST_LSN, previous_lsn=PREVIOUS_LSN, undo_next_lsn=UNDO_LSN,
            undo_records=UNDO_RECORDS, undo_bytes=UNDO_BYTES))
        add(f'transaction-state-{state}', TRANSACTION_KIND, data,
            expected=summary(FIRST_LSN, PREVIOUS_LSN, UNDO_LSN, UNDO_RECORDS, UNDO_BYTES, state))
    for length in range(TRANSACTION.size):
        add(f'transaction-short-prefix-{length}', TRANSACTION_KIND, data[:length], CORRUPT)
    add('transaction-extra-byte', TRANSACTION_KIND, data + b'\x00', CORRUPT)
    TRANSACTION.put(data, 'state', UNKNOWN_STATE)
    add('transaction-unknown-state', TRANSACTION_KIND, data, UNSUPPORTED)
    free = bytearray([STALE_BYTE] * TRANSACTION.size)
    TRANSACTION.put(free, 'allocated', 0)
    add('transaction-free-stale', TRANSACTION_KIND, free, NOT_FOUND)

    (output / 'cases.tsv').write_text(''.join(
        f'{row["name"]} {row["kind"]} {row["major"]} {row["minor"]} {row["code"]}\n' for row in cases))
    (output / 'manifest.json').write_text(json.dumps(dict(
        scope='original checkpoint framing vectors; no selected-history/recovery acceptance',
        cases=cases), indent=2) + '\n')
    return len(cases)


if __name__ == '__main__':
    count = author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('checkpoint table fixtures\n')
    print(f'Authored {count} native checkpoint table and entry vectors')
