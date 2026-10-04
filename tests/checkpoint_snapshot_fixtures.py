#!/usr/bin/env python3
"""Original complete checkpoint graphs and independent membership verdicts."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import logfile_fixtures as w
import logfile_tables_fixtures as t
from logfile_source_fixtures import restart, SMALL_PAGE_BYTES, SMALL_FILE_BYTES
from logfile_checkpoint_fixtures import CLIENT_RESTART, TABLES
from logfile_names_fixtures import entry as name_entry, TERMINATOR, HEADER as NAME_HEADER
from checkpoint_fixtures import make_body, DUMP_OPERATIONS, STORED_UPDATE_BYTES, OPAQUE_HEADER_BYTE, OPEN_COUNT

OPEN, NAMES, DIRTY, TRANSACTIONS = range(len(TABLES))
KINDS = len(TABLES)
SUCCESS, CORRUPT, UNSUPPORTED, INVALID, STALE, RANGE = 0, 2, 3, 9, 10, 11
WORKSPACE_BYTES = 8 * 1024
SUMMARY_PREFIX_VALUES = 6
SUMMARY_TABLE_VALUES = 6
SUMMARY_VALUES = SUMMARY_PREFIX_VALUES + KINDS * SUMMARY_TABLE_VALUES
FIRST_KEY = t.TABLE.size
OPEN_FREE_INDEX = 1
SECOND_ALLOCATED_INDEX = 2
ALL_TABLES = (1 << KINDS) - 1
UNKNOWN_STATE = t.UNKNOWN_STATE


def sha(data):
    return hashlib.sha256(data).hexdigest()


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases, owners = [], {}

    def owner(name, major, extended=False, file_bytes=SMALL_FILE_BYTES):
        log = SMALL_PAGE_BYTES
        circular = (w.RESTART_PAGES + w.LEGACY_TAIL_PAGES) * log
        analysis = w.lsn_at(circular + w.PAGE_DATA_OFFSET, file_bytes)
        anchors = [w.lsn_at(circular + (kind + 1) * log + w.PAGE_DATA_OFFSET, file_bytes)
            for kind in range(KINDS)]
        checkpoint = w.lsn_at(circular + (KINDS + 1) * log + w.PAGE_DATA_OFFSET, file_bytes)
        client, _ = w.client(oldest=analysis, restart=checkpoint)
        header_bytes = w.EXTENDED_RECORD_HEADER_BYTES if extended else w.RECORD.size
        page, _ = restart(clients=[(client, {})], current=checkpoint,
            file_bytes=file_bytes, record_header_bytes=header_bytes)
        page = bytearray(page)
        area = struct.unpack_from('<H', page, w.RESTART_HEADER.offsets['area_offset'])[0]
        w.RESTART_AREA.put(page, 'last_data_bytes', CLIENT_RESTART.size, area)
        journal = bytearray(file_bytes)
        for index in range(w.RESTART_PAGES):
            journal[index * log:(index + 1) * log] = page
        source = name + '.journal'
        (output / source).write_bytes(journal)
        value = dict(source=source, major=major, header_bytes=header_bytes,
            analysis=analysis, anchors=anchors, checkpoint=checkpoint, source_sha256=sha(journal))
        owners[name] = value
        return value

    def bodies(major):
        values = [make_body(kind, major)[0] for kind in range(KINDS)]
        stride = t.OPEN_BASE.size if major == 0 else t.OPEN.size
        first, _ = name_entry(FIRST_KEY, tuple(map(ord, '$I30')))
        second, _ = name_entry(FIRST_KEY + SECOND_ALLOCATED_INDEX * stride, tuple(map(ord, '$I30')))
        values[NAMES] = first + second + TERMINATOR
        return values

    def records(selected, mask, raw_bodies, anchor_override=None):
        fields = dict(major=selected['major'], minor=0, analysis_lsn=selected['analysis'])
        headers = bytes([OPAQUE_HEADER_BYTE]) * (selected['header_bytes'] - w.RECORD.size)
        dumps = []
        for kind, body in enumerate(raw_bodies):
            anchor = selected['anchors'][kind]
            if anchor_override and kind in anchor_override:
                anchor = anchor_override[kind]
            if mask & (1 << kind):
                fields[TABLES[kind] + '_lsn'] = anchor
                fields[TABLES[kind] + '_bytes'] = len(body)
            update = w.UPDATE.pack(dict(redo_operation=DUMP_OPERATIONS[kind],
                redo_offset=STORED_UPDATE_BYTES, redo_bytes=len(body)))
            update += struct.pack('<Q', w.UNUSED_LCN_SLOT) + body
            common = w.RECORD.pack(dict(lsn=anchor, client_sequence=w.CLIENT_SEQUENCE,
                client_index=0, data_bytes=len(update), type=w.UPDATE_TYPE, transaction=w.TRANSACTION))
            dumps.append(bytes(common + headers + update))
        prefix = CLIENT_RESTART.pack(fields)
        checkpoint = w.RECORD.pack(dict(lsn=selected['checkpoint'],
            client_sequence=w.CLIENT_SEQUENCE, data_bytes=len(prefix), type=w.RESTART_TYPE))
        return bytes(checkpoint + headers + prefix), dumps

    def expected(selected, mask, raw_bodies):
        names = 2 if mask & (1 << NAMES) else 0
        dirty_count = 2 if mask & (1 << DIRTY) else 0
        values = [mask, selected['major'], 0, selected['checkpoint'], names, dirty_count]
        for kind in range(KINDS):
            if mask & (1 << kind):
                count = 0 if kind == NAMES else struct.unpack_from('<H', raw_bodies[kind], t.TABLE.offsets['allocated'])[0]
                values += [kind, selected['anchors'][kind], selected['header_bytes'] + STORED_UPDATE_BYTES,
                    len(raw_bodies[kind]), count, names if kind == NAMES else 0]
            else:
                values += [0] * SUMMARY_TABLE_VALUES
        assert len(values) == SUMMARY_VALUES
        return values

    def add(name, selected, mask, raw_bodies=None, code=SUCCESS, capacity=WORKSPACE_BYTES,
            null_workspace=False, anchor_override=None, change_record=None,
            summary_override=None, workspace_prefix=1, name_indices=(0, SECOND_ALLOCATED_INDEX)):
        assert name not in {case['name'] for case in cases}
        raw_bodies = bodies(selected['major']) if raw_bodies is None else raw_bodies
        checkpoint, dumps = records(selected, mask, raw_bodies, anchor_override)
        if change_record:
            kind, field, value = change_record
            raw = bytearray(dumps[kind])
            w.RECORD.put(raw, field, value)
            dumps[kind] = bytes(raw)
        result = expected(selected, mask, raw_bodies) if code == SUCCESS else [0] * SUMMARY_VALUES
        if summary_override is not None:
            result = summary_override
        if not mask & (1 << NAMES) or null_workspace:
            workspace_prefix = 0
        workspace = bytearray(workspace_prefix)
        if code == SUCCESS and mask & (1 << NAMES) and workspace_prefix:
            for index in name_indices:
                workspace[index // w.BITS_PER_BYTE] |= 1 << (index % w.BITS_PER_BYTE)
        (output / (name + '.checkpoint')).write_bytes(checkpoint)
        for kind, dump in enumerate(dumps):
            (output / f'{name}.dump-{kind}').write_bytes(dump)
        (output / (name + '.expected')).write_text(' '.join(map(str, result)) + '\n')
        (output / (name + '.workspace')).write_bytes(workspace)
        cases.append(dict(name=name, source=selected['source'], mask=mask, code=code,
            capacity=capacity, null_workspace=null_workspace, workspace_prefix=workspace_prefix,
            expected=result, checkpoint_sha256=sha(checkpoint), dump_sha256=[sha(d) for d in dumps],
            workspace_sha256=sha(workspace)))

    base = owner('base', 0)
    for major in (0, 1):
        for extended in (False, True):
            selected = owner(f'client-{major}-extended-{int(extended)}', major, extended)
            for mask in range(1 << KINDS):
                has_targets = bool(mask & ((1 << NAMES) | (1 << DIRTY)))
                code = CORRUPT if has_targets and not mask & (1 << OPEN) else SUCCESS
                add(f'client-{major}-extended-{int(extended)}-mask-{mask}', selected, mask, code=code)
            add(f'client-{major}-extended-{int(extended)}-exact-workspace', selected,
                ALL_TABLES, capacity=1)
            add(f'client-{major}-extended-{int(extended)}-short-workspace', selected,
                ALL_TABLES, code=RANGE, capacity=0)
            add(f'client-{major}-extended-{int(extended)}-null-workspace', selected,
                ALL_TABLES, code=INVALID, null_workspace=True)
            stride = t.OPEN_BASE.size if major == 0 else t.OPEN.size
            for label, key in [('header', FIRST_KEY - 1), ('interior', FIRST_KEY + 1),
                              ('free', FIRST_KEY + OPEN_FREE_INDEX * stride),
                              ('past-end', FIRST_KEY + OPEN_COUNT * stride),
                              ('huge', (1 << (w.WORD_BYTES * w.BITS_PER_BYTE)) - 1)]:
                raw = bodies(major)
                malformed = bytearray(raw[NAMES])
                NAME_HEADER.put(malformed, 'target_attribute', key)
                raw[NAMES] = bytes(malformed)
                add(f'client-{major}-extended-{int(extended)}-name-{label}', selected,
                    ALL_TABLES, raw, CORRUPT)
                raw = bodies(major)
                malformed = bytearray(raw[DIRTY])
                layout = t.DIRTY_BASE if major == 0 else t.DIRTY
                layout.put(malformed, 'target_attribute', key, t.TABLE.size)
                raw[DIRTY] = bytes(malformed)
                add(f'client-{major}-extended-{int(extended)}-dirty-{label}', selected,
                    ALL_TABLES, raw, CORRUPT)
            raw = bodies(major)
            first, _ = name_entry(FIRST_KEY, tuple(map(ord, '$I30')))
            duplicate, _ = name_entry(FIRST_KEY, tuple(map(ord, '$OTHER')))
            raw[NAMES] = first + duplicate + TERMINATOR
            add(f'client-{major}-extended-{int(extended)}-duplicate-target', selected,
                ALL_TABLES, raw, CORRUPT)
            raw = bodies(major)
            empty, _ = name_entry(FIRST_KEY, ())
            second, _ = name_entry(FIRST_KEY + SECOND_ALLOCATED_INDEX * stride, (0xd800, 0, 0xdc00))
            raw[NAMES] = empty + second + TERMINATOR
            add(f'client-{major}-extended-{int(extended)}-lossless-names', selected,
                ALL_TABLES, raw)
    raw = bodies(0)
    first, _ = name_entry(FIRST_KEY, tuple(map(ord, '$I30')))
    historical_self = t.TABLE.size + SECOND_ALLOCATED_INDEX * t.OPEN.size
    wrong, _ = name_entry(historical_self, tuple(map(ord, '$I30')))
    raw[NAMES] = first + wrong + TERMINATOR
    add('historical-self-is-not-key', base, ALL_TABLES, raw, CORRUPT)
    add('colliding-dump-lsns', base, ALL_TABLES, code=CORRUPT,
        anchor_override={NAMES: base['anchors'][OPEN]})
    for kind in range(KINDS):
        add(f'foreign-client-kind-{kind}', base, ALL_TABLES, code=STALE,
            change_record=(kind, 'client_index', 1))
    raw = bodies(0)
    raw[NAMES] = TERMINATOR
    value = expected(base, ALL_TABLES, raw)
    value[4] = 0
    value[SUMMARY_PREFIX_VALUES + NAMES * SUMMARY_TABLE_VALUES + SUMMARY_TABLE_VALUES - 1] = 0
    add('empty-names-null-workspace', base, ALL_TABLES, raw, null_workspace=True,
        capacity=0, summary_override=value, workspace_prefix=0)
    add('all-absent-null-workspace', base, 0, null_workspace=True, capacity=0,
        workspace_prefix=0)
    for count in (2 * w.BITS_PER_BYTE,
            ((1 << (w.WORD_BYTES * w.BITS_PER_BYTE)) - 1 - t.TABLE.size) // t.OPEN_BASE.size):
        selected = owner(f'large-open-{count}', 0, file_bytes=w.FILE_BYTES)
        raw = bodies(0)
        raw[OPEN] = make_body(OPEN, 0, count)[0]
        first, _ = name_entry(FIRST_KEY, tuple(map(ord, '$I30')))
        last, _ = name_entry(FIRST_KEY + (count - 1) * t.OPEN_BASE.size, tuple(map(ord, '$I30')))
        raw[NAMES] = first + last + TERMINATOR
        needed = (count + w.BITS_PER_BYTE - 1) // w.BITS_PER_BYTE
        add(f'large-open-{count}-exact-workspace', selected, ALL_TABLES, raw,
            capacity=needed, workspace_prefix=needed, name_indices=(0, count - 1))
        add(f'large-open-{count}-short-workspace', selected, ALL_TABLES, raw, RANGE,
            capacity=needed - 1, workspace_prefix=needed)
    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases, owners=owners), indent=2) + '\n')
    (output / 'cases.tsv').write_text('\n'.join(
        f"{c['name']} {c['source']} {c['code']} {c['capacity']} {int(c['null_workspace'])} {c['workspace_prefix']}"
        for c in cases) + '\n')
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('original-complete-checkpoint-membership\n')
