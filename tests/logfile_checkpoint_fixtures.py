#!/usr/bin/env python3
"""Author original NTFS client restart-prefix bytes and independent field oracles."""
from pathlib import Path
import json
import sys

from logfile_fixtures import Layout

CLIENT_RESTART = Layout((('major', 'I'), ('minor', 'I'), ('analysis_lsn', 'Q'),
    ('open_attributes_lsn', 'Q'), ('attribute_names_lsn', 'Q'),
    ('dirty_pages_lsn', 'Q'), ('transactions_lsn', 'Q'),
    ('open_attributes_bytes', 'I'), ('attribute_names_bytes', 'I'),
    ('dirty_pages_bytes', 'I'), ('transactions_bytes', 'I')))
TABLES = ('open_attributes', 'attribute_names', 'dirty_pages', 'transactions')
CLIENT_BASE_MAJOR = 0
CLIENT_ATTRIBUTES_MAJOR = 1
CLIENT_MINOR = 0
UNKNOWN_MAJOR = 2
UNKNOWN_MINOR = 1
UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1
MAX_PACKET_BYTES = 1024 * 1024
EXTENDED_RESTART_BYTES = 112
OPAQUE_BYTE = 0x7e
SUCCESS = 0
CORRUPT = 2
UNSUPPORTED = 3
RANGE = 11
RESULTS = {SUCCESS: 'success', CORRUPT: 'corrupt metadata',
           UNSUPPORTED: 'unsupported format', RANGE: 'resource limit'}


def report(values, size, code):
    fields = values if code == SUCCESS else {}
    value = dict(schema_version=1, scope='client-restart', code=code,
                 result=RESULTS[code], recovery_qualified=False,
                 major=fields.get('major', 0), minor=fields.get('minor', 0),
                 analysis_lsn=fields.get('analysis_lsn', 0))
    for table in TABLES:
        value[table] = dict(lsn=fields.get(table + '_lsn', 0),
                            bytes=fields.get(table + '_bytes', 0))
    value['extension'] = dict(offset=CLIENT_RESTART.size if code == SUCCESS else 0,
                              length=size - CLIENT_RESTART.size if code == SUCCESS else 0)
    return value


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases = []

    def add(name, values, code=SUCCESS, *, size=CLIENT_RESTART.size, data=None):
        payload = CLIENT_RESTART.pack(values)
        if data is None:
            if size >= len(payload):
                payload.extend(bytes([OPAQUE_BYTE]) * (size - len(payload)))
            else:
                payload = payload[:size]
        else:
            payload = data
        path = name + '.payload'
        (output / path).write_bytes(payload)
        expected = report(values, len(payload), code)
        case = dict(path=path, bytes=len(payload), code=code, expected=expected,
                    transport=len(payload) == 0 or len(payload) > MAX_PACKET_BYTES)
        cases.append(case)

    base = dict(major=CLIENT_BASE_MAJOR, minor=CLIENT_MINOR)
    attributes = dict(major=CLIENT_ATTRIBUTES_MAJOR, minor=CLIENT_MINOR)
    fields = dict(base, analysis_lsn=0x123456789abcdef0,
                  open_attributes_lsn=0x1000000000000100, open_attributes_bytes=17,
                  attribute_names_lsn=0x2000000000000200, attribute_names_bytes=33,
                  dirty_pages_lsn=0x3000000000000300, dirty_pages_bytes=65,
                  transactions_lsn=0x4000000000000400, transactions_bytes=129)
    raw_boundaries = dict(attributes, analysis_lsn=UINT64_MAX,
                          open_attributes_lsn=0, open_attributes_bytes=UINT32_MAX,
                          attribute_names_lsn=UINT64_MAX, attribute_names_bytes=0,
                          dirty_pages_lsn=UINT64_MAX, dirty_pages_bytes=UINT32_MAX,
                          transactions_lsn=1, transactions_bytes=1)
    add('base-empty', base)
    add('attributes-empty', attributes)
    add('base-fields', fields)
    add('raw-reference-boundaries', raw_boundaries)
    add('attributes-extended', dict(fields, major=CLIENT_ATTRIBUTES_MAJOR), size=EXTENDED_RESTART_BYTES)
    add('base-opaque-byte', fields, size=CLIENT_RESTART.size + 1)
    add('maximum-payload', dict(fields, major=CLIENT_ATTRIBUTES_MAJOR), size=MAX_PACKET_BYTES)
    add('unknown-major', dict(fields, major=UNKNOWN_MAJOR), UNSUPPORTED)
    add('maximum-major', dict(fields, major=UINT32_MAX), UNSUPPORTED)
    add('base-unknown-minor', dict(fields, minor=UNKNOWN_MINOR), UNSUPPORTED)
    add('attributes-unknown-minor', dict(attributes, minor=UNKNOWN_MINOR), UNSUPPORTED)
    add('maximum-minor', dict(attributes, minor=UINT32_MAX), UNSUPPORTED)
    add('oversized-payload', fields, RANGE, size=MAX_PACKET_BYTES + 1)
    for size in range(CLIENT_RESTART.size):
        add(f'truncated-{size:02}', fields, CORRUPT, size=size)
    (output / 'cases.json').write_text(json.dumps(cases, indent=2) + '\n')
    lines = []
    for case in cases:
        value = case['expected']
        row = [case['path'], str(case['code']), str(value['major']), str(value['minor']),
               str(value['analysis_lsn'])]
        for table in TABLES:
            row.extend((str(value[table]['lsn']), str(value[table]['bytes'])))
        row.extend((str(value['extension']['offset']), str(value['extension']['length'])))
        lines.append('\t'.join(row))
    (output / 'cases.tsv').write_text('\n'.join(lines) + '\n')
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('original NTFS client restart-prefix fixtures\n')
