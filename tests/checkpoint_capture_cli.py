#!/usr/bin/env python3
"""Compare captured checkpoint ownership with independently authored exact packets."""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import tool_environment
from logfile_checkpoint_fixtures import CLIENT_RESTART, TABLES
from logfile_tables_fixtures import TABLE
from logfile_fixtures import UPDATE
from checkpoint_capture_fixtures import NAMES, KINDS

DEADLINE_SECONDS = 20
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_IDENTITY = (1 << 16) - 1


def invoke(binary, *arguments):
    run = subprocess.run([str(binary), 'checkpoint-capture', *map(str, arguments)],
        cwd=ROOT, env=tool_environment(), stdin=subprocess.DEVNULL,
        capture_output=True, timeout=DEADLINE_SECONDS, check=False)
    assert len(run.stdout) <= MAX_OUTPUT_BYTES and len(run.stderr) <= MAX_OUTPUT_BYTES
    return run


def main(binary, directory):
    cases = json.loads((directory / 'manifest.json').read_text())['cases']
    hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in directory.rglob('*') if path.is_file()}
    packets = 0
    for case in cases:
        assert hashes[directory / case['path']] == case['source_sha256']
        run = invoke(binary, directory / case['path'], case['client_index'], case['client_sequence'])
        assert not run.stderr and run.returncode == (0 if case['code'] == 0 else 1), (case['path'], run.stderr)
        result = json.loads(run.stdout)
        assert result['schema_version'] == 1 and result['scope'] == 'checkpoint-capture'
        assert result['index'] == case['client_index'] and result['sequence'] == case['client_sequence']
        assert result['code'] == case['code'], (case['path'], result)
        assert result['history_qualified'] is False and result['recovery_qualified'] is False
        assert result['acquisition'] == case['report'], (case['path'], result['acquisition'], case['report'])
        assert result['preparation']['published'] is True
        if case['code'] != 0:
            assert result['capture'] is None
            continue
        capture = result['capture']
        expected = []
        for packet in case['packets']:
            raw = (directory / packet['path']).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == packet['sha256']
            expected.append(raw)
        raw = bytes.fromhex(capture['bytes_hex'])
        assert raw == b''.join(expected) and capture['bytes'] == len(raw)
        assert capture['checkpoint'] == dict(offset=0, length=len(expected[0]))
        assert capture['client_index'] == case['client_index']
        assert capture['client_sequence'] == case['client_sequence']
        assert capture['client']['sequence'] == case['client_sequence']
        assert capture['client']['restart_lsn'] == case['report']['checkpoint_lsn']
        assert capture['client']['name_utf16'] == list(map(ord, 'NTFS'))
        payload = expected[0][case['header_bytes']:]
        prefix = {name: struct.unpack_from('<' + form, payload, CLIENT_RESTART.offsets[name])[0]
            for name, form in CLIENT_RESTART.fields}
        client = capture['restart']
        assert {name: client[name] for name in ('major', 'minor', 'analysis_lsn')} == {
            name: prefix[name] for name in ('major', 'minor', 'analysis_lsn')}
        assert client['extension'] == dict(offset=CLIENT_RESTART.size,
            length=len(payload) - CLIENT_RESTART.size)
        for name in TABLES:
            assert client[name] == dict(lsn=prefix[name + '_lsn'], bytes=prefix[name + '_bytes'])
        snapshot = capture['snapshot']
        assert {name: snapshot[name] for name in ('present_mask', 'client_major', 'client_minor',
            'checkpoint_lsn', 'named_attributes', 'dirty_pages')} == dict(
            present_mask=case['present_mask'], client_major=case['client_major'], client_minor=0,
            checkpoint_lsn=case['report']['checkpoint_lsn'],
            named_attributes=case['named_attributes'], dirty_pages=case['dirty_pages'])
        offset, ordinal = len(expected[0]), 1
        for kind in range(KINDS):
            table = snapshot['tables'][kind]
            if not case['present_mask'] & (1 << kind):
                assert capture['dumps'][kind] == dict(offset=0, length=0)
                assert table['checkpoint_lsn'] == 0 and table['table_lsn'] == 0
                assert table['body'] == dict(offset=0, length=0)
                continue
            packet = expected[ordinal]
            assert capture['dumps'][kind] == dict(offset=offset, length=len(packet))
            assert table['kind'] == kind and table['client_major'] == case['client_major']
            assert table['checkpoint_lsn'] == case['report']['checkpoint_lsn']
            assert table['table_lsn'] == case['packets'][ordinal]['lsn']
            update = packet[case['header_bytes']:]
            redo = struct.unpack_from('<H', update, UPDATE.offsets['redo_offset'])[0]
            size = struct.unpack_from('<H', update, UPDATE.offsets['redo_bytes'])[0]
            assert table['body'] == dict(offset=case['header_bytes'] + redo, length=size)
            body = update[redo:redo + size]
            if kind == NAMES:
                assert table['names']['entry_count'] == case['named_attributes']
            else:
                header = {name: struct.unpack_from('<' + form, body, TABLE.offsets[name])[0]
                    for name, form in TABLE.fields if not form.endswith('s')}
                assert table['table'] == dict(entry_bytes=header['entry_bytes'],
                    entry_count=header['entries'], allocated_count=header['allocated'],
                    free_goal=header['free_goal'], first_free=header['first_free'],
                    last_free=header['last_free'], entries=dict(offset=TABLE.size,
                        length=header['entry_bytes'] * header['entries']))
            offset += len(packet)
            ordinal += 1
        assert offset == len(raw) and ordinal == len(expected)
        packets += len(expected)
    source = directory / cases[0]['path']
    for arguments in ((), (source,), (source, '0'), (source, '0', '0', 'extra'),
        (directory, '0', '0'), (directory / 'missing', '0', '0'),
        *((source, invalid, '0') for invalid in ('', '-1', '+1', '1x', str(MAX_IDENTITY + 1))),
        *((source, '0', invalid) for invalid in ('', '-1', '+1', '1x', str(MAX_IDENTITY + 1)))):
        run = invoke(binary, *arguments)
        assert run.returncode == 2 and not run.stdout
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == digest for path, digest in hashes.items())
    print(f'PASS: {len(cases)} complete checkpoint acquisition/refusal reports, '
        f'{packets} exact owned packets and snapshot tables, immutable source; native recovery remains separate')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
