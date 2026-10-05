#!/usr/bin/env python3
"""Compare complete CLI transaction packets/reports against the independent author."""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys

SOURCE_ARGUMENT, INDEX_ARGUMENT, SEQUENCE_ARGUMENT, TRANSACTION_ARGUMENT, ROOT_ARGUMENT = range(5)
BITS_PER_BYTE = 8
INDEX_BITS = SEQUENCE_BITS = struct.calcsize('<H') * BITS_PER_BYTE
TRANSACTION_BITS = struct.calcsize('<I') * BITS_PER_BYTE
LSN_BITS = struct.calcsize('<Q') * BITS_PER_BYTE

binary, directory = Path(sys.argv[1]), Path(sys.argv[2])
manifest = json.loads((directory / 'manifest.json').read_text())
packets = 0
for case in manifest['cases']:
    source = directory / case['path']
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    command = [str(binary), 'transaction-records', str(source), str(case['index']),
               str(case['sequence']), str(case['transaction']), str(case['root'])]
    run = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert run.returncode == (0 if case['code'] == 0 else 1), (command, run.stderr)
    assert not run.stderr, (command, run.stderr)
    result = json.loads(run.stdout)
    assert result['scope'] == 'transaction-records' and result['code'] == case['code'], case['path']
    assert result['history_qualified'] is False and result['recovery_qualified'] is False
    assert result['index'] == case['index'] and result['sequence'] == case['sequence']
    assert result['transaction'] == case['transaction'] and result['requested_lsn'] == case['root']
    assert result['chain'] == case['report'], (case['path'], result['chain'], case['report'])
    assert result['preparation']['published'] is True
    assert len(result['records']) == len(case['records'])
    expected = (directory / (case['path'] + '.packets')).read_bytes()
    for actual, oracle in zip(result['records'], case['records']):
        data = bytes.fromhex(actual['bytes_hex'])
        offset, length = oracle['packet_offset'], oracle['bytes']
        assert data == expected[offset:offset + length], case['path']
        assert hashlib.sha256(data).hexdigest() == oracle['sha256']
        assert actual['record'] == oracle['record'], case['path']
        assembly = actual['assembly']
        assert assembly['bytes'] == length and assembly['pages_read'] == oracle['pages']
        assert assembly['copy_pages_read'] == oracle['copies']
        assert assembly['read_calls'] == oracle['read_calls']
        assert assembly['read_bytes'] == oracle['read_bytes']
        packets += 1
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before == case['source_sha256']

baseline = manifest['cases'][0]
arguments = [str(directory / baseline['path']), str(baseline['index']),
             str(baseline['sequence']), str(baseline['transaction']), str(baseline['root'])]
for field, value in ((INDEX_ARGUMENT, '-1'), (INDEX_ARGUMENT, str(1 << INDEX_BITS)),
                     (SEQUENCE_ARGUMENT, str(1 << SEQUENCE_BITS)),
                     (TRANSACTION_ARGUMENT, str(1 << TRANSACTION_BITS)),
                     (ROOT_ARGUMENT, str(1 << LSN_BITS)), (ROOT_ARGUMENT, 'bad')):
    changed = list(arguments)
    changed[field] = value
    run = subprocess.run([str(binary), 'transaction-records', *changed], capture_output=True, timeout=10)
    assert run.returncode == 2 and not run.stdout
for changed in (arguments[:ROOT_ARGUMENT], arguments + ['extra'],
                [str(directory), *arguments[INDEX_ARGUMENT:]],
                [str(directory / 'absent.journal'), *arguments[INDEX_ARGUMENT:]]):
    run = subprocess.run([str(binary), 'transaction-records', *changed], capture_output=True, timeout=10)
    assert run.returncode == 2 and not run.stdout
print(f"PASS: {len(manifest['cases'])} original transaction-chain CLI profiles; {packets} exact packets")
