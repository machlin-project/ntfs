#!/usr/bin/env python3
"""Compare checkpoint transaction diagnostics with the independent seed author."""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys

SOURCE_ARGUMENT, INDEX_ARGUMENT, SEQUENCE_ARGUMENT = range(3)
BITS_PER_BYTE = 8
IDENTITY_BITS = struct.calcsize('<H') * BITS_PER_BYTE
DEFAULT_RECORDS = DEFAULT_TRANSACTIONS = 4096

binary, directory = Path(sys.argv[1]), Path(sys.argv[2])
manifest = json.loads((directory / 'manifest.json').read_text())
profiles = transactions = 0
for case in manifest['cases']:
    # Explicit policy controls are exercised by the C suite. The CLI uses its
    # documented defaults, so those profiles do not have the same oracle.
    if (case['max_records'], case['max_transactions']) != (DEFAULT_RECORDS, DEFAULT_TRANSACTIONS):
        continue
    source = directory / case['path']
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    command = [str(binary), 'checkpoint-transactions', str(source), str(case['index']),
               str(case['sequence'])]
    run = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert run.returncode == (0 if case['code'] == 0 else 1), (command, run.stderr, run.stdout)
    assert not run.stderr, (command, run.stderr)
    actual = json.loads(run.stdout)
    assert actual['scope'] == 'checkpoint-transactions' and actual['code'] == case['code']
    assert actual['history_qualified'] is False and actual['recovery_qualified'] is False
    assert actual['index'] == case['index'] and actual['sequence'] == case['sequence']
    assert actual['checkpoint'] == case['checkpoint'], (case['path'], actual['checkpoint'])
    assert actual['report'] == case['report'], (case['path'], actual['report'], case['report'])
    assert actual['transactions'] == case['views'], case['path']
    assert actual['preparation']['published'] is True
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before == case['source_sha256']
    profiles += 1
    transactions += len(actual['transactions'])

baseline = manifest['cases'][0]
arguments = [str(directory / baseline['path']), str(baseline['index']), str(baseline['sequence'])]
for field, value in ((INDEX_ARGUMENT, '-1'), (INDEX_ARGUMENT, str(1 << IDENTITY_BITS)),
                     (INDEX_ARGUMENT, 'bad'), (SEQUENCE_ARGUMENT, '-1'),
                     (SEQUENCE_ARGUMENT, str(1 << IDENTITY_BITS))):
    changed = list(arguments)
    changed[field] = value
    run = subprocess.run([str(binary), 'checkpoint-transactions', *changed], capture_output=True, timeout=10)
    assert run.returncode == 2 and not run.stdout
for changed in (arguments[:SEQUENCE_ARGUMENT], arguments + ['extra'],
                [str(directory), *arguments[INDEX_ARGUMENT:]],
                [str(directory / 'absent.journal'), *arguments[INDEX_ARGUMENT:]]):
    run = subprocess.run([str(binary), 'checkpoint-transactions', *changed], capture_output=True, timeout=10)
    assert run.returncode == 2 and not run.stdout
print(f'PASS: {profiles} original checkpoint transaction CLI profiles; {transactions} exact seeds/chains')
