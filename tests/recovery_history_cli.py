#!/usr/bin/env python3
"""Compare complete published history/lifetimes with original byte and state oracles."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

binary, root = Path(sys.argv[1]), Path(sys.argv[2])
cases = json.loads((root / 'manifest.json').read_text())
passed = 0
for case in cases:
    source = root / case['path']
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    assert before == case['source_sha256']
    run = subprocess.run([str(binary), 'recovery-inputs', str(source), '0', '7'],
        capture_output=True, timeout=30)
    assert not run.stderr, (case['path'], run.stderr)
    result = json.loads(run.stdout)
    assert result['code'] == case['code'], (case['path'], result)
    assert run.returncode == (0 if case['code'] == 0 else 1), case['path']
    assert not result['recovery_qualified'] and not result['writes_enabled']
    report = result['report']
    assert report['read_calls'] == result['checkpoint']['read_calls'] + result['history']['read_calls']
    assert report['read_bytes'] == result['checkpoint']['read_bytes'] + result['history']['read_bytes']
    if case['code'] == 0:
        assert report['published'] and result['history']['complete']
        assert report['records'] == case['records'] and report['history_bytes'] == case['history_bytes']
        assert report['verified_seeds'] == case['verified_seeds']
        assert report['partial_prefixes'] == case['partial_prefixes']
        assert result['transactions'] == case['states'], case['path']
        packets = b''.join(bytes.fromhex(record['bytes_hex']) for record in result['records'])
        assert packets == (root / (case['path'] + '.packets')).read_bytes()
        assert hashlib.sha256(packets).hexdigest() == case['packets_sha256']
        assert [len(bytes.fromhex(r['bytes_hex'])) for r in result['records']] == case['packet_lengths']
        assert result['history']['first_lsn'] == case['first_lsn']
        assert result['history']['completed_end_lsn'] == case['end_lsn']
        assert result['checkpoint']['checkpoint_lsn'] == case['checkpoint_lsn']
        for ordinal, state in enumerate(case['states']):
            members = [r['record']['lsn'] for r in result['records'] if r['epoch'] == ordinal]
            assert len(members) == state['records'] and members[-1] == state['last_lsn']
        for label, state in (('active', 0), ('prepared', 1), ('committed', 2), ('forgotten', 3)):
            assert report[label + '_transactions'] == sum(s['state'] == state for s in case['states'])
        passed += 1
    else:
        assert not report['published'] and report['retained_bytes'] == 0
        assert result['records'] == [] and result['transactions'] == []
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
print(f'{len(cases)} recovery-input CLI profiles, {passed} exact published histories passed')
