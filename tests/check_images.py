#!/usr/bin/env python3
"""Verify byte contents against fixture expectations, including cross-run reads."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

tool, directory = sys.argv[1], Path(sys.argv[2])
manifest = json.loads((directory / 'manifest.json').read_text())
layouts = ('standard.img', 'mft-resident-list.img', 'mft-nonresident-list.img', 'nested-index.img', 'ntfs30.img')
for layout in layouts:
    image = directory / layout
    listing = subprocess.check_output([tool, str(image), 'ls'], text=True).splitlines()
    assert set(listing) == set(manifest), (layout, listing)
    assert len(listing) == len(manifest), 'duplicate directory entries'
    for name, digest in manifest.items():
        data = subprocess.check_output([tool, str(image), 'cat', '/' + name])
        assert hashlib.sha256(data).hexdigest() == digest, (layout, name)
    assert subprocess.check_output([tool, str(image), 'cat', '/HELLO.TXT']) == (directory / 'expected/hello.txt').read_bytes()
    assert subprocess.check_output([tool, str(image), 'cat', '/streamed.txt', 'notes']) == b'alternate payload'
for name, operation in [('torn-mft.img', 'info'), ('overflow.img', 'info'), ('truncated.img', 'info'), ('torn-index.img', 'ls')]:
    result = subprocess.run([tool, str(directory / name), operation], capture_output=True)
    assert result.returncode == 1 and b'corrupt' in result.stderr, (name, result.returncode, result.stderr)
cases = json.loads((directory / 'cases.json').read_text())
for case in cases:
    result = subprocess.run([tool, str(directory / case['image']), *case['arguments']], capture_output=True)
    if case['error']:
        assert result.returncode == 1 and case['error'].encode() in result.stderr, (case['image'], result.returncode, result.stderr)
    else:
        assert result.returncode == 0 and hashlib.sha256(result.stdout).hexdigest() == case['sha256'], (case['image'], result.returncode, result.stderr)
print(f'PASS: {len(manifest)} file hashes across {len(layouts)} filesystem layouts, directory order, case folding, ADS, four damaged images and {len(cases)} format/continuation/rejection cases')
