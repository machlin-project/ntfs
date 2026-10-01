#!/usr/bin/env python3
"""Independent mkntfs/ntfscp images; compare our reads with ntfscat and inputs."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import time

BYTE_VALUES = 256
LARGE_FILE_BYTES = 2 * 1024 * 1024 + BYTE_VALUES
INDEX_EXTRA_FILES = 96
IMAGE_BYTES = 64 * 1024 * 1024
GEOMETRIES = ((512, 1024), (512, 4096), (4096, 4096), (512, 65536))

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--tools', type=Path, default=root / 'vendor/ntfs-tools')
parser.add_argument('--reader', type=Path, default=root / '.build/ntfs-inspect')
parser.add_argument('--output', type=Path, default=root / 'artifacts/interoperability')
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
tools = {name: args.tools / ('sbin' if name in ('mkntfs', 'ntfscp') else 'bin') / name for name in ('mkntfs', 'ntfscp', 'ntfscat', 'ntfsls')}
for path in (*tools.values(), args.reader):
    if not path.is_file():
        raise SystemExit(f'Required executable missing: {path}')
report = {'profiles': [], 'status': 'running', 'windows_acceptance': 'not run'}
report_path = args.output / 'report.json'
report_path.write_text(json.dumps(report, indent=2) + '\n')
payloads = {'empty.txt': b'', 'small.txt': b'Independent NTFS fixture\n',
            'large.bin': bytes(range(BYTE_VALUES)) * (LARGE_FILE_BYTES // BYTE_VALUES),
            'café-Ω.txt': 'Names and content: Україна\n'.encode()}
# Enough names to force external index allocation across all geometries.
payloads.update({f'entry-{n:03}.txt': f'file {n}\n'.encode() for n in range(INDEX_EXTRA_FILES)})
for name, content in payloads.items():
    (args.output / name).write_bytes(content)
(args.output / 'ads.bin').write_bytes(b'Named NTFS stream\x00with binary data')

with (args.output / 'commands.log').open('w') as log:
    def run(command, capture=False):
        log.write(' '.join(map(str, command)) + '\n')
        log.flush()
        return subprocess.run(list(map(str, command)), check=True, stdout=subprocess.PIPE if capture else log, stderr=log).stdout

    for sector, cluster in GEOMETRIES:
        image = args.output / f'ntfs-s{sector}-c{cluster}.img'
        if image.exists():
            raise SystemExit(f'Refusing to overwrite prior image: {image}. Choose a new --output.')
        started = time.monotonic()
        with image.open('xb') as volume:
            volume.truncate(IMAGE_BYTES)
        run([tools['mkntfs'], '-F', '-Q', '-s', sector, '-c', cluster, '-L', 'Machlin reference', image])
        for name in payloads:
            run([tools['ntfscp'], '-f', image, args.output / name, '/' + name])
        run([tools['ntfscp'], '-f', '-N', 'notes', image, args.output / 'ads.bin', '/small.txt'])
        before = hashlib.sha256(image.read_bytes()).hexdigest()
        info = run([args.reader, image, 'info'], True).decode()
        names = run([args.reader, image, 'ls'], True).decode().splitlines()
        assert set(payloads).issubset(names) and len(names) == len(set(names)), names
        for name, expected in payloads.items():
            actual = run([args.reader, image, 'cat', '/' + name], True)
            oracle = run([tools['ntfscat'], image, '/' + name], True)
            assert actual == oracle == expected, (sector, cluster, name)
        assert run([args.reader, image, 'cat', '/SMALL.TXT'], True) == payloads['small.txt']
        assert run([args.reader, image, 'cat', '/small.txt', 'notes'], True) == (args.output / 'ads.bin').read_bytes()
        after = hashlib.sha256(image.read_bytes()).hexdigest()
        assert before == after, 'read-only implementation changed the image'
        report['profiles'].append({'sector': sector, 'cluster': cluster, 'files': len(payloads), 'sha256': after, 'seconds': round(time.monotonic() - started, 3), 'info': info, 'result': 'pass'})
        report_path.write_text(json.dumps(report, indent=2) + '\n')
report['status'] = 'pass'
report_path.write_text(json.dumps(report, indent=2) + '\n')
print(f'PASS: {len(report["profiles"])} independent geometries, {len(payloads)} files each, ADS, case folding, byte-for-byte oracle and unchanged images')
