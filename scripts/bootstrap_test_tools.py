#!/usr/bin/env python3
"""Build pinned external NTFS test utilities locally; never a product dependency."""
from pathlib import Path
import hashlib
import json
from environment import tool_environment
import subprocess
import sys
import tarfile
import urllib.request

root = Path(__file__).resolve().parents[1]
vendor = root / 'vendor'
vendor.mkdir(exist_ok=True)
version = '2022.10.3'
archive = vendor / f'ntfs-3g_ntfsprogs-{version}.tgz'
url = f'https://tuxera.com/opensource/{archive.name}'
expected_sha256 = 'f20e36ee68074b845e3629e6bced4706ad053804cbaf062fbae60738f854170c'
if not archive.exists():
    with urllib.request.urlopen(url, timeout=60) as source:
        archive.write_bytes(source.read())
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
if digest != expected_sha256:
    raise SystemExit('External test-tool archive checksum mismatch')
source = vendor / f'ntfs-3g_ntfsprogs-{version}'
if not source.exists():
    with tarfile.open(archive) as package:
        package.extractall(vendor, filter='data')
prefix = vendor / 'ntfs-tools'
env = tool_environment()
for key in ('CC', 'CXX', 'CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS', 'SDKROOT'):
    env.pop(key, None)
if sys.platform == 'darwin':
    env['CC'] = subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip()
    env['SDKROOT'] = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
commands = [['./configure', '--disable-ntfs-3g', '--disable-shared', '--enable-static', f'--prefix={prefix}'], ['make', '-j4'], ['make', 'install', f'rootlibdir={prefix / "lib"}']]
logs = root / 'artifacts/test-tools'
logs.mkdir(parents=True, exist_ok=True)
for label, command in zip(('configure', 'build', 'install'), commands):
    with (logs / f'{label}.log').open('w') as log:
        subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
(root / 'artifacts/toolchain.json').write_text(json.dumps({'url': url, 'sha256': digest, 'version': version, 'prefix': str(prefix), 'commands': commands, 'product_dependency': False}, indent=2) + '\n')
print(prefix)
