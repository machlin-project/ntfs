#!/usr/bin/env python3
"""Bounded libFuzzer run over the public read-only NTFS API; no mounts."""
from pathlib import Path
import argparse
import shutil
import subprocess
import sys
from environment import tool_environment

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--seconds', type=int, default=60)
parser.add_argument('--compiler', help='Clang executable with a libFuzzer runtime; defaults to the platform toolchain')
args = parser.parse_args()
if not 1 <= args.seconds <= 3600:
    parser.error('--seconds must be between 1 and 3600')
env = tool_environment()
output = root / 'artifacts/fuzz'
output.mkdir(parents=True, exist_ok=True)
corpus = output / 'corpus'
corpus.mkdir(exist_ok=True)
fixtures = output / 'seeds'
subprocess.run([sys.executable, str(root / 'tests/fixtures.py'), str(fixtures)], cwd=root, env=env, check=True)
for path in fixtures.glob('*.img'):
    shutil.copyfile(path, corpus / path.name)
if sys.platform == 'darwin':
    compiler = args.compiler or subprocess.check_output(['xcrun', '--find', 'clang'], env=env, text=True).strip()
    sdk = ['-isysroot', subprocess.check_output(['xcrun', '--show-sdk-path'], env=env, text=True).strip()]
    resource = Path(subprocess.check_output([compiler, '-print-resource-dir'], env=env, text=True).strip())
    if not (resource / 'lib/darwin/libclang_rt.fuzzer_osx.a').is_file():
        parser.error('Selected Clang has no libFuzzer runtime. Use --compiler with a full LLVM Clang installation.')
else:
    compiler, sdk = args.compiler or 'clang', []
binary = output / 'ntfs-fuzzer'
command = [compiler, *sdk, '-std=c11', '-O1', '-g', '-fsanitize=fuzzer,address,undefined', '-fno-omit-frame-pointer', '-I', str(root / 'include'), *map(str, sorted((root / 'core').glob('*.c'))), str(root / 'tests/fuzz.c'), '-o', str(binary)]
subprocess.run(command, cwd=root, env=env, check=True)
subprocess.run([str(binary), str(corpus), f'-max_total_time={args.seconds}', '-max_len=8388608', '-rss_limit_mb=1024', '-timeout=5', f'-artifact_prefix={output}/'], cwd=root, env=env, check=True)
