#!/usr/bin/env python3
"""Bounded libFuzzer run over the public read-only NTFS API; no mounts."""
from pathlib import Path
import argparse
import shutil
import subprocess
import sys
from environment import tool_environment

DEFAULT_SECONDS = 60
MAX_SECONDS = 3600
# All fixture payloads fit in one MiB. Author that physical geometry directly:
# libFuzzer retains whole inputs, so unused disk tails amplify corpus memory.
MAX_INPUT_BYTES = 1024 * 1024
RSS_LIMIT_MIB = 1024
INPUT_TIMEOUT_SECONDS = 5

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--seconds', type=int, default=DEFAULT_SECONDS)
parser.add_argument('--compiler', help='Clang executable with a libFuzzer runtime; defaults to the platform toolchain')
args = parser.parse_args()
if not 1 <= args.seconds <= MAX_SECONDS:
    parser.error(f'--seconds must be between 1 and {MAX_SECONDS}')
env = tool_environment()
output = root / 'artifacts/fuzz'
output.mkdir(parents=True, exist_ok=True)
corpus = output / f'corpus-{MAX_INPUT_BYTES}'
corpus.mkdir(exist_ok=True)
fixtures = output / f'seeds-{MAX_INPUT_BYTES}'
subprocess.run([sys.executable, str(root / 'tests/fixtures.py'), str(fixtures), '--image-bytes', str(MAX_INPUT_BYTES)], cwd=root, env=env, check=True)
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
subprocess.run([str(binary), str(corpus), f'-max_total_time={args.seconds}', f'-max_len={MAX_INPUT_BYTES}', f'-rss_limit_mb={RSS_LIMIT_MIB}', f'-timeout={INPUT_TIMEOUT_SECONDS}', f'-artifact_prefix={output}/'], cwd=root, env=env, check=True)
