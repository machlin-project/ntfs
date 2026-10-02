#!/usr/bin/env python3
"""Bounded image and parser libFuzzer campaigns; immutable files, no mounts."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from environment import tool_environment
from fuzz_seeds import generate

DEFAULT_SECONDS = 60
MAX_SECONDS = 3600
# All fixture payloads fit in one MiB. Author that physical geometry directly:
# libFuzzer retains whole inputs, so unused disk tails amplify corpus memory.
MAX_INPUT_BYTES = 1024 * 1024
RSS_LIMIT_MIB = 1024
INPUT_TIMEOUT_SECONDS = 5
STRUCTURE_INPUT_BYTES = 32768
SECURITY_INPUT_BYTES = 1024 * 1024
COMPRESSION_INPUT_BYTES = 128 * 1024
LOGFILE_INPUT_BYTES = 128 * 1024
TARGETS = ('image', 'validation', 'mapping-pairs', 'attribute-list', 'index-root', 'index-block', 'lznt1', 'reparse', 'security', 'access', 'wof', 'logfile')

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--seconds', type=int, default=DEFAULT_SECONDS)
parser.add_argument('--target', choices=(*TARGETS, 'all'), default='image', help='Time budget applies to each selected target')
parser.add_argument('--output', type=Path, default=root / 'artifacts/fuzz')
parser.add_argument('--compiler', help='Clang executable with a libFuzzer runtime; defaults to the platform toolchain')
args = parser.parse_args()
if not 1 <= args.seconds <= MAX_SECONDS:
    parser.error(f'--seconds must be between 1 and {MAX_SECONDS}')
env = tool_environment()
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=True)
run_directory = Path(tempfile.mkdtemp(prefix='run-', dir=output))
if sys.platform == 'darwin':
    compiler = args.compiler or subprocess.check_output(['xcrun', '--find', 'clang'], env=env, text=True).strip()
    sdk = ['-isysroot', subprocess.check_output(['xcrun', '--show-sdk-path'], env=env, text=True).strip()]
    resource = Path(subprocess.check_output([compiler, '-print-resource-dir'], env=env, text=True).strip())
    if not (resource / 'lib/darwin/libclang_rt.fuzzer_osx.a').is_file():
        parser.error('Selected Clang has no libFuzzer runtime. Use --compiler with a full LLVM Clang installation.')
else:
    compiler, sdk = args.compiler or 'clang', []
targets = TARGETS if args.target == 'all' else (args.target,)
report = {'status': 'running', 'compiler': compiler, 'seconds_per_target': args.seconds,
          'directory': str(run_directory), 'targets': []}
report_path = run_directory / 'report.json'
report_path.write_text(json.dumps(report, indent=2) + '\n')
try:
    for target in targets:
        campaign = run_directory / target
        campaign.mkdir()
        maximum = MAX_INPUT_BYTES if target in ('image', 'validation') else STRUCTURE_INPUT_BYTES
        if target in ('security', 'access'):
            maximum = SECURITY_INPUT_BYTES
        if target == 'wof':
            maximum = COMPRESSION_INPUT_BYTES
        if target == 'logfile':
            maximum = LOGFILE_INPUT_BYTES
        corpus = output / target / f'corpus-{maximum}'
        corpus.mkdir(parents=True, exist_ok=True)
        seeds = campaign / 'seeds'
        if target in ('image', 'validation'):
            subprocess.run([sys.executable, str(root / 'tests/fixtures.py'), str(seeds), '--image-bytes', str(maximum)], cwd=root, env=env, check=True)
            # Complete inventories have their own walker and corpus. Preserve
            # the original image API corpus without duplicating unused tails.
            paths = sorted(seeds.glob('validation-*.img')) if target == 'validation' else sorted(
                path for path in seeds.glob('*.img') if not path.name.startswith('validation-'))
            sources = [root / ('tests/fuzz_validation.c' if target == 'validation' else 'tests/fuzz.c'), root / 'tests/fuzz_mutator.c']
            flags = []
        else:
            generate(seeds)
            paths = sorted((seeds / target).glob('*.seed'))
            source = {'access': 'fuzz_access.c', 'wof': 'fuzz_wof.c', 'logfile': 'fuzz_logfile.c'}.get(target, 'fuzz_structures.c')
            sources = [root / 'tests' / source]
            flags = [] if target in ('access', 'wof', 'logfile') else ['-DNTFS_FUZZ_TARGET=NTFS_FUZZ_' + target.replace('-', '_').upper()]
        for path in paths:
            shutil.copyfile(path, corpus / path.name)
        binary = campaign / 'ntfs-fuzzer'
        command = [compiler, *sdk, '-std=c11', '-O1', '-g', '-fsanitize=fuzzer,address,undefined', '-fno-omit-frame-pointer', '-Wdeclaration-after-statement', '-I', str(root / 'include'), '-I', str(root / 'core'), *flags, *map(str, sorted((root / 'core').glob('*.c'))), *map(str, sources), str(root / 'tests/fuzz_device.c'), '-o', str(binary)]
        item = {'target': target, 'input_bytes': maximum, 'status': 'building', 'log': str(campaign / 'run.log')}
        report['targets'].append(item)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
        subprocess.run(command, cwd=root, env=env, check=True)
        item['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        item['status'] = 'running'
        report_path.write_text(json.dumps(report, indent=2) + '\n')
        print(f'Fuzzing {target}: {args.seconds}s, max input {maximum} bytes', flush=True)
        with (campaign / 'run.log').open('w') as log:
            run = subprocess.run([str(binary), str(corpus), f'-max_total_time={args.seconds}', f'-max_len={maximum}', f'-rss_limit_mb={RSS_LIMIT_MIB}', f'-timeout={INPUT_TIMEOUT_SECONDS}', f'-artifact_prefix={campaign}/'], cwd=root, env=env, stdout=log, stderr=log)
        item['exit_code'] = run.returncode
        item['status'] = 'pass' if run.returncode == 0 else 'fail'
        if run.returncode != 0:
            raise subprocess.CalledProcessError(run.returncode, run.args)
    report['status'] = 'pass'
except BaseException:
    report['status'] = 'fail'
    if report['targets'] and report['targets'][-1]['status'] in ('building', 'running'):
        report['targets'][-1]['status'] = 'fail'
    raise
finally:
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
