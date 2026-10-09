#!/usr/bin/env python3
"""Bounded image and parser libFuzzer campaigns; immutable files, no mounts."""
from pathlib import Path
import argparse
import hashlib
import json
import random
import shutil
import subprocess
import sys
import tempfile
from environment import sanitizer_environment
from fuzz_seeds import generate, journal_volume_images, lznt1_unit_seeds, LZNT1_UNIT_SELECTOR
from directory_fuzz_seeds import generate as generate_directory
from usn_fuzz_seeds import generate as generate_usn

DEFAULT_SECONDS = 60
MAX_SECONDS = 3600
# The image campaign's payloads fit in one MiB. Author that geometry directly;
# larger journal-volume layouts stay in the dedicated component/source suites.
# libFuzzer retains whole inputs, so unused disk tails amplify corpus memory.
MAX_INPUT_BYTES = 1024 * 1024
# Complete diagnostic resources also contain the reserved sector after that
# declared data span. Keep authored data geometry unchanged and retain the copy.
IMAGE_RESERVED_BOOT_BYTES = 4096
MAX_IMAGE_RESOURCE_BYTES = MAX_INPUT_BYTES + IMAGE_RESERVED_BOOT_BYTES
RSS_LIMIT_MIB = 1024
INPUT_TIMEOUT_SECONDS = 5
IMAGE_FUZZ_PROCESSES = 1
FINISH_GRACE_SECONDS = 120
SEED_REPLAY_BATCH_FILES = 32
STRUCTURE_INPUT_BYTES = 32768
SECURITY_INPUT_BYTES = 1024 * 1024
COMPRESSION_INPUT_BYTES = 128 * 1024
ENCODER_INPUT_BYTES = 16 * 4096
ENCODER_UNIT_INPUT_BYTES = ENCODER_INPUT_BYTES + LZNT1_UNIT_SELECTOR.size
LOGFILE_INPUT_BYTES = 2 * 1024 * 1024
TARGETS = ('image', 'validation', 'mapping-pairs', 'attribute-list', 'index-root', 'index-block', 'directory-mutation', 'lznt1', 'lznt1-encode', 'reparse', 'security', 'access', 'wof', 'logfile', 'usn')

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--seconds', type=int, default=DEFAULT_SECONDS)
parser.add_argument('--target', choices=(*TARGETS, 'all'), default='image', help='Time budget applies to each selected target')
parser.add_argument('--output', type=Path, default=root / 'artifacts/fuzz')
parser.add_argument('--compiler', help='Clang executable with a libFuzzer runtime; defaults to the platform toolchain')
args = parser.parse_args()
if not 1 <= args.seconds <= MAX_SECONDS:
    parser.error(f'--seconds must be between 1 and {MAX_SECONDS}')
env = sanitizer_environment()
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
          'directory': str(run_directory), 'targets': [],
          'sanitizer_options': {name: env[name] for name in ('ASAN_OPTIONS', 'UBSAN_OPTIONS')}}
report_path = run_directory / 'report.json'
report_path.write_text(json.dumps(report, indent=2) + '\n')
try:
    for target in targets:
        campaign = run_directory / target
        campaign.mkdir()
        maximum = MAX_INPUT_BYTES if target in ('image', 'validation') else STRUCTURE_INPUT_BYTES
        if target in ('security', 'access'):
            maximum = SECURITY_INPUT_BYTES
        if target in ('wof', 'usn'):
            maximum = COMPRESSION_INPUT_BYTES
        if target == 'lznt1-encode':
            maximum = ENCODER_UNIT_INPUT_BYTES
        if target == 'logfile':
            maximum = LOGFILE_INPUT_BYTES
        if target in ('image', 'validation'):
            maximum = MAX_IMAGE_RESOURCE_BYTES
        corpus = output / target / f'corpus-{maximum}'
        corpus.mkdir(parents=True, exist_ok=True)
        seeds = campaign / 'seeds'
        if target in ('image', 'validation'):
            subprocess.run([sys.executable, str(root / 'tests/fixtures.py'), str(seeds), '--image-bytes', str(MAX_INPUT_BYTES)], cwd=root, env=env, check=True)
            # Complete inventories have their own walker and corpus. Preserve
            # the original image API corpus without duplicating unused tails.
            paths = sorted(seeds.glob('validation-*.img')) if target == 'validation' else sorted(
                path for path in seeds.glob('*.img') if not path.name.startswith('validation-'))
            if target == 'image':
                # Public stream admission must reject the fixed bad-cluster
                # stream, while preserving ordinary ADS with the same name.
                paths.extend(sorted(seeds.glob('validation-bad-*.img')))
                paths.extend(journal_volume_images(seeds, MAX_INPUT_BYTES))
                metadata_seeds = seeds / 'metadata-objects'
                subprocess.run([sys.executable, str(root / 'tests/metadata_objects_fixtures.py'),
                                str(metadata_seeds), '--image-bytes', str(MAX_INPUT_BYTES)],
                               cwd=root, env=env, check=True)
                paths.extend(sorted(metadata_seeds.glob('*.img')))
            sources = [root / ('tests/fuzz_validation.c' if target == 'validation' else 'tests/fuzz.c'), root / 'tests/fuzz_mutator.c']
            flags = []
        elif target == 'directory-mutation':
            paths = generate_directory(seeds / target)
            sources = [root / 'tests/fuzz_directory.c']
            flags = []
        elif target == 'usn':
            paths = generate_usn(seeds)
            sources = [root / 'tests/fuzz_usn.c']
            flags = []
        elif target == 'lznt1-encode':
            seeds.mkdir()
            authored = {'empty': b'', 'zero': bytes(ENCODER_INPUT_BYTES),
                        'alphabet': (b'abcdefghijklmnopqrstuvwxyz' * ENCODER_INPUT_BYTES)[:ENCODER_INPUT_BYTES],
                        'byte-ramp': bytes(range(256)) * (ENCODER_INPUT_BYTES // 256),
                        'random': random.Random(20261008).randbytes(ENCODER_INPUT_BYTES)}
            authored.update(lznt1_unit_seeds())
            paths = []
            for name, data in authored.items():
                path = seeds / (name + '.seed')
                path.write_bytes(data)
                paths.append(path)
            sources = [root / 'tests/fuzz_write_lznt1.c']
            flags = []
        else:
            generate(seeds)
            paths = sorted((seeds / target).glob('*.seed'))
            source = {'access': 'fuzz_access.c', 'wof': 'fuzz_wof.c', 'logfile': 'fuzz_logfile.c'}.get(target, 'fuzz_structures.c')
            sources = [root / 'tests' / source]
            flags = [] if target in ('access', 'wof', 'logfile') else ['-DNTFS_FUZZ_TARGET=NTFS_FUZZ_' + target.replace('-', '_').upper()]
        for path in paths:
            shutil.copyfile(path, corpus / path.name)
        if not paths:
            raise ValueError(f'No authored seeds were generated for {target}')
        binary = campaign / 'ntfs-fuzzer'
        command = [compiler, *sdk, '-std=c11', '-O1', '-g', '-fsanitize=fuzzer,address,undefined', '-fno-omit-frame-pointer', '-Wdeclaration-after-statement', '-I', str(root / 'include'), '-I', str(root / 'core'), *flags, *map(str, sorted((root / 'core').glob('*.c'))), *map(str, sources), str(root / 'tests/fuzz_device.c'), '-o', str(binary)]
        # Whole-image corpora retain large raw byte arrays. LibFuzzer's process
        # mode uses bounded subsets and merges discoveries between children,
        # retaining sanitizer checks without accumulating one live image corpus.
        # Every OOM, timeout and crash still fails; no finding is ignored.
        process_flags = []
        if target in ('image', 'validation'):
            process_flags = [f'-fork={IMAGE_FUZZ_PROCESSES}', '-ignore_ooms=0',
                             '-ignore_timeouts=0', '-ignore_crashes=0']
        if target == 'logfile':
            # This one process owns its corpus. Periodic imports re-read whole
            # already-authored journals and retain a second large input batch.
            # Startup loading and the separate exhaustive replay remain intact.
            process_flags.append('-reload=0')
        item = {'target': target, 'input_bytes': maximum, 'status': 'building',
                'processes': IMAGE_FUZZ_PROCESSES if target in ('image', 'validation') else 0,
                'rss_limit_mib': RSS_LIMIT_MIB, 'timeout_seconds': INPUT_TIMEOUT_SECONDS,
                'log': str(campaign / 'run.log')}
        item['authored_seeds'] = len(paths)
        if target in ('image', 'validation'):
            item['declared_image_bytes'] = MAX_INPUT_BYTES
            item['reserved_boot_bytes'] = IMAGE_RESERVED_BOOT_BYTES
        if target == 'logfile':
            item['external_corpus_reload'] = False
            item['circular_record_seeds'] = json.loads((seeds / 'logfile-record-selection.json').read_text())
        report['targets'].append(item)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
        subprocess.run(command, cwd=root, env=env, check=True)
        item['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        item['status'] = 'running'
        report_path.write_text(json.dumps(report, indent=2) + '\n')
        if paths:
            # Child subsets are coverage-guided exploration, not proof that
            # every authored seed ran. Fixed-file batches check all seeds once
            # without retaining a growing corpus or weakening sanitizer checks.
            replay_log = campaign / 'seed-replay.log'
            item['seed_replay'] = {'files': len(paths), 'log': str(replay_log), 'status': 'running'}
            report_path.write_text(json.dumps(report, indent=2) + '\n')
            with replay_log.open('w') as log:
                for start in range(0, len(paths), SEED_REPLAY_BATCH_FILES):
                    replay = subprocess.run([str(binary), *map(str, paths[start:start + SEED_REPLAY_BATCH_FILES]),
                        '-runs=1', '-print_final_stats=1', f'-rss_limit_mb={RSS_LIMIT_MIB}',
                        f'-timeout={INPUT_TIMEOUT_SECONDS}', f'-artifact_prefix={campaign}/'],
                        cwd=campaign, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                        timeout=FINISH_GRACE_SECONDS)
                    item['seed_replay']['exit_code'] = replay.returncode
                    if replay.returncode != 0:
                        item['seed_replay']['status'] = 'fail'
                        raise subprocess.CalledProcessError(replay.returncode, replay.args)
            item['seed_replay']['status'] = 'pass'
            report_path.write_text(json.dumps(report, indent=2) + '\n')
        print(f'Fuzzing {target}: {args.seconds}s, max input {maximum} bytes', flush=True)
        with (campaign / 'run.log').open('w') as log:
            run = subprocess.run([str(binary), str(corpus), *process_flags,
                '-print_final_stats=1', f'-max_total_time={args.seconds}', f'-max_len={maximum}',
                f'-rss_limit_mb={RSS_LIMIT_MIB}', f'-timeout={INPUT_TIMEOUT_SECONDS}',
                f'-artifact_prefix={campaign}/'], cwd=campaign, env=env, stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, timeout=args.seconds + FINISH_GRACE_SECONDS)
        item['exit_code'] = run.returncode
        item['status'] = 'pass' if run.returncode == 0 else 'fail'
        if run.returncode != 0:
            raise subprocess.CalledProcessError(run.returncode, run.args)
    report['status'] = 'pass'
except BaseException:
    report['status'] = 'fail'
    if report['targets'] and report['targets'][-1]['status'] in ('building', 'running'):
        report['targets'][-1]['status'] = 'fail'
        replay = report['targets'][-1].get('seed_replay')
        if replay and replay['status'] == 'running':
            replay['status'] = 'fail'
    raise
finally:
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
