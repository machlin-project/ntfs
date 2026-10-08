#!/usr/bin/env python3
"""Compare decoder contracts to frozen source under fatal sanitizers.

The two decoders and their scalar support from the reference are linked with
renamed symbols. Status, written length and partial error output must agree exactly.
The regular fixture suite owns independent successful-output expectations.
"""
import argparse
import json
from pathlib import Path
import subprocess

from benchmark_cpu import ROOT, build
from environment import sanitizer_environment, tool_environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    reference = args.reference.resolve()
    fixtures = args.fixtures.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = tool_environment()
    clang = subprocess.check_output(['xcrun', '--find', 'clang'], env=env, text=True).strip()
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], env=env, text=True).strip()
    commands = []

    def run(name, argv, environment=env):
        argv = list(map(str, argv))
        result = subprocess.run(argv, cwd=ROOT, env=environment, capture_output=True)
        (output / f'{name}.stdout').write_bytes(result.stdout)
        (output / f'{name}.stderr').write_bytes(result.stderr)
        commands.append(dict(name=name, argv=argv, exitCode=result.returncode))
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if result.returncode:
            raise RuntimeError(f'{name} failed; see retained diagnostics')
        return result.stdout.decode().strip()

    results = []
    for context, flags in (('userspace', []), ('portable', ['-DNTFS_MEMORY_PORTABLE']),
                           ('general-registers', ['-DKERNEL', '-mgeneral-regs-only'])):
        objects = []
        support_exports = ('u16', 'u32', 'u64', 'put_u16', 'put_u32', 'put_u64', 'bounds',
                           'alloc', 'alloc_optional', 'free', 'io', 'default_limits',
                           'result_string', 'decode_time')
        support_renames = [f'-Dntfs_{symbol}=reference_{symbol}' for symbol in support_exports]
        for codec in ('support', 'xpress', 'lzx'):
            name = f'{context}-reference-{codec}'
            target = output / f'{name}.o'
            exports = () if codec == 'support' else (f'{codec}_workspace_size',
                       f'{codec}_workspace_alignment',
                       'xpress_huffman_decode' if codec == 'xpress' else 'lzx_decode')
            renames = [*support_renames, *(f'-Dntfs_{symbol}=reference_{symbol}' for symbol in exports)]
            run(name, [clang, '-isysroot', sdk, '-std=c11', '-O2', '-g', '-ffreestanding',
                       '-fno-builtin', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                       '-I', reference / 'include', '-I', reference / 'core', *flags, *renames,
                       '-c', reference / 'core' / f'{codec}.c', '-o', target])
            objects.append(target)
        binary, argv = build(ROOT, output, ROOT / 'tests/huffman.c',
                              [*flags, *objects, '-DNTFS_HUFFMAN_REFERENCE',
                               '-fsanitize=address,undefined'], context, clang, env)
        commands.append(dict(name=f'{context}-build', argv=argv, exitCode=0))
        summary = run(f'{context}-check', [binary, fixtures], sanitizer_environment())
        results.append(dict(context=context, summary=summary))
        print(context, summary, flush=True)
    report = dict(complete=True, reference=str(reference), fixtures=str(fixtures),
                  fatalSanitizers=True, kernelLoaded=False, results=results)
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
