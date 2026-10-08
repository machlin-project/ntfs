#!/usr/bin/env python3
"""Check independent LZNT1 contracts and frozen/current complete error output.

Default execution retains fatal ASan/UBSan and Linux LeakSanitizer. A locally
restricted runner must retain and label any separate no-LSan supplement; it is
not the full Linux sanitizer gate. Apple ASan has a different leak-check boundary.
"""
import argparse
import json
from pathlib import Path

from benchmark_cpu import ROOT, build
from benchmark_lznt1 import build as build_encoder
from benchmark_toolchain import command, select, identity, sdk_flags, host_flags, section_flags
from environment import sanitizer_environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler')
    args = parser.parse_args()
    reference, fixtures, output = args.reference.resolve(), args.fixtures.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = select(args.compiler)
    toolchain = identity(env)
    results = []
    for context, flags in (('userspace', []), ('portable', ['-DNTFS_MEMORY_PORTABLE', '-DNTFS_WIRE_BYTES_PORTABLE']),
                           ('general-registers', ['-DKERNEL', '-mgeneral-regs-only'])):
        target = output / f'{context}-reference-lznt1.o'
        command([env['CC'], *sdk_flags(env), *host_flags(), *section_flags(), '-std=c11', '-O2', '-g',
                 '-UNDEBUG', '-ffreestanding', '-fno-builtin', '-Wall', '-Wextra', '-Werror',
                 '-fsanitize=address,undefined', '-I', reference / 'include', '-I', reference / 'core',
                 *flags, '-Dntfs_lznt1_decode=reference_lznt1_decode', '-c', reference / 'core/lznt1.c',
                 '-o', target], output, f'{context}-reference-lznt1-build', env)
        binary, _ = build(ROOT, output, ROOT / 'tests/lznt1_contract.c',
                           [*flags, target, '-DNTFS_LZNT1_REFERENCE', '-fsanitize=address,undefined'],
                           f'{context}-decode', env['CC'], env)
        decoded = command([binary, fixtures], output, f'{context}-decode-check', sanitizer_environment())
        target = output / f'{context}-reference-write-lznt1.o'
        exports = ('workspace_size', 'bound', 'measure', 'encode')
        renames = [f'-Dntfs_write_lznt1_{name}=reference_write_lznt1_{name}' for name in exports]
        command([env['CC'], *sdk_flags(env), *host_flags(), *section_flags(), '-std=c11', '-O2', '-g',
                 '-UNDEBUG', '-ffreestanding', '-fno-builtin', '-Wall', '-Wextra', '-Werror',
                 '-fsanitize=address,undefined', '-I', reference / 'include', '-I', reference / 'core',
                 *flags, *renames, '-c', reference / 'core/write_lznt1.c', '-o', target], output,
                f'{context}-reference-write-lznt1-build', env)
        binary, _ = build_encoder(ROOT, output, ROOT / 'tests/write_lznt1_differential.c',
                                   [*flags, target, '-fsanitize=address,undefined'],
                                   f'{context}-encode', env)
        encoded = command([binary], output, f'{context}-encode-check', sanitizer_environment())
        results.append(dict(context=context, decoder=decoded.strip(), encoder=encoded.strip()))
        print(context, decoded.strip(), encoded.strip(), flush=True)
    report = dict(complete=True, reference=str(reference), fixtures=str(fixtures), toolchain=toolchain,
                  fatalSanitizers=True, kernelLoaded=False, results=results)
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
