#!/usr/bin/env python3
"""Check memory fallbacks and strict core objects in explicit compiler contexts.

Xcode kernel SDK objects are never linked, installed or loaded. Linux checks
native freestanding userspace and GPR-restricted objects, without claiming a
kernel SDK build. GPR tests always run as ordinary userspace processes.
"""
import argparse
import json
from pathlib import Path
import platform
import re
import shutil
import sys

from benchmark_cpu import ROOT, build
from benchmark_toolchain import command, select, identity, sdk_flags
from environment import sanitizer_environment

FRAME_BYTES = 2048
FORBIDDEN_ARM = re.compile(r'(?<![\w])(?:[bhsdqv](?:[12]?[0-9]|3[01]))(?=[.\],\s]|$)')
FORBIDDEN_X86 = re.compile(r'\b(?:[xyz]mm[0-9]+|mm[0-9]+)\b|\bst(?:\([0-7]\))?(?!\w)')


def object_contexts(environment):
    if sys.platform == 'darwin':
        return [dict(name=context, arch=arch, flags=['-arch', arch] + (
            ['-mkernel', '-DKERNEL', '-DKERNEL_EXTENSION', '-mgeneral-regs-only',
             '-isystem', str(Path(environment['SDKROOT']) /
                            'System/Library/Frameworks/Kernel.framework/Headers')]
            if context == 'kernel' else []), restricted=context == 'kernel')
            for context, arch in (('userspace', 'arm64'), ('userspace', 'x86_64'),
                                  ('kernel', 'arm64e'), ('kernel', 'x86_64'))]
    return [dict(name=name, arch=platform.machine(), flags=flags, restricted=bool(flags))
            for name, flags in (('userspace', []),
                                ('general-registers', ['-DKERNEL', '-mgeneral-regs-only']))]


def find_tool(override, default, environment):
    if sys.platform == 'darwin' and not override:
        import subprocess
        return subprocess.check_output(['xcrun', '--find', default], env=environment,
                                       text=True, timeout=15).strip()
    path = shutil.which(override or default, path=environment.get('PATH'))
    if path is None:
        raise ValueError(f'Required object inspection tool not found: {override or default}')
    return str(Path(path).resolve())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--compiler', help='Explicit compiler executable; selected Xcode or cc by default')
    parser.add_argument('--disassembler', help='Explicit otool (macOS) or objdump (Linux) executable')
    parser.add_argument('--nm', help='Explicit symbol inspection executable')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = select(args.compiler)
    tests = sanitizer_environment()
    toolchain = identity(env)
    clang = env['CC']
    commands = []
    checked, objects = [], []
    report = dict(complete=False, toolchain=toolchain, tests=checked, objects=objects,
                  coreSources=len(list((ROOT / 'core').glob('*.c'))),
                  kernelLoaded=False, kernelSDKObjects=sys.platform == 'darwin',
                  stackFrameLimitBytes=FRAME_BYTES)

    def run(label, argv, environment=env):
        result = command(argv, output, label, environment)
        commands.append(dict(name=label, argv=list(map(str, argv)), exitCode=0))
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        return result

    try:
        disassembler = find_tool(args.disassembler, 'otool' if sys.platform == 'darwin' else 'objdump', env)
        nm = find_tool(args.nm, 'nm', env)
        report['inspectionTools'] = dict(disassembler=disassembler, nm=nm)
        for context, flags in (
            ('portable', ['-DNTFS_MEMORY_PORTABLE', '-DNTFS_WIRE_BYTES_PORTABLE']),
            ('general-registers', ['-DKERNEL', '-mgeneral-regs-only']),
        ):
            for name in ('memory', 'codecs', 'endian'):
                label = f'{context}-{name}'
                harness = ROOT / ('tests/endian.c' if name == 'endian' else f'tests/cpu_{name}.c')
                binary, argv = build(ROOT, output, harness,
                                     [*flags, '-fsanitize=address,undefined'], label, clang, env)
                commands.append(dict(name=f'{label}-build', argv=argv, exitCode=0))
                run(f'{label}-run', [binary, *([args.fixtures.resolve()] if name == 'codecs' else [])], tests)
                checked.append(label)

        for context in object_contexts(env):
            name, arch = context['name'], context['arch']
            directory = output / f'{name}-{arch}'
            directory.mkdir()
            flags = [clang, *sdk_flags(env), *context['flags'], '-std=c11', '-O2',
                     '-ffreestanding', '-fno-builtin', '-Wall', '-Wextra', '-Werror',
                     '-Wdeclaration-after-statement', f'-Wframe-larger-than={FRAME_BYTES}',
                     '-I', ROOT / 'include', '-I', ROOT / 'core']
            if 'clang' in toolchain['compiler_version'].lower():
                flags.append('-Wconditional-uninitialized')
            for source in sorted((ROOT / 'core').glob('*.c')):
                label = f'{name}-{arch}-{source.stem}'
                target = directory / f'{source.stem}.o'
                run(f'{label}-compile', [*flags, '-c', source, '-o', target])
                if context['restricted']:
                    options = ['-tvV'] if sys.platform == 'darwin' else ['-d', '--no-show-raw-insn']
                    assembly = run(f'{label}-assembly', [disassembler, *options, target])
                    pattern = FORBIDDEN_ARM if arch.lower() in ('arm64', 'arm64e', 'aarch64') else FORBIDDEN_X86
                    if pattern.search(assembly):
                        raise ValueError(f'Unexpected SIMD/FP register in {label}')
                if source.name == 'memory.c':
                    symbols = run(f'{label}-undefined', [nm, '-u', target])
                    if symbols.strip():
                        raise ValueError(f'Unexpected runtime dependency in {label}: {symbols}')
                objects.append(dict(context=name, arch=arch, source=str(source.relative_to(ROOT)),
                                    object=str(target)))
        report.update(complete=True, restrictedSIMDRegisters=0, memoryRuntimeDependencies=0)
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(complete=True, objects=len(objects), focusedTests=len(checked))))


if __name__ == '__main__':
    main()
