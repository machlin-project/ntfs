#!/usr/bin/env python3
"""Check memory fallbacks and compile the complete core for user/kernel contexts.

Kernel objects are never linked, installed or loaded. General-register-only
tests run as ordinary userspace processes; disassembly independently checks the
actual kernel objects. Reports retain commands, diagnostics and assembly.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

from benchmark_cpu import ROOT, build
from environment import sanitizer_environment, tool_environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = tool_environment()
    tests = sanitizer_environment()
    clang = subprocess.check_output(['xcrun', '--find', 'clang'], env=env, text=True).strip()
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], env=env, text=True).strip()
    commands = []

    def run(label, argv, environment=env):
        argv = list(map(str, argv))
        result = subprocess.run(argv, cwd=ROOT, env=environment, capture_output=True)
        (output / f'{label}.stdout').write_bytes(result.stdout)
        (output / f'{label}.stderr').write_bytes(result.stderr)
        commands.append(dict(name=label, argv=argv, exitCode=result.returncode))
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if result.returncode:
            raise RuntimeError(f'{label} failed; see retained diagnostics')
        return result.stdout.decode()

    checked = []
    for context, flags in (
        ('portable', ['-DNTFS_MEMORY_PORTABLE']),
        ('general-registers', ['-DKERNEL', '-mgeneral-regs-only']),
    ):
        for name in ('memory', 'codecs'):
            label = f'{context}-{name}'
            binary, argv = build(ROOT, output, ROOT / f'tests/cpu_{name}.c',
                                 [*flags, '-fsanitize=address,undefined'], label, clang, env)
            commands.append(dict(name=f'{label}-build', argv=argv, exitCode=0))
            run(f'{label}-run', [binary, *([args.fixtures.resolve()] if name == 'codecs' else [])], tests)
            checked.append(label)

    objects = []
    forbidden_arm = re.compile(r'(?<![\w])(?:[bhsdqv](?:[12]?[0-9]|3[01]))(?=[.\],\s]|$)')
    forbidden_x86 = re.compile(r'\b(?:[xyz]mm[0-9]+|mm[0-9]+)\b|\bst(?:\([0-7]\))?(?!\w)')
    for context, arch in (('userspace', 'arm64'), ('userspace', 'x86_64'),
                          ('kernel', 'arm64e'), ('kernel', 'x86_64')):
        directory = output / f'{context}-{arch}'
        directory.mkdir()
        flags = [clang, '-arch', arch, '-isysroot', sdk, '-std=c11', '-O2',
                 '-ffreestanding', '-fno-builtin', '-Wall', '-Wextra', '-Werror',
                 '-Wconditional-uninitialized', '-Wdeclaration-after-statement',
                 '-Wframe-larger-than=2048', '-I', ROOT / 'include', '-I', ROOT / 'core']
        if context == 'kernel':
            flags += ['-mkernel', '-DKERNEL', '-DKERNEL_EXTENSION', '-mgeneral-regs-only',
                      '-isystem', Path(sdk) / 'System/Library/Frameworks/Kernel.framework/Headers']
        for source in sorted((ROOT / 'core').glob('*.c')):
            label = f'{context}-{arch}-{source.stem}'
            target = directory / f'{source.stem}.o'
            run(f'{label}-compile', [*flags, '-c', source, '-o', target])
            if context == 'kernel':
                assembly = run(f'{label}-assembly', ['xcrun', 'otool', '-tvV', target])
                pattern = forbidden_arm if arch == 'arm64e' else forbidden_x86
                assert not pattern.search(assembly), f'Unexpected SIMD/FP register in {label}'
            if source.name == 'memory.c':
                symbols = run(f'{label}-undefined', ['xcrun', 'nm', '-u', target])
                assert not symbols.strip(), f'Unexpected runtime dependency in {label}: {symbols}'
            objects.append(dict(context=context, arch=arch, source=str(source.relative_to(ROOT)),
                                object=str(target)))
    report = dict(complete=True, tests=checked, objects=objects,
                  coreSources=len(list((ROOT / 'core').glob('*.c'))),
                  kernelSIMDRegisters=0, memoryRuntimeDependencies=0,
                  kernelLoaded=False, stackFrameLimitBytes=2048)
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(complete=True, objects=len(objects), focusedTests=len(checked))))


if __name__ == '__main__':
    main()
