#!/usr/bin/env python3
"""Compile the real SDK bridge and test unavailable app paths without launching an app."""
import argparse
import json
from pathlib import Path
import platform
import re
import sys

from benchmark_toolchain import command, digest
from environment import tool_environment

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('adapters/fskit/NTFSAppSupport.h', 'adapters/fskit/NTFSAppSupport.m',
           'adapters/fskit/ImageCommands.swift', 'tests/fskit_app_support.swift')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/fskit-app-support')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'result': 'FAIL', 'scope': 'Real SDK app bridge and unavailable paths only',
              'sources': {name: digest(ROOT / name) for name in SOURCES}}
    try:
        if sys.platform != 'darwin':
            report['result'] = 'UNEXECUTED'
            raise RuntimeError('Actual macOS SDK and runtime required; no substitute framework is used')
        env = tool_environment()

        def query(name, *argv):
            return command(argv, output, name, env, timeout=30, output_limit=65536).strip()

        sdk = query('sdk-path', 'xcrun', '--show-sdk-path')
        version = query('sdk-version', 'xcrun', '--show-sdk-version')
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', version):
            raise ValueError('Invalid selected SDK version')
        numbers = tuple(map(int, version.split('.')))
        if numbers < (26, 5):
            report['result'] = 'UNEXECUTED'
            raise RuntimeError('Selected SDK is older than the app minimum macOS 26.5')
        clang = query('clang-path', 'xcrun', '--find', 'clang')
        swift = query('swift-path', 'xcrun', '--find', 'swiftc')
        architecture = platform.machine()
        if architecture not in ('arm64', 'x86_64'):
            raise ValueError('Unsupported native macOS architecture')
        target = f'{architecture}-apple-macos26.5'
        report['toolchain'] = {'sdk': sdk, 'sdk_version': version, 'clang': clang,
                               'swift': swift, 'target': target,
                               'xcode': query('xcode-version', 'xcodebuild', '-version'),
                               'runtime': query('runtime-version', 'sw_vers', '-productVersion')}
        adapter = ROOT / 'adapters/fskit'
        bridge = output / 'NTFSAppSupport.o'
        command([clang, '-isysroot', sdk, '-target', target, '-fobjc-arc', '-fblocks',
                 '-O0', '-g', '-Wall', '-Wextra', '-Werror', '-Wdeclaration-after-statement',
                 '-c', adapter / 'NTFSAppSupport.m', '-o', bridge],
                output, 'compile-bridge', env, timeout=120)
        executable = output / 'ntfs-app-support-test'
        command([swift, '-sdk', sdk, '-target', target, '-swift-version', '5',
                 '-Onone', '-g', '-warnings-as-errors', '-import-objc-header',
                 adapter / 'NTFSAppSupport.h', adapter / 'ImageCommands.swift',
                 ROOT / 'tests/fskit_app_support.swift', bridge, '-framework', 'AppKit',
                 '-framework', 'FSKit', '-o', executable],
                output, 'compile-swift', env, timeout=180)
        raw = command([executable, 'modern' if numbers[0] >= 27 else 'legacy'],
                      output, 'run', env, timeout=30, output_limit=65536)
        report['tests'] = json.loads(raw)
        if report['tests'].get('result') != 'PASS':
            raise ValueError('App-support test did not return PASS')
        report['result'] = 'PASS'
        print(raw.strip())
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
