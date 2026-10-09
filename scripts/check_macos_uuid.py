#!/usr/bin/env python3
"""Diagnose selected-Xcode UUID stability with small relocated C/Swift builds.

These standalone binaries are never run or installed. Original object files,
unstripped and stripped executables, dSYMs, commands and logs remain in a new
output directory. This is a toolchain probe, not FSKit acceptance.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

from benchmark_toolchain import command
from build_fskit import REPRODUCIBLE_BUILD_ROOT, debug_input_diagnostics
from environment import tool_environment


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def probe(output):
    if sys.platform != 'darwin':
        raise ValueError('The UUID probe requires actual macOS and selected Xcode')
    output = output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    report = {'status': 'running', 'scope': 'standalone toolchain probe; no execution or FSKit acceptance',
              'variants': []}
    environment = tool_environment()

    def save():
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    def run(argv, directory, name, cwd=None):
        return command(argv, directory, name, environment, timeout=120,
                       output_limit=1024 * 1024, cwd=cwd or directory)

    save()
    try:
        report['xcode'] = run(['xcodebuild', '-version'], output, 'xcode').strip()
        sdk = run(['xcrun', '--show-sdk-path'], output, 'sdk-path').strip()
        sdk_version = run(['xcrun', '--show-sdk-version'], output, 'sdk-version').strip()
        report['sdk_version'] = sdk_version
        for variant in ('original', 'compiler-mapped', 'compiler-and-linker-mapped', 'source-and-linker-mapped'):
            value = {'name': variant, 'architectures': []}
            report['variants'].append(value)
            for architecture in ('arm64', 'x86_64'):
                pair = {'architecture': architecture, 'builds': []}
                value['architectures'].append(pair)
                for location in ('first', 'relocated-second'):
                    directory = output / variant / architecture / location
                    directory.mkdir(parents=True)
                    source = directory / 'SourceSnapshot'
                    source.mkdir()
                    c_source = source / 'answer.c'
                    c_source.write_text('int ntfs_probe_answer(void) { return 42; }\n')
                    swift_source = source / 'main.swift'
                    swift_source.write_text('@_silgen_name("ntfs_probe_answer") func answer() -> Int32\n'
                                            'if answer() != 42 { fatalError("probe") }\n')
                    target = architecture + '-apple-macos' + sdk_version
                    source_only = variant == 'source-and-linker-mapped'
                    mapping = (str(source) + '=' + REPRODUCIBLE_BUILD_ROOT + '/SourceSnapshot' if source_only
                               else str(directory) + '=' + REPRODUCIBLE_BUILD_ROOT)
                    c_flags = [] if variant == 'original' else ['-ffile-prefix-map=' + mapping]
                    swift_flags = [] if variant == 'original' else [
                        '-file-prefix-map', mapping, '-debug-prefix-map', mapping,
                        '-Xfrontend', '-prefix-serialized-debugging-options']
                    c_object, swift_object = directory / 'answer.o', directory / 'main.o'
                    module = directory / 'NTFSReproProbe.swiftmodule'
                    binary = directory / 'probe'
                    run(['xcrun', 'clang', '-g', '-O2', '-target', target, '-isysroot', sdk,
                         *c_flags, '-c', str(c_source), '-o', str(c_object)], directory, 'compile-c', source)
                    run(['xcrun', 'swiftc', '-g', '-O', '-target', target, '-sdk', sdk,
                         '-module-name', 'NTFSReproProbe', *swift_flags, '-emit-module',
                         '-emit-module-path', str(module), '-emit-object', str(swift_source),
                         '-o', str(swift_object)], directory, 'compile-swift', source)
                    linker_mapped = variant in ('compiler-and-linker-mapped', 'source-and-linker-mapped')
                    ast_path = '../' + module.name if linker_mapped else str(module)
                    linker_flags = ['-Xlinker', '-oso_prefix', '-Xlinker', str(directory) + '/'] if linker_mapped else []
                    run(['xcrun', 'swiftc', '-target', target, '-sdk', sdk,
                         str(c_object), str(swift_object), '-Xlinker', '-reproducible',
                         '-Xlinker', '-add_ast_path', '-Xlinker', ast_path, *linker_flags,
                         '-o', str(binary)], directory, 'link', source)
                    symbols = directory / 'probe.dSYM'
                    if source_only:
                        for path in (c_object, swift_object):
                            (source / path.name).symlink_to('../' + path.name)
                    symbol_flags = ['--oso-prepend-path=' + str(directory)] if linker_mapped and not source_only else []
                    debug_log = run(['xcrun', 'dsymutil', *symbol_flags, str(binary), '-o', str(symbols)],
                                    directory, 'debug-symbols', source)
                    debug_log += (directory / 'debug-symbols.stderr').read_text(errors='replace')
                    debug_diagnostics = debug_input_diagnostics(debug_log)
                    stripped = directory / 'probe-stripped'
                    shutil.copyfile(binary, stripped)
                    run(['xcrun', 'strip', '-S', str(stripped)], directory, 'strip', source)
                    uuid = run(['xcrun', 'dwarfdump', '--uuid', str(stripped)], directory, 'uuid').strip()
                    debug_uuid = run(['xcrun', 'dwarfdump', '--uuid', str(symbols)], directory, 'debug-uuid').strip()
                    if uuid.split()[:3] != debug_uuid.split()[:3]:
                        raise ValueError('Probe executable and dSYM UUIDs differ')
                    contents = ''
                    if not debug_diagnostics:
                        run(['xcrun', 'dwarfdump', '--verify', str(symbols)], directory, 'debug-verify')
                        contents = run(['xcrun', 'dwarfdump', '--debug-info', '--recurse-depth=0', str(symbols)],
                                       directory, 'debug-content')
                    pair['builds'].append({'directory': str(directory), 'uuid_output': uuid,
                                           'stripped_sha256': digest(stripped), 'unstripped_sha256': digest(binary),
                                           'c_object_sha256': digest(c_object), 'swift_object_sha256': digest(swift_object),
                                           'debug_input_diagnostics': debug_diagnostics,
                                           'debug_compile_units': contents.count('DW_TAG_compile_unit')})
                    save()
                pair['stripped_equal'] = pair['builds'][0]['stripped_sha256'] == pair['builds'][1]['stripped_sha256']
                pair['debug_inputs_complete'] = all(not item['debug_input_diagnostics'] and
                                                    item['debug_compile_units'] > 0 for item in pair['builds'])
                save()
        report['status'] = 'complete'
        save()
        return report
    except BaseException as error:
        report.update(status='failed', error=f'{type(error).__name__}: {error}')
        save()
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New owned artifact directory')
    args = parser.parse_args()
    result = probe(args.output)
    print(json.dumps({'status': result['status'], 'variants': {
        item['name']: {pair['architecture']: pair['stripped_equal'] for pair in item['architectures']}
        for item in result['variants']}, 'debug_inputs_complete': {
        item['name']: {pair['architecture']: pair['debug_inputs_complete'] for pair in item['architectures']}
        for item in result['variants']}}))
