#!/usr/bin/env python3
"""Forward Xcode's clang link invocation with relocatable debugger paths.

The build helper writes the selected compiler and owned build root beside the
source snapshot. This wrapper changes only paths in linker debug metadata; it
does not change UUID generation, strip executable bytes, sign, or install.
"""
import json
import os
from pathlib import Path
import shlex
import sys

MAX_RESPONSE_BYTES = 1024 * 1024
MAX_RESPONSE_TOTAL_BYTES = 8 * MAX_RESPONSE_BYTES
MAX_ARGUMENTS = 65536
MAX_RESPONSE_DEPTH = 4


def mapped_arguments(arguments, build_root, cwd):
    build_root, cwd = Path(build_root).resolve(), Path(cwd).resolve()
    response_bytes = 0

    def map_path(value):
        path = Path(value)
        if path.is_absolute() and path.resolve().is_relative_to(build_root):
            return os.path.relpath(path, cwd)
        return value

    def expand(values, depth=0):
        nonlocal response_bytes
        if depth > MAX_RESPONSE_DEPTH:
            raise ValueError('Linker response-file nesting exceeds its bound')
        result = []
        for value in values:
            loader_path = value.split('/')[0] in ('@executable_path', '@loader_path', '@rpath')
            path = (cwd / value[1:]).resolve() if value.startswith('@') and not loader_path else None
            if path is not None and path.is_relative_to(build_root):
                if not path.is_file():
                    raise ValueError('Expected a regular linker response file')
                with path.open('rb') as source:
                    contents = source.read(MAX_RESPONSE_BYTES + 1)
                response_bytes += len(contents)
                if len(contents) > MAX_RESPONSE_BYTES or response_bytes > MAX_RESPONSE_TOTAL_BYTES:
                    raise ValueError('Linker response file exceeds its byte bound')
                result.extend(expand(shlex.split(contents.decode('utf-8'), comments=False), depth + 1))
            else:
                result.append(value)
            if len(result) > MAX_ARGUMENTS:
                raise ValueError('Linker arguments exceed their count bound')
        return result

    result = expand(arguments)
    index = 0
    while index < len(result):
        if result[index:index + 3] == ['-Xlinker', '-add_ast_path', '-Xlinker']:
            if index + 3 >= len(result):
                raise ValueError('Missing Swift debug module path')
            result[index + 3] = map_path(result[index + 3])
            index += 4
        elif result[index].startswith('-Wl,-add_ast_path,'):
            result[index] = '-Wl,-add_ast_path,' + map_path(result[index][len('-Wl,-add_ast_path,'):])
            index += 1
        else:
            index += 1
    return [*result, '-Xlinker', '-oso_prefix', '-Xlinker', str(build_root) + '/']


def main():
    build_root = Path(__file__).resolve().parents[2]
    settings = json.loads((build_root / 'linker-settings.json').read_text())
    if Path(settings['build_root']).resolve() != build_root:
        raise ValueError('Linker settings do not identify the owned build root')
    clang = Path(settings['clang'])
    if not clang.is_absolute() or not clang.is_file():
        raise ValueError('Selected clang linker driver is absent')
    arguments = sys.argv[1:]
    if '-o' in arguments:
        arguments = mapped_arguments(arguments, build_root, Path.cwd())
        print('NTFS_REPRO_LINK: ' + shlex.join([str(clang), *arguments]), file=sys.stderr, flush=True)
    os.execv(str(clang), [str(clang), *arguments])


if __name__ == '__main__':
    main()
