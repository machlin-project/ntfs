#!/usr/bin/env python3
"""Decode original C-authored LZNT1 packets with Windows RtlDecompressBuffer.

This is an in-memory codec oracle. It never opens a device, changes a file's
compression setting, or calls the product decoder. A new report directory keeps
both successes and the first failure. Missing Windows/native exports are failures,
not synthetic passes. Original packet pairs come from ntfs-write-lznt1-tests;
cluster-rounded unit pairs come from ntfs-write-lznt1-unit-tests. Both accept an
OUTPUT_DIR and create disjoint names without replacing existing evidence.
"""
import argparse
import ctypes as ct
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys

MAX_INPUT_BYTES = 1024 * 1024
CHUNK_BYTES = 4096
HEADER_BYTES = 2
MAX_PACKED_BYTES = MAX_INPUT_BYTES + (MAX_INPUT_BYTES // CHUNK_BYTES) * HEADER_BYTES
MAX_CASES = 512
MAX_CORPUS_BYTES = 64 * 1024 * 1024
GUARD_BYTES = 32
GUARD_VALUE = 0xa5
COMPRESSION_FORMAT_LZNT1 = 2
NAME = re.compile(r'(case|unit)-([0-9]{4})\.(data|packed)')
NATIVE_PROVENANCE = 'Windows ntdll RtlDecompressBuffer, COMPRESSION_FORMAT_LZNT1'
SYNTHETIC_PROVENANCE = 'Synthetic transport contract only; no Windows codec qualification'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_packet(path, maximum):
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    if path.is_symlink():
        raise ValueError('Corpus member is a symlink')
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise ValueError('Corpus member is not a bounded nonempty regular file')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) != info.st_size or len(data) > maximum:
            raise ValueError('Corpus member changed size or exceeds its bound')
        return data
    finally:
        os.close(descriptor)


def inventory(directory):
    pairs = {}
    for count, member in enumerate(directory.iterdir(), 1):
        if count > MAX_CASES * 2:
            raise ValueError('Corpus exceeds its member-count budget')
        match = NAME.fullmatch(member.name)
        if match is None:
            raise ValueError('Unexpected corpus member')
        # Keep existing case identities stable and unit identities disjoint,
        # even when the two independent producers use the same ordinal.
        identity = match[2] if match[1] == 'case' else 'unit-' + match[2]
        pairs.setdefault(identity, {})[match[3]] = member
    if not pairs or len(pairs) > MAX_CASES:
        raise ValueError('Corpus has no cases or exceeds its case budget')
    if any(set(pair) != {'data', 'packed'} for pair in pairs.values()):
        raise ValueError('Corpus contains an unpaired member')
    return sorted(pairs.items())


class WindowsDecoder:
    def __init__(self):
        if sys.platform != 'win32':
            raise RuntimeError('Native LZNT1 collection requires Windows Python')
        self.library = ct.WinDLL('ntdll.dll')
        self.function = self.library.RtlDecompressBuffer
        self.function.argtypes = (ct.c_uint16, ct.c_void_p, ct.c_uint32, ct.c_void_p,
                                  ct.c_uint32, ct.POINTER(ct.c_uint32))
        self.function.restype = ct.c_int32

    def decode(self, packed, expected_size):
        input_array = (ct.c_ubyte * (len(packed) + GUARD_BYTES * 2))()
        output_array = (ct.c_ubyte * (expected_size + GUARD_BYTES * 2))()
        ct.memset(input_array, GUARD_VALUE, ct.sizeof(input_array))
        ct.memset(output_array, GUARD_VALUE, ct.sizeof(output_array))
        ct.memmove(ct.addressof(input_array) + GUARD_BYTES, packed, len(packed))
        written = ct.c_uint32(0xffffffff)
        status = self.function(COMPRESSION_FORMAT_LZNT1,
                               ct.addressof(output_array) + GUARD_BYTES, expected_size,
                               ct.addressof(input_array) + GUARD_BYTES, len(packed),
                               ct.byref(written))
        prefix = bytes([GUARD_VALUE]) * GUARD_BYTES
        input_expected = prefix + packed + prefix
        input_unchanged = bytes(input_array) == input_expected
        output = bytes(output_array)
        guards = output[:GUARD_BYTES] == prefix and output[-GUARD_BYTES:] == prefix
        return {'status': status & 0xffffffff, 'written': written.value,
                'input_unchanged': input_unchanged, 'output_guards': guards,
                'data': output[GUARD_BYTES:-GUARD_BYTES]}


def collect(corpus, output, *, test_decoder=None):
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'machlin-lznt1-windows-v1', 'complete': False, 'passed': False,
              'provenance': SYNTHETIC_PROVENANCE if test_decoder is not None else NATIVE_PROVENANCE,
              'platform': platform.platform(), 'python': platform.python_version(),
              'collector_sha256': digest(Path(__file__).read_bytes()), 'cases': []}
    total = 0
    try:
        cases = inventory(corpus)
        report['expected_cases'] = len(cases)
        decoder = test_decoder if test_decoder is not None else WindowsDecoder()
        for name, paths in cases:
            original = read_packet(paths['data'], MAX_INPUT_BYTES)
            packed = read_packet(paths['packed'], MAX_PACKED_BYTES)
            total += len(original) + len(packed)
            if total > MAX_CORPUS_BYTES:
                raise ValueError('Corpus exceeds its aggregate byte budget')
            result = decoder.decode(packed, len(original))
            row = {'case': name, 'original_bytes': len(original), 'packed_bytes': len(packed),
                   'original_sha256': digest(original), 'packed_sha256': digest(packed),
                   'status': f"0x{result['status']:08x}", 'written': result['written'],
                   'input_unchanged': result['input_unchanged'],
                   'output_guards': result['output_guards'],
                   'content_matches': result['data'] == original,
                   'source_files_unchanged': (read_packet(paths['data'], MAX_INPUT_BYTES) == original and
                                              read_packet(paths['packed'], MAX_PACKED_BYTES) == packed)}
            row['passed'] = (result['status'] == 0 and result['written'] == len(original) and
                             row['input_unchanged'] and row['output_guards'] and
                             row['content_matches'] and row['source_files_unchanged'])
            report['cases'].append(row)
            if not row['passed']:
                raise ValueError(f'Independent Windows codec comparison failed for case {name}')
        report.update({'complete': True, 'passed': True, 'corpus_bytes': total})
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
    finally:
        with (output / 'report.json').open('x', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    arguments = parser.parse_args()
    report = collect(arguments.corpus, arguments.output)
    print(json.dumps({'passed': report['passed'], 'complete': report['complete'],
                      'cases': len(report['cases']), 'error': report.get('error')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
