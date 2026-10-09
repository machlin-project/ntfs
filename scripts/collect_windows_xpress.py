#!/usr/bin/env python3
"""Observe original XPRESS-HUFF packets through Windows Cabinet raw block API.

No product codec, device or filesystem compression operation is used. The fresh
output directory retains original packets, every native verdict and failure stage.
Optional EOF/padding variants are separately labelled compatibility observations;
standard packets require exact native success. Missing API acquisition is never
reported as a codec mismatch or as a successful native observation.
"""
import argparse
import ctypes as ct
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from windows_xpress_fixtures import vectors

MAX_INPUT_BYTES = 65536
MAX_PACKED_BYTES = 128 * 1024
MAX_CASES = 512
MAX_CORPUS_BYTES = 32 * 1024 * 1024
GUARD_BYTES = 32
GUARD_VALUE = 0xa5
COMPRESS_ALGORITHM_XPRESS_HUFF = 4
COMPRESS_RAW = 0x20000000
NATIVE_PROVENANCE = 'Windows Cabinet CreateDecompressor/Decompress, XPRESS_HUFF | COMPRESS_RAW'
SYNTHETIC_PROVENANCE = 'Synthetic transport contracts only; no Windows codec observation'
AUTHOR_FILES = ('windows_xpress_fixtures.py', 'huffman_fixtures.py', 'wof_fixtures.py', 'lzx_fixtures.py')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unchanged(path, expected):
    if path.is_symlink():
        return False
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size != len(expected):
            return False
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            return stream.read(len(expected) + 1) == expected
    finally:
        os.close(descriptor)


class NativeStageError(RuntimeError):
    def __init__(self, stage, message):
        super().__init__(message)
        self.stage = stage


class WindowsDecoder:
    def __init__(self):
        if sys.platform != 'win32':
            raise RuntimeError('Native XPRESS collection requires Windows Python')
        self.library = ct.WinDLL('cabinet.dll', use_last_error=True)
        self.create = self.library.CreateDecompressor
        self.create.argtypes = (ct.c_uint32, ct.c_void_p, ct.POINTER(ct.c_void_p))
        self.create.restype = ct.c_int32
        self.reset = self.library.ResetDecompressor
        self.reset.argtypes = (ct.c_void_p,)
        self.reset.restype = ct.c_int32
        self.function = self.library.Decompress
        self.function.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_size_t, ct.c_void_p,
                                  ct.c_size_t, ct.POINTER(ct.c_size_t))
        self.function.restype = ct.c_int32
        self.release = self.library.CloseDecompressor
        self.release.argtypes = (ct.c_void_p,)
        self.release.restype = ct.c_int32
        self.handle = ct.c_void_p()
        ct.set_last_error(0)
        if not self.create(COMPRESS_ALGORITHM_XPRESS_HUFF | COMPRESS_RAW, None,
                           ct.byref(self.handle)):
            raise OSError(ct.get_last_error(), 'CreateDecompressor refused XPRESS_HUFF raw mode')
        if not self.handle.value:
            raise RuntimeError('CreateDecompressor returned a null handle after success')

    def decode(self, packed, expected_size):
        ct.set_last_error(0)
        if not self.reset(self.handle):
            raise NativeStageError('reset', f'ResetDecompressor failed: Win32 {ct.get_last_error()}')
        input_array = (ct.c_ubyte * (len(packed) + GUARD_BYTES * 2))()
        output_array = (ct.c_ubyte * (expected_size + GUARD_BYTES * 2))()
        ct.memset(input_array, GUARD_VALUE, ct.sizeof(input_array))
        ct.memset(output_array, GUARD_VALUE, ct.sizeof(output_array))
        ct.memmove(ct.addressof(input_array) + GUARD_BYTES, packed, len(packed))
        written = ct.c_size_t(-1)
        ct.set_last_error(0)
        accepted = bool(self.function(self.handle, ct.addressof(input_array) + GUARD_BYTES,
                                      len(packed), ct.addressof(output_array) + GUARD_BYTES,
                                      expected_size, ct.byref(written)))
        error = 0 if accepted else ct.get_last_error()
        guard = bytes([GUARD_VALUE]) * GUARD_BYTES
        output = bytes(output_array)
        return dict(accepted=accepted, last_error=error, written=written.value,
                    input_unchanged=bytes(input_array) == guard + packed + guard,
                    output_guards=output[:GUARD_BYTES] == guard and output[-GUARD_BYTES:] == guard,
                    data=output[GUARD_BYTES:-GUARD_BYTES])

    def close(self):
        handle, self.handle = self.handle, None
        ct.set_last_error(0)
        if not self.release(handle):
            raise OSError(ct.get_last_error(), 'CloseDecompressor failed')


def collect(output, *, test_decoder=None, test_vectors=None):
    if test_vectors is not None and test_decoder is None:
        raise ValueError('Synthetic vectors require an explicitly synthetic provider')
    output.mkdir(parents=True, exist_ok=False)
    report = dict(schema='machlin-xpress-windows-v1', complete=False, passed=False,
                  native_observation=False, acquisition_complete=False, stage='authoring',
                  provenance=SYNTHETIC_PROVENANCE if test_decoder is not None else NATIVE_PROVENANCE,
                  platform=platform.platform(), python=platform.python_version(),
                  collector_sha256=digest(Path(__file__).read_bytes()),
                  author_sha256={},
                  algorithm=COMPRESS_ALGORITHM_XPRESS_HUFF, raw_flag=COMPRESS_RAW,
                  cases=[])
    decoder = None
    try:
        report['author_sha256'] = {name: digest((ROOT / 'tests' / name).read_bytes()) for name in AUTHOR_FILES}
        corpus = output / 'corpus'
        corpus.mkdir()
        authored, names, total = [], set(), 0
        for index, (name, packed, original, required) in enumerate(
                vectors() if test_vectors is None else test_vectors):
            if index >= MAX_CASES or name in names:
                raise ValueError('Corpus exceeds case bound or duplicates an identity')
            if not 0 < len(original) <= MAX_INPUT_BYTES or not 0 < len(packed) <= MAX_PACKED_BYTES:
                raise ValueError('Corpus member exceeds a nonempty packet bound')
            total += len(original) + len(packed)
            if total > MAX_CORPUS_BYTES:
                raise ValueError('Corpus exceeds aggregate byte bound')
            names.add(name)
            plain_path, packet_path = corpus / f'case-{index:04d}.data', corpus / f'case-{index:04d}.packed'
            with plain_path.open('xb') as stream:
                stream.write(original)
            with packet_path.open('xb') as stream:
                stream.write(packed)
            authored.append((name, plain_path, packet_path, original, packed, bool(required)))
        if not authored or not any(item[-1] for item in authored):
            raise ValueError('No required native packet cases were authored')
        report.update(expected_cases=len(authored), expected_required_cases=sum(item[-1] for item in authored),
                      corpus_bytes=total, stage='acquisition')
        decoder = test_decoder if test_decoder is not None else WindowsDecoder()
        report.update(acquisition_complete=True, stage='decompression')
        for name, plain_path, packet_path, original, packed, required in authored:
            report['active_case'] = name
            result = decoder.decode(packed, len(original))
            report['native_observation'] = test_decoder is None
            row = dict(case=name, required=required, original_bytes=len(original), packed_bytes=len(packed),
                       original_sha256=digest(original), packed_sha256=digest(packed),
                       accepted=result['accepted'], last_error=result['last_error'], written=result['written'],
                       input_unchanged=result['input_unchanged'], output_guards=result['output_guards'],
                       content_matches=result['data'] == original,
                       source_files_unchanged=unchanged(plain_path, original) and unchanged(packet_path, packed))
            row['compatible'] = (row['accepted'] and row['written'] == len(original) and row['content_matches'])
            row['integrity_passed'] = row['input_unchanged'] and row['output_guards'] and row['source_files_unchanged']
            report['cases'].append(row)
            # A native acceptance with wrong bytes is always a failed observation,
            # including variants whose rejection is an allowed compatibility result.
            if not row['integrity_passed'] or (row['accepted'] or required) and not row['compatible']:
                raise NativeStageError('comparison', f'Native XPRESS observation failed for {name}')
        report.update(complete=True, passed=True, stage='complete',
                      native_observation=test_decoder is None,
                      required_cases=sum(row['required'] for row in report['cases']),
                      accepted_cases=sum(row['accepted'] for row in report['cases']),
                      compatibility_refusals=[row['case'] for row in report['cases'] if not row['accepted']])
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
        report['failure_stage'] = getattr(error, 'stage', report['stage'])
    finally:
        if decoder is not None:
            try:
                decoder.close()
                report['closed'] = True
            except Exception as error:
                report.update(complete=False, passed=False,
                              cleanup_error=f'{type(error).__name__}: {error}',
                              failure_stage=report.get('failure_stage', 'cleanup'))
        with (output / 'report.json').open('x', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    report = collect(arguments.output)
    print(json.dumps({name: report.get(name) for name in (
        'passed', 'complete', 'native_observation', 'stage', 'expected_cases',
        'required_cases', 'accepted_cases', 'compatibility_refusals', 'error', 'cleanup_error')}))
    return 0 if report['passed'] and report['native_observation'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
