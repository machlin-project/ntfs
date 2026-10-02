#!/usr/bin/env python3
"""Capture original payloads through an external wimlib compression API.

The third-party codec is loaded only in this test process. Product binaries do
not link it. Captured inputs, bytes, version and library hash remain artifacts.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from environment import tool_environment

LZX_TYPE = 2
UNIT_BYTES = 32768
COMPRESS_LEVELS = (20, 50, 80)
CALL_OPCODE = 0xe8
CALL_OPERAND_BYTES = ctypes.sizeof(ctypes.c_int32)
CALL_BYTES = 1 + CALL_OPERAND_BYTES
CALL_STRIDE = 37
CALL_TRANSLATION_SIZE = 12000000
CALL_PARAMETERS = (0, 1, 127, CALL_TRANSLATION_SIZE - 1, CALL_TRANSLATION_SIZE,
                   -1, -127, -CALL_TRANSLATION_SIZE)
SIZES = (1, 2, 3, 10, 11, 31, 32, 127, 256, 777, 4096, 8192, 16384, 32767, UNIT_BYTES)
SEED = 0x4c5a58


def payloads():
    rng = random.Random(SEED)
    text = b'Original independent LZX corpus: words, numbers 0123456789 and punctuation.\n'
    calls = bytearray(b'\x90' * UNIT_BYTES)
    for index, position in enumerate(range(0, UNIT_BYTES - CALL_BYTES, CALL_STRIDE)):
        calls[position] = CALL_OPCODE
        value = CALL_PARAMETERS[index % len(CALL_PARAMETERS)]
        calls[position + 1:position + CALL_BYTES] = value.to_bytes(CALL_OPERAND_BYTES, 'little', signed=True)
    random_data = rng.randbytes(UNIT_BYTES)
    mixed = bytearray(random_data)
    for position in range(0, UNIT_BYTES, 1024):
        mixed[position:position + 768] = bytes([position // 1024]) * 768
    sources = {
        'zero': bytes(UNIT_BYTES),
        'constant': b'A' * UNIT_BYTES,
        'period-three': (b'Ab7' * UNIT_BYTES)[:UNIT_BYTES],
        'alphabet': bytes(range(256)) * (UNIT_BYTES // 256),
        'text': (text * UNIT_BYTES)[:UNIT_BYTES],
        'calls': bytes(calls),
        'mixed': bytes(mixed),
        'random': random_data,
    }
    for name, original in sources.items():
        for size in SIZES:
            yield f'{name}-{size}', original[:size]


def bind(library):
    api = ctypes.CDLL(str(library))
    api.wimlib_get_version_string.argtypes = []
    api.wimlib_get_version_string.restype = ctypes.c_char_p
    api.wimlib_create_compressor.argtypes = [ctypes.c_int, ctypes.c_size_t,
                                           ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p)]
    api.wimlib_create_compressor.restype = ctypes.c_int
    api.wimlib_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.c_void_p]
    api.wimlib_compress.restype = ctypes.c_size_t
    api.wimlib_free_compressor.argtypes = [ctypes.c_void_p]
    api.wimlib_free_compressor.restype = None
    api.wimlib_create_decompressor.argtypes = [ctypes.c_int, ctypes.c_size_t,
                                             ctypes.POINTER(ctypes.c_void_p)]
    api.wimlib_create_decompressor.restype = ctypes.c_int
    api.wimlib_decompress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                     ctypes.c_size_t, ctypes.c_void_p]
    api.wimlib_decompress.restype = ctypes.c_int
    api.wimlib_free_decompressor.argtypes = [ctypes.c_void_p]
    api.wimlib_free_decompressor.restype = None
    return api


def external_decode(api, decoder, packed, original):
    source = ctypes.create_string_buffer(packed)
    target = ctypes.create_string_buffer(len(original))
    verdict = api.wimlib_decompress(source, len(packed), target, len(original), decoder)
    if verdict != 0 or target.raw != original:
        raise ValueError(f'external LZX content mismatch: verdict={verdict}, size={len(original)}')


def run(args):
    library = args.library.resolve(strict=True)
    api = bind(library)
    args.output.mkdir(parents=True, exist_ok=False)
    vectors = args.output / 'vectors'
    vectors.mkdir()
    report = {'library': str(library), 'sha256': hashlib.sha256(library.read_bytes()).hexdigest(),
              'version': api.wimlib_get_version_string().decode('ascii'),
              'levels': list(COMPRESS_LEVELS), 'seed': SEED, 'cases': [], 'raw_fallbacks': [],
              'synthetic_checked': [], 'complete': False}
    decoder = ctypes.c_void_p()
    if api.wimlib_create_decompressor(LZX_TYPE, UNIT_BYTES, ctypes.byref(decoder)) != 0:
        raise ValueError('external decompressor creation failed')
    try:
        for level in COMPRESS_LEVELS:
            compressor = ctypes.c_void_p()
            if api.wimlib_create_compressor(LZX_TYPE, UNIT_BYTES, level,
                                            ctypes.byref(compressor)) != 0:
                raise ValueError('external compressor creation failed')
            try:
                for name, original in payloads():
                    source = ctypes.create_string_buffer(original)
                    packed_buffer = ctypes.create_string_buffer(UNIT_BYTES * 2)
                    size = api.wimlib_compress(source, len(original), packed_buffer,
                                              len(packed_buffer), compressor)
                    if size == 0:
                        report['raw_fallbacks'].append({'name': name, 'level': level,
                                                        'original_size': len(original)})
                        continue
                    packed = packed_buffer.raw[:size]
                    external_decode(api, decoder, packed, original)
                    case = f'level-{level}-{name}'
                    (vectors / f'{case}.lzx').write_bytes(packed)
                    (vectors / f'{case}.data').write_bytes(original)
                    report['cases'].append({'name': case, 'original_size': len(original),
                                            'packed_size': len(packed),
                                            'original_sha256': hashlib.sha256(original).hexdigest()})
            finally:
                api.wimlib_free_compressor(compressor)
        if not report['cases']:
            raise ValueError('external compressor produced no encoded cases')
        (vectors / 'cases.txt').write_text('\n'.join(case['name'] for case in report['cases']) + '\n')
        if args.synthetic:
            for case in (args.synthetic / 'cases.txt').read_text().splitlines():
                packed = (args.synthetic / f'{case}.lzx').read_bytes()
                original = (args.synthetic / f'{case}.data').read_bytes()
                if original:
                    external_decode(api, decoder, packed, original)
                    report['synthetic_checked'].append(case)
        if args.reader:
            if not args.invalid:
                raise ValueError('--reader requires --invalid')
            result = subprocess.run([str(args.reader.resolve()), str(vectors.resolve()),
                                     str(args.invalid.resolve())], env=tool_environment(),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=120, check=False)
            (args.output / 'reader.log').write_bytes(result.stdout)
            report['reader_exit'] = result.returncode
            if result.returncode != 0:
                raise ValueError('core LZX reader rejected external corpus; see reader.log')
        report['complete'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        api.wimlib_free_decompressor(decoder)
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'complete': True, 'captured': len(report['cases']),
                      'synthetic_checked': len(report['synthetic_checked']),
                      'version': report['version']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reader', type=Path)
    parser.add_argument('--synthetic', type=Path)
    parser.add_argument('--invalid', type=Path)
    run(parser.parse_args())
