#!/usr/bin/env python3
"""Independent declarative XPRESS vectors and WOF parser fuzz envelopes.

Expected bytes come from original payload patterns, never the decoder. Physical
words are laid out after constructing the complete bit string; raw extensions
are attached to their prefetch boundary rather than using a decoder or bit-reader.
"""
from pathlib import Path
import struct
import sys

BYTE_BITS = 8
WORD = struct.Struct('<H')
WORD_BITS = WORD.size * BYTE_BITS
LOOKAHEAD_WORDS = 2
SYMBOLS = 512
UNIFORM_CODE_BITS = 9
MAX_CODE_BITS = 15
LITERAL_SYMBOLS = 256
NIBBLE_BITS = 4
LENGTHS_PER_BYTE = 2
TABLE_BYTES = SYMBOLS // LENGTHS_PER_BYTE
MAX_BLOCK = 65536
END_SYMBOL = 256
MIN_MATCH = 3
MATCH_LENGTH_BITS = 4
LONG_LENGTH = (1 << MATCH_LENGTH_BITS) - 1
LENGTH_ESCAPE = 255
HEADER = struct.Struct('<BIQQI')
KIND_METADATA, KIND_TABLE, KIND_XPRESS = range(3)
REPARSE = struct.Struct('<IHH')
WOF_FILE = struct.Struct('<IIII')
WOF_TAG = 0x80000017
WOF_VERSION, WOF_PROVIDER_FILE, WOF_FILE_VERSION = 1, 2, 1
WOF_XPRESS_4K, WOF_LZX_32K, WOF_XPRESS_8K, WOF_XPRESS_16K = range(4)
UNIT_4K = 4096
UNIT_32K = 32768
PREFIX_BOUNDARY_CASES = WORD_BITS * 2
SMALL_CHUNKS = 3
PACKED_CHUNK_BYTES = 100
FINAL_CHUNK_BYTES = 3
WORD_MAX = (1 << WORD_BITS) - 1


def literal(value):
    return ('literal', value)


def match(distance, length):
    assert distance > 0 and length >= MIN_MATCH
    return ('match', distance, length)


def encode(codes, tokens, eof=True):
    lengths = bytearray(TABLE_BYTES)
    for symbol, (code, bits) in codes.items():
        assert 0 <= code < (1 << bits) and 1 <= bits <= (1 << NIBBLE_BITS) - 1
        lengths[symbol // LENGTHS_PER_BYTE] |= bits << ((symbol % LENGTHS_PER_BYTE) * NIBBLE_BITS)
    fragments, events = [], {}
    bit_count = 0

    def append_bits(code, count):
        nonlocal bit_count
        if count:
            fragments.append(f'{code:0{count}b}')
            bit_count += count

    sequence = list(tokens) + ([literal(END_SYMBOL)] if eof else [])
    for token in sequence:
        extension = b''
        distance_bits, distance_low = 0, 0
        if token[0] == 'literal':
            symbol = token[1]
        else:
            _, distance, length = token
            distance_bits = distance.bit_length() - 1
            distance_low = distance - (1 << distance_bits)
            reduced = length - MIN_MATCH
            symbol = END_SYMBOL + min(reduced, LONG_LENGTH) + (distance_bits << MATCH_LENGTH_BITS)
            if reduced >= LONG_LENGTH:
                extra = reduced - LONG_LENGTH
                if extra < LENGTH_ESCAPE:
                    extension = bytes([extra])
                elif reduced < MAX_BLOCK:
                    extension = bytes([LENGTH_ESCAPE]) + WORD.pack(reduced)
                else:
                    extension = bytes([LENGTH_ESCAPE]) + WORD.pack(0) + struct.pack('<I', reduced)
        code, count = codes[symbol]
        append_bits(code, count)
        if extension:
            boundary = max(LOOKAHEAD_WORDS, (bit_count + WORD_BITS - 1) // WORD_BITS + 1)
            events.setdefault(boundary, bytearray()).extend(extension)
        append_bits(distance_low, distance_bits)

    bits = ''.join(fragments)
    words = max(LOOKAHEAD_WORDS, (len(bits) + WORD_BITS - 1) // WORD_BITS + 1)
    padded = bits.ljust(words * WORD_BITS, '0')
    output = bytearray(lengths)
    for index in range(words):
        output.extend(events.pop(index, b''))
        output.extend(WORD.pack(int(padded[index * WORD_BITS:(index + 1) * WORD_BITS], 2)))
    output.extend(events.pop(words, b''))
    assert not events
    return bytes(output)


def vectors():
    # Explicit complete canonical alphabets, including the maximum code length.
    uniform = {symbol: (symbol, UNIFORM_CODE_BITS) for symbol in range(SYMBOLS)}
    short = {ord('A'): (0, 1), ord('B'): (2, 2), END_SYMBOL: (3, 2)}
    chain = {symbol: ((1 << (symbol + 1)) - 2, symbol + 1) for symbol in range(MAX_CODE_BITS - 1)}
    chain.update({MAX_CODE_BITS - 1: ((1 << MAX_CODE_BITS) - 2, MAX_CODE_BITS),
                  END_SYMBOL: ((1 << MAX_CODE_BITS) - 1, MAX_CODE_BITS)})
    cases = {}

    def add(name, codes, tokens, expected, eof=True):
        assert len(expected) <= MAX_BLOCK
        cases[name] = (encode(codes, tokens, eof), expected)

    for size in (0, 1, 16, 17, 31, 32, 127, UNIT_4K, UNIT_32K, MAX_BLOCK):
        original = (b'AB' * ((size + 1) // 2))[:size]
        add(f'prefix-{size}', short, map(literal, original), original)
    original = bytes(range(LITERAL_SYMBOLS)) * 3
    add('all-literals', uniform, map(literal, original), original)
    original = bytes(range(MAX_CODE_BITS)) * 19
    add('long-codes', chain, map(literal, original), original)
    add('optional-eof', short, [literal(ord('A'))], b'A', eof=False)
    packed = encode(short, [literal(ord('A'))])
    cases['nonzero-padding'] = (packed[:-WORD.size] + WORD.pack(WORD_MAX), b'A')
    for length in range(MIN_MATCH, LONG_LENGTH + MIN_MATCH):
        original = (b'Ab7' * (length + 1))[:len(b'Ab7') + length]
        add(f'short-match-{length}', uniform,
            [*map(literal, b'Ab7'), match(len(b'Ab7'), length)], original)
    for length in (18, 19, 255, 272, 273, 274, UNIT_4K - 1, UNIT_32K - 1, MAX_BLOCK - 1):
        add(f'long-match-{length}', uniform, [literal(ord('A')), match(1, length)], b'A' * (length + 1))
    for count in range(1, PREFIX_BOUNDARY_CASES + 1):
        length = 273 if count % 2 else 18
        add(f'prefetch-{count}', uniform,
            [*[literal(ord('A'))] * count, match(1, length), literal(ord('B'))],
            b'A' * (count + length) + b'B')
    for bits in range(MAX_CODE_BITS + 1):
        distance = (1 << (bits + 1)) - 1 if bits < MAX_CODE_BITS else MAX_BLOCK - MIN_MATCH - 1
        original = (b'Ab7' * (distance + 1))[:distance]
        add(f'distance-{bits}', uniform,
            [*map(literal, original), match(distance, MIN_MATCH)], original + (original * MIN_MATCH)[:MIN_MATCH])
    add('interleaved-extensions', uniform,
        [*map(literal, b'Ab7'), match(3, 273), match(3, 18), literal(ord('Z'))],
        b'Ab7' * ((3 + 273 + 18) // 3) + b'Z')
    return cases


def invalid_vectors():
    uniform = {symbol: (symbol, UNIFORM_CODE_BITS) for symbol in range(SYMBOLS)}
    empty = bytes(TABLE_BYTES + LOOKAHEAD_WORDS * WORD.size)
    short_raw = encode(uniform, [literal(ord('A')), match(1, 18)])
    long_raw = encode(uniform, [literal(ord('A')), match(1, 273)])
    assert long_raw.endswith(bytes([LENGTH_ESCAPE]) + WORD.pack(273 - MIN_MATCH))
    return {
        'empty-tree': (empty, 1),
        'oversubscribed': (bytes([0x11]) * TABLE_BYTES + bytes(LOOKAHEAD_WORDS * WORD.size), 1),
        'undersubscribed': (bytes([0x01]) + empty[1:], 1),
        'no-prefix-match': (encode(uniform, [match(1, MIN_MATCH)]), MIN_MATCH),
        'distance-overrun': (encode(uniform, [literal(ord('A')), match(2, MIN_MATCH)]), MIN_MATCH + 1),
        'length-overrun': (short_raw, 18),
        'short-raw-extension': (short_raw[:-1], 19),
        'short-word-extension': (long_raw[:-1], 274),
        'invalid-word-extension': (long_raw[:-WORD.size] + WORD.pack(LONG_LENGTH - 1), 274),
        'overlong-dword-extension': (encode(uniform, [literal(ord('A')), match(1, MAX_BLOCK + MIN_MATCH)]), MAX_BLOCK),
        'missing-lookahead': (encode(uniform, [literal(ord('A'))])[:TABLE_BYTES + LOOKAHEAD_WORDS * WORD.size - 1], 1),
    }


def generate(output):
    output = Path(output)
    vector_dir, seed_dir = output / 'xpress-vectors', output / 'wof'
    vector_dir.mkdir(parents=True, exist_ok=True)
    seed_dir.mkdir(parents=True, exist_ok=True)
    names = []
    for name, (packed, original) in vectors().items():
        (vector_dir / f'{name}.xpress').write_bytes(packed)
        (vector_dir / f'{name}.data').write_bytes(original)
        (seed_dir / f'{name}.seed').write_bytes(HEADER.pack(KIND_XPRESS, 0, 0, 0, len(original)) + packed)
        names.append(name)
    (vector_dir / 'cases.txt').write_text('\n'.join(names) + '\n')
    invalid_dir = output / 'xpress-invalid'
    invalid_dir.mkdir(parents=True, exist_ok=True)
    invalid_names = []
    for name, (packed, expected) in invalid_vectors().items():
        (invalid_dir / f'{name}.xpress').write_bytes(packed)
        (invalid_dir / f'{name}.data').write_bytes(bytes(expected))
        (seed_dir / f'{name}.seed').write_bytes(HEADER.pack(KIND_XPRESS, 0, 0, 0, expected) + packed)
        invalid_names.append(name)
    (invalid_dir / 'cases.txt').write_text('\n'.join(invalid_names) + '\n')
    for algorithm in (WOF_XPRESS_4K, WOF_LZX_32K, WOF_XPRESS_8K, WOF_XPRESS_16K):
        payload = WOF_FILE.pack(WOF_VERSION, WOF_PROVIDER_FILE, WOF_FILE_VERSION, algorithm)
        packet = REPARSE.pack(WOF_TAG, len(payload), 0) + payload
        (seed_dir / f'provider-{algorithm}.seed').write_bytes(HEADER.pack(KIND_METADATA, 0, 0, 0, 0) + packet)
    table = struct.pack('<II', PACKED_CHUNK_BYTES, 2 * PACKED_CHUNK_BYTES)
    (seed_dir / 'table.seed').write_bytes(
        HEADER.pack(KIND_TABLE, WOF_XPRESS_4K, UNIT_4K * (SMALL_CHUNKS - 1) + FINAL_CHUNK_BYTES,
                    len(table) + PACKED_CHUNK_BYTES * (SMALL_CHUNKS - 1) + FINAL_CHUNK_BYTES, 0) + table)
    # Small independently authored wire vector: 'A' (0), 'B' (10), EOF (11).
    expected_table = bytearray(TABLE_BYTES)
    expected_table[ord('A') // LENGTHS_PER_BYTE] = 0x10
    expected_table[ord('B') // LENGTHS_PER_BYTE] = 0x02
    expected_table[END_SYMBOL // LENGTHS_PER_BYTE] = 0x02
    assert encode({ord('A'): (0, 1), ord('B'): (2, 2), END_SYMBOL: (3, 2)},
                  [literal(ord('A')), literal(ord('B'))]) == bytes(expected_table) + bytes.fromhex('00580000')


if __name__ == '__main__':
    generate(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).touch()
