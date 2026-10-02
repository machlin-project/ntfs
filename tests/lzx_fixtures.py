#!/usr/bin/env python3
"""Original declarative WOF/WIM LZX packets and independently expected bytes.

The author lays out words, alphabets and explicit tokens. It never runs or
imports a decoder. Raw payloads and match witnesses provide byte oracles.
"""
from pathlib import Path
import struct
import sys

BYTE_BITS = 8
WORD = struct.Struct('<H')
WORD_BITS = WORD.size * BYTE_BITS
OFFSETS = struct.Struct('<III')
UNIT_BYTES = 32768
LITERALS = 256
POSITION_SLOTS = 30
NO_FOOTER_SLOTS = 4
REPEATED_OFFSETS, INITIAL_OFFSET, OFFSET_BIAS = 3, 1, 2
LENGTH_HEADER_BITS = 3
LENGTH_HEADERS = 1 << LENGTH_HEADER_BITS
MAIN_SYMBOLS = LITERALS + POSITION_SLOTS * LENGTH_HEADERS
MIN_MATCH, MAX_MATCH = 2, 257
SECONDARY_BASE = MIN_MATCH + LENGTH_HEADERS - 1
LENGTH_SYMBOLS = MAX_MATCH - SECONDARY_BASE + 1
PRETREE_SYMBOLS, PRETREE_LENGTH_BITS = 20, 4
ALIGNED_SYMBOLS, ALIGNED_BITS = 8, 3
MAX_CODE_BITS = 16
MAX_PRETREE_BITS = (1 << PRETREE_LENGTH_BITS) - 1
MAX_ALIGNED_BITS = (1 << ALIGNED_BITS) - 1
BLOCK_TYPE_BITS, DEFAULT_FLAG_BITS, SIZE_BITS = 3, 1, 16
VERBATIM, ALIGNED, RAW = 1, 2, 3
ZERO_SHORT, ZERO_LONG, REPEAT = 17, 18, 19
ZERO_SHORT_BASE, ZERO_SHORT_BITS = 4, 4
ZERO_LONG_BASE, ZERO_LONG_BITS = 20, 5
REPEAT_BASE, REPEAT_BITS = 4, 1
LENGTH_MODULUS = MAX_CODE_BITS + 1
E8_OPCODE, E8_PARAMETER, E8_TAIL_BYTES = 0xe8, 12000000, 10
CALL = struct.Struct('<i')
CALL_BYTES = 1 + CALL.size
KIND_LZX = 3
WOF_LZX_ALGORITHM = 1
FUZZ_HEADER = struct.Struct('<BIQQI')


def canonical(lengths):
    codes, value, previous = {}, 0, 0
    for symbol in sorted(range(len(lengths)), key=lambda index: (lengths[index], index)):
        width = lengths[symbol]
        if not width:
            continue
        value <<= width - previous
        assert value < (1 << width)
        codes[symbol] = (value, width)
        value += 1
        previous = width
    return codes


def alphabet(count):
    short_bits = count.bit_length() - 1
    short_count = (1 << (short_bits + 1)) - count
    return [short_bits] * short_count + [short_bits + 1] * (count - short_count)


def selected(count, symbols):
    result = [0] * count
    widths = alphabet(len(symbols))
    for symbol, width in zip(sorted(symbols), widths):
        result[symbol] = width
    return result


def literal(value):
    return ('literal', value)


def match(slot, length, extra=0):
    return ('match', slot, length, extra)


class Packet:
    def __init__(self):
        self.fragments = []
        self.data = bytearray()
        self.prior_main = [0] * MAIN_SYMBOLS
        self.prior_length = [0] * LENGTH_SYMBOLS

    def bits(self, value, width):
        assert 0 <= value < (1 << width)
        if width:
            self.fragments.append(f'{value:0{width}b}')

    def code(self, symbol, codes):
        value, width = codes[symbol]
        self.bits(value, width)

    def words(self, mandatory=False):
        bits = ''.join(self.fragments)
        padding = (-len(bits)) % WORD_BITS
        if mandatory and padding == 0:
            padding = WORD_BITS
        bits += '0' * padding
        self.data.extend(b''.join(WORD.pack(int(bits[index:index + WORD_BITS], 2))
                                  for index in range(0, len(bits), WORD_BITS)))
        self.fragments.clear()

    def header(self, kind, size, default=False):
        self.bits(kind, BLOCK_TYPE_BITS)
        self.bits(int(default), DEFAULT_FLAG_BITS)
        if not default:
            self.bits(size, SIZE_BITS)

    def lengths(self, values, prior, pretree=None, rle=True):
        pretree = alphabet(PRETREE_SYMBOLS) if pretree is None else pretree
        codes = canonical(pretree)
        for width in pretree:
            self.bits(width, PRETREE_LENGTH_BITS)
        index = 0
        while index < len(values):
            run = 1
            while index + run < len(values) and values[index + run] == values[index]:
                run += 1
            if rle and values[index] == 0 and run >= ZERO_LONG_BASE:
                take = min(run, ZERO_LONG_BASE + (1 << ZERO_LONG_BITS) - 1)
                self.code(ZERO_LONG, codes)
                self.bits(take - ZERO_LONG_BASE, ZERO_LONG_BITS)
            elif rle and values[index] == 0 and run >= ZERO_SHORT_BASE:
                take = min(run, ZERO_SHORT_BASE + (1 << ZERO_SHORT_BITS) - 1)
                self.code(ZERO_SHORT, codes)
                self.bits(take - ZERO_SHORT_BASE, ZERO_SHORT_BITS)
            elif rle and run >= REPEAT_BASE:
                take = min(run, REPEAT_BASE + (1 << REPEAT_BITS) - 1)
                self.code(REPEAT, codes)
                self.bits(take - REPEAT_BASE, REPEAT_BITS)
                self.code((prior[index] - values[index]) % LENGTH_MODULUS, codes)
            else:
                take = 1
                self.code((prior[index] - values[index]) % LENGTH_MODULUS, codes)
            index += take

    def compressed(self, size, tokens, kind=VERBATIM, main=None, lengths=None,
                   aligned=None, pretree=None, rle=True, default=False):
        main = alphabet(MAIN_SYMBOLS) if main is None else main
        lengths = alphabet(LENGTH_SYMBOLS) if lengths is None else lengths
        aligned = [ALIGNED_BITS] * ALIGNED_SYMBOLS if aligned is None else aligned
        self.header(kind, size, default)
        if kind == ALIGNED:
            for width in aligned:
                self.bits(width, ALIGNED_BITS)
        self.lengths(main[:LITERALS], self.prior_main[:LITERALS], pretree, rle)
        self.lengths(main[LITERALS:], self.prior_main[LITERALS:], pretree, rle)
        self.lengths(lengths, self.prior_length, pretree, rle)
        self.prior_main = list(main)
        self.prior_length = list(lengths)
        main_codes, length_codes, aligned_codes = map(canonical, (main, lengths, aligned))
        for token in tokens:
            if token[0] == 'literal':
                self.code(token[1], main_codes)
                continue
            _, slot, length, extra = token
            header = min(length - MIN_MATCH, LENGTH_HEADERS - 1)
            self.code(LITERALS + slot * LENGTH_HEADERS + header, main_codes)
            if header == LENGTH_HEADERS - 1:
                self.code(length - SECONDARY_BASE, length_codes)
            bits = 0 if slot < NO_FOOTER_SLOTS else slot // 2 - 1
            if kind == ALIGNED and bits >= ALIGNED_BITS:
                self.bits(extra >> ALIGNED_BITS, bits - ALIGNED_BITS)
                self.code(extra & (ALIGNED_SYMBOLS - 1), aligned_codes)
            else:
                self.bits(extra, bits)

    def raw(self, original, offsets=(INITIAL_OFFSET,) * REPEATED_OFFSETS, default=False):
        self.header(RAW, len(original), default)
        self.words(mandatory=True)
        self.data.extend(OFFSETS.pack(*offsets))
        self.data.extend(original)
        if len(original) % WORD.size:
            self.data.extend(b'\0')

    def finish(self, lookahead=True):
        self.words()
        return bytes(self.data) + (WORD.pack(0) if lookahead else b'')


def encode_uniform(original):
    """Useful for integrated fixtures; compress a uniform unit using explicit R0."""
    assert original and len(set(original)) == 1
    length_symbol = LITERALS + LENGTH_HEADERS - 1
    main = selected(MAIN_SYMBOLS, (original[0], length_symbol))
    tokens, remaining = [literal(original[0])], len(original) - 1
    while remaining >= SECONDARY_BASE:
        size = min(MAX_MATCH, remaining)
        tokens.append(match(0, size))
        remaining -= size
    tokens.extend(literal(original[0]) for _ in range(remaining))
    packet = Packet()
    packet.compressed(len(original), tokens, main=main, default=len(original) == UNIT_BYTES)
    return packet.finish()


def vectors():
    result = {'empty': (b'', b'')}

    def compressed(name, original, tokens=None, **options):
        packet = Packet()
        packet.compressed(len(original), list(map(literal, original)) if tokens is None else tokens,
                          **options)
        result[name] = (packet.finish(), original)

    for size in (1, 2, 3, 10, 11, 31, 127, 777, 4096, UNIT_BYTES):
        original = b'A' * size
        packet = Packet()
        packet.raw(original, default=size == UNIT_BYTES)
        result[f'raw-{size}'] = (packet.finish(), original)
        result[f'raw-no-lookahead-{size}'] = (packet.finish(False), original)
        result[f'uniform-{size}'] = (encode_uniform(original), original)
    compressed('all-literals', bytes(range(LITERALS)) * 3)
    compressed('plain-length-codes', b'AB' * 19, rle=False)
    compressed('empty-unused-trees', b'AB' * 19,
               main=selected(MAIN_SYMBOLS, (ord('A'), ord('B'))),
               lengths=[0] * LENGTH_SYMBOLS, aligned=[0] * ALIGNED_SYMBOLS, kind=ALIGNED)
    chain = [0] * MAIN_SYMBOLS
    for symbol in range(MAX_CODE_BITS - 1):
        chain[symbol] = symbol + 1
    chain[MAX_CODE_BITS - 1] = chain[ord('A')] = MAX_CODE_BITS
    compressed('main-code-sixteen', bytes(range(MAX_CODE_BITS)) + b'A', main=chain)
    pre_chain = [0] * PRETREE_SYMBOLS
    for symbol in range(MAX_PRETREE_BITS - 1):
        pre_chain[symbol] = symbol + 1
    pre_chain[MAX_PRETREE_BITS - 1] = pre_chain[REPEAT] = MAX_PRETREE_BITS
    compressed('pretree-code-fifteen', b'Ab7' * 19, pretree=pre_chain, rle=False)
    secondary_chain = [0] * LENGTH_SYMBOLS
    for symbol in range(MAX_CODE_BITS - 1):
        secondary_chain[symbol] = symbol + 1
    secondary_chain[MAX_CODE_BITS - 1] = secondary_chain[MAX_CODE_BITS] = MAX_CODE_BITS
    compressed('length-code-sixteen', b'A' * 26,
               [literal(65), match(0, SECONDARY_BASE + 16)], lengths=secondary_chain)
    aligned_chain = list(range(1, MAX_ALIGNED_BITS)) + [MAX_ALIGNED_BITS] * 2
    compressed('aligned-code-seven', bytes(range(21)) + bytes(range(2)),
               [*map(literal, bytes(range(21))), match(8, 2, 7)],
               kind=ALIGNED, aligned=aligned_chain)
    for length in range(MIN_MATCH, MAX_MATCH + 1):
        if length < SECONDARY_BASE or length in (9, 10, 127, 128, 255, 256, MAX_MATCH):
            compressed(f'length-{length}', b'Ab7' + (b'Ab7' * length)[:length],
                       [*map(literal, b'Ab7'), match(4, length, 1)])
    for kind, name in ((VERBATIM, 'verbatim'), (ALIGNED, 'aligned')):
        for slot in range(REPEATED_OFFSETS, POSITION_SLOTS):
            bits = 0 if slot < NO_FOOTER_SLOTS else slot // 2 - 1
            extra = (1 << bits) - 1
            distance = INITIAL_OFFSET if slot == REPEATED_OFFSETS else ((2 + (slot & 1)) << bits) - OFFSET_BIAS + extra
            prefix = (b'Ab7' * (distance + 1))[:distance]
            compressed(f'{name}-slot-{slot}', prefix + (prefix * MIN_MATCH)[:MIN_MATCH],
                       [*map(literal, prefix), match(slot, MIN_MATCH, extra)], kind=kind)
    packet = Packet()
    original = b'0123456789'
    packet.raw(original, offsets=(3, 7, 5))
    packet.compressed(8, [match(1, 2), match(2, 2), match(1, 2), match(0, 2)])
    # R1 swaps with R0: (7,3,5), R2 swaps: (5,3,7), R1 swaps: (3,5,7).
    result['raw-repeat-queue'] = (packet.finish(), original + b'34784784')
    original = b'0123456789abcdefghijklmn'
    packet = Packet()
    packet.compressed(len(original) + 14,
                      [*map(literal, original), match(4, 2, 1), match(6, 2, 1),
                       match(5, 2, 1), match(1, 2), match(2, 2), match(1, 2), match(0, 2)])
    result['new-repeat-queue'] = (packet.finish(), original + b'lmjknlnllnlnll')
    packet = Packet()
    packet.compressed(19, map(literal, b'A' * 19), main=selected(MAIN_SYMBOLS, (65, 66)))
    packet.compressed(23, map(literal, b'B' * 23), main=selected(MAIN_SYMBOLS, (65, 66)))
    packet.raw(b'raw')
    packet.compressed(2, [match(0, 2)], main=alphabet(MAIN_SYMBOLS))
    result['block-length-deltas'] = (packet.finish(), b'A' * 19 + b'B' * 23 + b'rawww')
    # CALL fixtures specify encoded absolute operands and expected relative ones.
    for position in (0, 1, 7, 17):
        for operand in (0, position, -position, -position - 1, E8_PARAMETER - 1,
                        E8_PARAMETER, -1):
            encoded = b'\x90' * position + bytes([E8_OPCODE]) + CALL.pack(operand) + b'Z' * 19
            transformed = operand
            if -position <= operand < E8_PARAMETER:
                transformed = operand - position if operand >= 0 else operand + E8_PARAMETER
            original = encoded[:position + 1] + CALL.pack(transformed) + encoded[position + CALL_BYTES:]
            packet = Packet()
            packet.raw(encoded)
            result[f'call-{position}-{operand}'] = (packet.finish(), original)
    for tail in range(E8_TAIL_BYTES - CALL.size):
        original = b'Q' * 19 + bytes([E8_OPCODE]) + CALL.pack(127) + b'Q' * tail
        packet = Packet()
        packet.raw(original)
        result[f'call-tail-{tail}'] = (packet.finish(), original)
    original = bytes([E8_OPCODE]) + CALL.pack(E8_OPCODE) + b'Q' * 19
    packet = Packet()
    packet.raw(original)
    result['call-operand-opcode'] = (packet.finish(), original)
    return result


def invalid_vectors():
    result = {}
    for kind in (0, 4, 5, 6, 7):
        packet = Packet()
        packet.header(kind, 1)
        result[f'reserved-type-{kind}'] = (packet.finish(), 1)
    for size, expected in ((0, 1), (2, 1)):
        packet = Packet()
        packet.header(VERBATIM, size)
        result[f'invalid-block-size-{size}'] = (packet.finish(), expected)
    packet = Packet()
    packet.raw(b'ABC')
    raw = packet.finish(False)
    for size in (0, 1, 2, OFFSETS.size, len(raw) - 2, len(raw) - 1):
        result[f'raw-truncated-{size}'] = (raw[:size], 3)
    for name, lengths in (('empty-main', [0] * MAIN_SYMBOLS),
                          ('incomplete-main', [1] + [0] * (MAIN_SYMBOLS - 1))):
        packet = Packet()
        packet.compressed(1, [], main=lengths)
        result[name] = (packet.finish(), 1)
    packet = Packet()
    packet.header(VERBATIM, 1)
    for _ in range(PRETREE_SYMBOLS):
        packet.bits(1, PRETREE_LENGTH_BITS)
    result['oversubscribed-pretree'] = (packet.finish(), 1)
    packet = Packet()
    packet.header(VERBATIM, 1)
    for _ in range(PRETREE_SYMBOLS):
        packet.bits(0, PRETREE_LENGTH_BITS)
    result['empty-pretree'] = (packet.finish(), 1)
    for name, widths in (('oversubscribed-aligned', [1] * ALIGNED_SYMBOLS),
                         ('incomplete-aligned', [1] + [0] * (ALIGNED_SYMBOLS - 1))):
        packet = Packet()
        packet.header(ALIGNED, 1)
        for width in widths:
            packet.bits(width, ALIGNED_BITS)
        result[name] = (packet.finish(), 1)
    packet = Packet()
    packet.header(VERBATIM, 1)
    packet.lengths([1] * LITERALS, [0] * LITERALS)
    packet.lengths([1] * (MAIN_SYMBOLS - LITERALS), [0] * (MAIN_SYMBOLS - LITERALS))
    packet.lengths([0] * LENGTH_SYMBOLS, [0] * LENGTH_SYMBOLS)
    result['oversubscribed-main'] = (packet.finish(), 1)
    for name, repeat_symbol in (('zero-run-crosses-range', ZERO_SHORT),
                                ('repeat-crosses-range', REPEAT),
                                ('repeat-nested-run', REPEAT)):
        packet = Packet()
        packet.header(VERBATIM, 1)
        pretree = alphabet(PRETREE_SYMBOLS)
        codes = canonical(pretree)
        for width in pretree:
            packet.bits(width, PRETREE_LENGTH_BITS)
        if name != 'repeat-nested-run':
            for _ in range(5):
                packet.code(ZERO_LONG, codes)
                packet.bits((1 << ZERO_LONG_BITS) - 1, ZERO_LONG_BITS)
        packet.code(repeat_symbol, codes)
        packet.bits(0, ZERO_SHORT_BITS if repeat_symbol == ZERO_SHORT else REPEAT_BITS)
        if repeat_symbol == REPEAT:
            packet.code(ZERO_SHORT if name == 'repeat-nested-run' else 0, codes)
        result[name] = (packet.finish(), 1)
    packet = Packet()
    packet.raw(bytes(range(16)))
    packet.compressed(2, [], kind=ALIGNED, aligned=[0] * ALIGNED_SYMBOLS)
    packet.code(LITERALS + 8 * LENGTH_HEADERS, canonical(alphabet(MAIN_SYMBOLS)))
    result['empty-used-aligned-tree'] = (packet.finish(), 18)
    for name, tokens, expected in (
            ('match-before-start', [match(0, 2)], 2),
            ('distance-before-start', [literal(65), match(4, 2)], 3),
            ('match-crosses-block', [literal(65), match(0, 10)], 10)):
        packet = Packet()
        packet.compressed(expected, tokens)
        result[name] = (packet.finish(), expected)
    packet = Packet()
    packet.raw(b'ABC', offsets=(0, 1, 1))
    packet.compressed(2, [match(0, 2)])
    result['zero-repeated-distance'] = (packet.finish(), 5)
    packet = Packet()
    packet.compressed(10, [literal(65)], lengths=[0] * LENGTH_SYMBOLS)
    packet.code(LITERALS + LENGTH_HEADERS - 1, canonical(alphabet(MAIN_SYMBOLS)))
    result['empty-used-length-tree'] = (packet.finish(), 10)
    packed = encode_uniform(b'A' * 777)
    result['compressed-truncation'] = (packed[:len(packed) // 2], 777)
    result['trailing-garbage'] = (packed + b'bad', 777)
    return result


def author(output):
    for directory, cases in (('lzx-vectors', vectors()), ('lzx-invalid', invalid_vectors())):
        target = output / directory
        target.mkdir(parents=True, exist_ok=True)
        for name, (packed, original) in cases.items():
            (target / f'{name}.lzx').write_bytes(packed)
            (target / f'{name}.data').write_bytes(original if isinstance(original, bytes)
                                                 else bytes(original))
        (target / 'cases.txt').write_text('\n'.join(cases) + '\n')
    seeds = output / 'wof'
    seeds.mkdir(parents=True, exist_ok=True)
    for name, (packed, original) in vectors().items():
        (seeds / f'lzx-{name}.seed').write_bytes(
            FUZZ_HEADER.pack(KIND_LZX, WOF_LZX_ALGORITHM, 0, 0, len(original)) + packed)


if __name__ == '__main__':
    root = Path(sys.argv[1])
    author(root)
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('Independent WOF LZX packets authored\n')
