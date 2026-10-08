#!/usr/bin/env python3
"""Independent canonical alphabets at every word offset, plus CPU workloads."""
from pathlib import Path
import sys

import lzx_fixtures as lzx
import wof_fixtures as xpress

SMALL_BLOCK_BYTES = 32


def chain(count, maximum, last):
    lengths = [0] * count
    for symbol in range(maximum - 1):
        lengths[symbol] = symbol + 1
    lengths[maximum - 1] = lengths[last] = maximum
    return lengths


def workloads():
    short = {ord('A'): (0, 1), ord('B'): (2, 2), xpress.END_SYMBOL: (3, 2)}
    uniform = {symbol: (symbol, xpress.UNIFORM_CODE_BITS) for symbol in range(xpress.SYMBOLS)}
    long = lzx.canonical(chain(xpress.SYMBOLS, xpress.MAX_CODE_BITS, xpress.END_SYMBOL))
    for name, codes, pattern, size in (
        ('short-codes', short, b'AB', xpress.UNIT_4K),
        ('long-codes', long, bytes([xpress.MAX_CODE_BITS - 1]), xpress.UNIT_4K),
        ('mixed-codes', long, bytes(range(xpress.MAX_CODE_BITS)), xpress.UNIT_4K),
        ('small-tree', uniform, b'AB', SMALL_BLOCK_BYTES),
    ):
        original = (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]
        yield 'xpress', name, xpress.encode(codes, map(xpress.literal, original)), original

    long = chain(lzx.MAIN_SYMBOLS, lzx.MAX_CODE_BITS, ord('A'))
    short = lzx.selected(lzx.MAIN_SYMBOLS, (ord('A'), ord('B')))
    for name, main, pattern, size in (
        ('short-codes', short, b'AB', lzx.UNIT_BYTES),
        ('long-codes', long, b'A', lzx.UNIT_BYTES),
        ('mixed-codes', long, bytes(range(lzx.MAX_CODE_BITS)) + b'A', lzx.UNIT_BYTES),
        ('small-tree', lzx.alphabet(lzx.MAIN_SYMBOLS), b'AB', SMALL_BLOCK_BYTES),
    ):
        original = (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]
        packet = lzx.Packet()
        packet.compressed(size, map(lzx.literal, original), main=main)
        yield 'lzx', name, packet.finish(), original


def vectors():
    codes = lzx.canonical(chain(xpress.SYMBOLS, xpress.MAX_CODE_BITS, xpress.END_SYMBOL))
    for width in range(1, xpress.MAX_CODE_BITS + 1):
        for offset in range(xpress.WORD_BITS):
            original = bytes(offset) + bytes([width - 1])
            yield 'xpress', f'width-{width}-offset-{offset}', \
                xpress.encode(codes, map(xpress.literal, original)), original

    main = chain(lzx.MAIN_SYMBOLS, lzx.MAX_CODE_BITS, ord('A'))
    empty_lengths = [0] * lzx.LENGTH_SYMBOLS
    probe = lzx.Packet()
    probe.compressed(1, [], main=main, lengths=empty_lengths)
    header_bits = sum(map(len, probe.fragments))
    for width in range(1, lzx.MAX_CODE_BITS + 1):
        for offset in range(lzx.WORD_BITS):
            padding = (offset - header_bits) % lzx.WORD_BITS
            original = bytes(padding) + bytes([width - 1])
            packet = lzx.Packet()
            packet.compressed(len(original), map(lzx.literal, original),
                              main=main, lengths=empty_lengths)
            assert (header_bits + padding) % lzx.WORD_BITS == offset
            # No lookahead: the last short symbol must work with fewer than
            # eight available bits and no speculative read of the next word.
            yield 'lzx', f'width-{width}-offset-{offset}', packet.finish(False), original

    # Cover both bit readers' interleaved byte fields, all secondary trees,
    # retained length deltas, raw transitions and optional final words.
    for codec, cases in (('xpress', xpress.vectors()), ('lzx', lzx.vectors())):
        for name, (packed, original) in cases.items():
            extension_case = codec == 'xpress' and (
                name.startswith('prefetch-') or name == 'interleaved-extensions'
                or name in ('long-match-273', 'long-match-274'))
            if original and (len(original) <= lzx.LITERALS or extension_case):
                yield codec, f'grammar-{name}', packed, original


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    names = []
    for codec, name, packed, original in vectors():
        stem = f'{codec}-{name}'
        (output / f'{stem}.packed').write_bytes(packed)
        (output / f'{stem}.data').write_bytes(original)
        names.append(f'{codec} {stem}\n')
    (output / 'cases.txt').write_text(''.join(names))


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('Independent Huffman word-boundary packets authored\n')
