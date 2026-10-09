#!/usr/bin/env python3
"""Unmodified, independently authored XPRESS packets for the native raw API."""
import huffman_fixtures
import wof_fixtures

COMPATIBILITY_CASES = frozenset(('optional-eof', 'nonzero-padding'))


def vectors():
    for codec, name, packed, original in huffman_fixtures.vectors():
        if codec == 'xpress':
            required = name not in {'grammar-' + item for item in COMPATIBILITY_CASES}
            yield 'boundary-' + name, packed, original, required
    for codec, name, packed, original in huffman_fixtures.workloads():
        if codec == 'xpress':
            yield 'workload-' + name, packed, original, True
    for name, (packed, original) in wof_fixtures.vectors().items():
        # A zero output size is the Compression API's size-query interface.
        # The bounded exact-content oracle covers nonempty raw blocks only.
        if original:
            yield 'grammar-' + name, packed, original, name not in COMPATIBILITY_CASES
