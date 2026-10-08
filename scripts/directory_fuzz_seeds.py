#!/usr/bin/env python3
"""Author bounded directory operation inputs; generation never executes the driver."""
from pathlib import Path
import argparse
import random
import struct

HEADER = struct.Struct('<HHBBH')  # initial keys, allocation failure, order, case mode, salt
OPERATION = struct.Struct('<BBHI')  # opcode, length selector, identifier, metadata stamp
KEYS = 768
MAX_BYTES = 32768
MAX_OPERATIONS = (MAX_BYTES - HEADER.size) // OPERATION.size
ADD, REMOVE, UPDATE, RENAME, LOOKUP, CLEAR = range(6)


def encode(operations, *, initial=0, fail=0, order=0, case_sensitive=0, salt=0):
    assert 0 <= initial <= KEYS and len(operations) <= MAX_OPERATIONS
    return HEADER.pack(initial, fail, order, case_sensitive, salt) + b''.join(
        OPERATION.pack(*operation) for operation in operations)


def authored():
    result = {}
    for order, label in enumerate(('ascending', 'descending', 'permuted')):
        identifiers = list(range(KEYS))
        if order == 1:
            identifiers.reverse()
        elif order == 2:
            identifiers = [(index * 307) % KEYS for index in identifiers]
        operations = [(UPDATE, 0, key, key + 1) for key in identifiers[::7]]
        operations += [(RENAME, 251 if key % 2 else 0, key, key + 2) for key in identifiers[::3]]
        operations += [(REMOVE, 0, key, 0) for key in identifiers]
        # The same model must grow again after becoming an empty resident root.
        operations += [(ADD, key % 252, key, key + 3) for key in identifiers]
        operations += [(CLEAR, 0, key, 0) for key in identifiers]
        result[label] = encode(operations, initial=KEYS, order=order, salt=order)
    result['duplicate-and-absent'] = encode([
        (ADD, 251, 0, 1), (ADD, 0, 0, 2), (LOOKUP, 0, 0, 0),
        (REMOVE, 0, 0, 0), (REMOVE, 0, 0, 0), (UPDATE, 0, 0, 0),
        (ADD, 0, 0, 3), (RENAME, 251, 0, 4), (UPDATE, 0, 0, 5)])
    for allocation in range(1, 97):
        result[f'allocation-{allocation:03d}'] = encode(
            [(REMOVE, 0, key, 0) for key in range(KEYS)], initial=KEYS,
            fail=allocation, order=2, salt=allocation)
    return result


def generate(output, *, stress=0, seed=0):
    output.mkdir(parents=True, exist_ok=True)
    cases = authored()
    rng = random.Random(seed)
    for index in range(stress):
        operations = [(rng.randrange(6), rng.randrange(256), rng.randrange(KEYS),
                       rng.getrandbits(32)) for _ in range(MAX_OPERATIONS)]
        cases[f'stress-{index:05d}'] = encode(operations, initial=rng.randrange(KEYS + 1),
            fail=0 if index % 4 else rng.randrange(1, 256), order=index % 3,
            case_sensitive=index % 2, salt=rng.randrange(65536))
    for name, data in cases.items():
        (output / (name + '.seed')).write_bytes(data)
    return sorted(output.glob('*.seed'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('stamp', type=Path, nargs='?')
    parser.add_argument('--stress', type=int, default=0)
    parser.add_argument('--seed', type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.stress <= 10000:
        parser.error('--stress must be between 0 and 10000')
    generate(args.output, stress=args.stress, seed=args.seed)
    if args.stamp:
        args.stamp.write_text('directory operation inputs\n')


if __name__ == '__main__':
    main()
