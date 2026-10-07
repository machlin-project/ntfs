#!/usr/bin/env python3
"""Author independent inputs for the installed ordinary-mutation syscall test."""
from pathlib import Path
import argparse
import hashlib
import json

WRITE_OFFSET = 257
WRITE_BYTES = 65537
FILE_BYTES = WRITE_OFFSET + WRITE_BYTES
MAPPED_OFFSET = 3997
MAPPED_BYTES = 257


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    output = parser.parse_args().output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    payload = bytes(((index * 37) ^ (index >> 7) ^ 0xA5) & 0xFF
                    for index in range(WRITE_BYTES))
    final = bytearray(FILE_BYTES)
    final[WRITE_OFFSET:] = payload
    mapped = bytes((index * 53 + 0x39) & 0xFF for index in range(MAPPED_BYTES))
    assert mapped != final[MAPPED_OFFSET:MAPPED_OFFSET + MAPPED_BYTES]
    final[MAPPED_OFFSET:MAPPED_OFFSET + MAPPED_BYTES] = mapped
    entries = {}
    for name, data in (('payload.bin', payload), ('final.bin', final)):
        (output / name).write_bytes(data)
        entries[name] = dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    (output / 'result.json').write_text(json.dumps(dict(
        success=True, independentExpectedBytes=True, writeOffset=WRITE_OFFSET,
        mappedOffset=MAPPED_OFFSET, mappedBytes=MAPPED_BYTES, entries=entries),
        indent=2) + '\n')


if __name__ == '__main__':
    main()
