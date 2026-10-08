"""Author independent USN record packets, including refused and truncated forms."""
from pathlib import Path
import argparse
import struct

V2 = struct.Struct('<IHHQQQQIIIIHH')
V3 = struct.Struct('<IHH16s16sQQIIIIHH')
ALIGNMENT = 8
MAX_NAME_BYTES = 65534


def packet(version, name, gap=0):
    prefix = V2 if version == 2 else V3
    offset = prefix.size + gap
    length = (offset + len(name) + ALIGNMENT - 1) // ALIGNMENT * ALIGNMENT
    identifiers = (0x1000000000018, 0x1000000000005) if version == 2 else (
        bytes(range(16)), bytes(range(16, 32)))
    # Opaque source/reason bits and full-width timestamp must survive framing.
    header = prefix.pack(length, version, 0, *identifiers, 4096, (1 << 64) - 1,
                         0x80002001, 0x80000001, 256, 0x20, len(name), offset)
    return header + bytes(gap) + name + bytes(length - offset - len(name))


def generate(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    seeds = {'empty': b'', 'v4-header': struct.pack('<IHH', ALIGNMENT, 4, 0)}
    for version in (2, 3):
        for label, name, gap in (('empty-name', b'', 0),
                                 ('ordinary', 'name-Ω'.encode('utf-16le'), 0),
                                 ('unpaired', b'\x00\xd8', 0),
                                 ('gap', b'A\x00', ALIGNMENT),
                                 ('maximum-name', b'Z\x00' * (MAX_NAME_BYTES // 2), 0)):
            value = packet(version, name, gap)
            stem = f'v{version}-{label}'
            seeds[stem] = value
            seeds[stem + '-short'] = value[:-1]
            if label == 'ordinary':
                for cut in range(len(value)):
                    seeds[f'{stem}-cut-{cut}'] = value[:cut]
                changed = bytearray(value)
                # Major/minor versions follow the DWORD record byte count.
                struct.pack_into('<H', changed, struct.calcsize('<IH'), 1)
                seeds[stem + '-minor'] = bytes(changed)
                seeds[stem + '-trailing'] = value + b'trailing-record-bytes'
    paths = []
    for name, value in sorted(seeds.items()):
        path = output / (name + '.seed')
        path.write_bytes(value)
        paths.append(path)
    return paths


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='New output directory; existing paths refuse')
    args = parser.parse_args()
    print(f'Authored {len(generate(args.output))} independent USN seeds')
