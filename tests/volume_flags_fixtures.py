#!/usr/bin/env python3
"""Original volume-information admission profiles; no flag meaning is inferred."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import fixtures as f

IMAGE_BYTES = 1024 * 1024
VOLUME_INFO = struct.Struct('<QBBH')
VOLUME_DIRTY = 0x0001
VOLUME_FLAG_BITS = struct.calcsize('<H') * f.BYTE_BITS
VOLUME_FLAG_MAX = (1 << VOLUME_FLAG_BITS) - 1
VOLUME_NAME_INSTANCE, VOLUME_INFO_INSTANCE = 1, 2
VOLUME_LABEL = 'Volume admission fixture'
SUCCESS, UNSUPPORTED, DIRTY = 0, 3, 13


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    f.IMAGE_SIZE = IMAGE_BYTES
    source, _, _ = f.make_image()
    cases = []

    def add(name, major, minor, flags, code):
        image = bytearray(source)
        info = VOLUME_INFO.pack(0, major, minor, flags)
        record = f.file_record(f.VOLUME_RECORD, [f.standard(),
            f.resident(f.VOL_NAME, VOLUME_LABEL.encode('utf-16le'), VOLUME_NAME_INSTANCE),
            f.resident(f.VOL_INFO, info, VOLUME_INFO_INSTANCE)])
        f.put_record(image, f.VOLUME_RECORD, record)
        filename = name + '.img'
        (output / filename).write_bytes(image)
        cases.append(dict(path=filename, major=major, minor=minor, flags=flags, code=code,
            sha256=hashlib.sha256(image).hexdigest()))

    for minor in (0, f.NTFS_MINOR_VERSION):
        add(f'clean-version-{minor}', f.NTFS_MAJOR_VERSION, minor, 0, SUCCESS)
        add(f'dirty-version-{minor}', f.NTFS_MAJOR_VERSION, minor, VOLUME_DIRTY, DIRTY)
    for bit in range(VOLUME_FLAG_BITS):
        flag = 1 << bit
        if flag == VOLUME_DIRTY:
            continue
        add(f'unsupported-flag-{flag:04x}', f.NTFS_MAJOR_VERSION, f.NTFS_MINOR_VERSION,
            flag, UNSUPPORTED)
        add(f'dirty-with-flag-{flag:04x}', f.NTFS_MAJOR_VERSION, f.NTFS_MINOR_VERSION,
            flag | VOLUME_DIRTY, DIRTY)
    add('all-unsupported-flags', f.NTFS_MAJOR_VERSION, f.NTFS_MINOR_VERSION,
        VOLUME_FLAG_MAX ^ VOLUME_DIRTY, UNSUPPORTED)
    add('all-flags-including-dirty', f.NTFS_MAJOR_VERSION, f.NTFS_MINOR_VERSION,
        VOLUME_FLAG_MAX, DIRTY)
    # Version refusal precedes dirty/unsupported classification, as in the existing API.
    for major, minor, name in ((f.NTFS_MAJOR_VERSION + 1, f.NTFS_MINOR_VERSION, 'major'),
                              (f.NTFS_MAJOR_VERSION, f.NTFS_MINOR_VERSION + 1, 'minor')):
        for flags in (0, VOLUME_DIRTY, VOLUME_FLAG_MAX ^ VOLUME_DIRTY, VOLUME_FLAG_MAX):
            add(f'unsupported-{name}-flags-{flags:04x}', major, minor, flags, UNSUPPORTED)
    (output / 'cases.tsv').write_text(''.join(
        f"{case['path']} {case['major']} {case['minor']} {case['flags']} {case['code']}\n"
        for case in cases))
    (output / 'manifest.json').write_text(json.dumps(dict(schema_version=1,
        origin='Original volume-information flags and version admission profiles',
        image_bytes=IMAGE_BYTES, label=VOLUME_LABEL, cases=cases), indent=2) + '\n')
    return cases


if __name__ == '__main__':
    cases = author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(f'{len(cases)} volume admission profiles\n')
