#!/usr/bin/env python3
"""Compare resolved descriptor bytes with external NTFS-3G exports, without mounts."""
from pathlib import Path
import argparse
from collections import namedtuple
import hashlib
import json
import os
import re
import selectors
import stat
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import tool_environment

GEOMETRIES = ((512, 1024), (512, 4096), (4096, 4096), (512, 65536))
SECURE_RECORD = 9
REFERENCE_SEQUENCE_SHIFT = 48
REFERENCE_RECORD_MASK = (1 << REFERENCE_SEQUENCE_SHIFT) - 1
TOOL_SECONDS = 60
OUTPUT_BYTES = 1024 * 1024
IO_BYTES = 64 * 1024
SDS_DUPLICATE_BYTES = 256 * 1024
INDEX_ROOT = struct.Struct('<IIIB3x')
INDEX_HEADER = struct.Struct('<IIIB3x')
VIEW_ENTRY = struct.Struct('<HHIHHHH')
LOCATOR = struct.Struct('<IIQI')
ATTRIBUTE_DATA, ATTRIBUTE_INDEX_ROOT = '0x80', '0x90'
ATTRIBUTE_STANDARD, ATTRIBUTE_SECURITY_DESCRIPTOR = '0x10', '0x50'
STANDARD_LEGACY_BYTES = struct.calcsize('<QQQQIIII')
INDEX_END, INDEX_CHILD = 2, 1
COLLATION_ULONG = 16
WIRE_ALIGNMENT = 8
SecurityLocator = namedtuple('SecurityLocator', ('hash', 'security_id', 'offset', 'length'))


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(IO_BYTES), b''):
            digest.update(chunk)
    return digest.hexdigest()


def capture(argv, log):
    log.write(json.dumps(list(map(str, argv)), ensure_ascii=True) + '\n')
    log.flush()
    deadline = time.monotonic() + TOOL_SECONDS
    output = bytearray()
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(list(map(str, argv)), cwd=ROOT, env=tool_environment(),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errors)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('External command exceeded its deadline')
                    ready = selector.select(remaining)
                    if not ready:
                        raise TimeoutError('External command exceeded its deadline')
                    for key, _ in ready:
                        chunk = os.read(key.fileobj.fileno(), IO_BYTES)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        if len(output) + len(chunk) > OUTPUT_BYTES:
                            raise ValueError('External output exceeded its byte budget')
                        output.extend(chunk)
            process.wait(timeout=max(0, deadline - time.monotonic()))
            if process.returncode != 0:
                errors.seek(0)
                detail = errors.read(IO_BYTES).decode('utf-8', errors='replace').strip()
                raise RuntimeError(f'External command failed: {detail}')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
    return bytes(output)


def exported_locators(root):
    kind, collation, _, _ = INDEX_ROOT.unpack_from(root)
    start, used, allocated, flags = INDEX_HEADER.unpack_from(root, INDEX_ROOT.size)
    if kind != 0 or collation != COLLATION_ULONG or flags != 0:
        raise ValueError('This independent oracle requires a resident leaf SII root')
    if not INDEX_HEADER.size <= start <= used <= allocated <= len(root) - INDEX_ROOT.size:
        raise ValueError('Malformed exported SII header')
    position, end = INDEX_ROOT.size + start, INDEX_ROOT.size + used
    result = {}
    while position < end:
        data_offset, data_length, _, length, key_length, flags, _ = VIEW_ENTRY.unpack_from(root, position)
        if length < VIEW_ENTRY.size or length % WIRE_ALIGNMENT or length > end - position or flags & INDEX_CHILD:
            raise ValueError('Malformed exported SII entry')
        if flags & INDEX_END:
            if position + length != end or key_length != 0 or data_length != 0:
                raise ValueError('Malformed exported SII terminal entry')
            return result
        if key_length != struct.calcsize('<I') or data_length != LOCATOR.size:
            raise ValueError('Unexpected exported SII key/data framing')
        if data_offset < VIEW_ENTRY.size + key_length or data_offset + data_length > length:
            raise ValueError('Exported SII data overlaps its key or exceeds its entry')
        (security_id,) = struct.unpack_from('<I', root, position + VIEW_ENTRY.size)
        locator = SecurityLocator(*LOCATOR.unpack_from(root, position + data_offset))
        if locator.security_id != security_id or security_id in result:
            raise ValueError('Exported SII IDs disagree or repeat')
        result[security_id] = locator
        position += length
    raise ValueError('Exported SII is missing its terminal entry')


def indexed_bytes(sds, locator):
    if locator.length < LOCATOR.size or locator.offset + SDS_DUPLICATE_BYTES + locator.length > len(sds):
        raise ValueError('Oracle descriptor locator exceeds SDS')
    first = sds[locator.offset:locator.offset + locator.length]
    duplicate = sds[locator.offset + SDS_DUPLICATE_BYTES:locator.offset + SDS_DUPLICATE_BYTES + locator.length]
    if first != duplicate or LOCATOR.unpack_from(first) != locator:
        raise ValueError('Oracle SDS copies or headers disagree')
    return first[LOCATOR.size:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images', type=Path, required=True, help='Existing interoperability image directory')
    parser.add_argument('--tools', type=Path, default=ROOT / 'vendor/ntfs-tools/bin')
    parser.add_argument('--reader', type=Path, default=ROOT / '.build/ntfs-inspect')
    parser.add_argument('--output', type=Path, required=True, help='New evidence directory')
    args = parser.parse_args()
    images = [(sector, cluster, args.images / f'ntfs-s{sector}-c{cluster}.img') for sector, cluster in GEOMETRIES]
    for path in (args.reader, args.tools / 'ntfsinfo', args.tools / 'ntfscat', *(entry[2] for entry in images)):
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            parser.error(f'A regular file is required: {path}')
    args.output.mkdir(parents=True, exist_ok=False)
    report = {'status': 'running', 'scope': 'original descriptor bytes and indexed IDs',
              'windows_acceptance': 'not run', 'authorization': 'not implemented', 'profiles': []}
    report_path = args.output / 'report.json'
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    try:
        with (args.output / 'commands.log').open('x') as log:
            for sector, cluster, image in images:
                profile = {'sector': sector, 'cluster': cluster, 'status': 'running',
                           'image_sha256_before': file_hash(image), 'descriptors': []}
                report['profiles'].append(profile)
                try:
                    sii = capture([args.tools / 'ntfscat', '-i', SECURE_RECORD, '-a', ATTRIBUTE_INDEX_ROOT, '-n', '$SII', image], log)
                    sds = capture([args.tools / 'ntfscat', '-i', SECURE_RECORD, '-a', ATTRIBUTE_DATA, '-n', '$SDS', image], log)
                    (args.output / f'sii-s{sector}-c{cluster}.bin').write_bytes(sii)
                    (args.output / f'sds-s{sector}-c{cluster}.bin').write_bytes(sds)
                    locators = exported_locators(sii)
                    info = json.loads(capture([args.reader, image, 'info-json'], log))
                    references = {'/': info['root_reference']}
                    for name in ('small.txt', 'large.bin', 'café-Ω.txt'):
                        entry = json.loads(capture([args.reader, image, 'lookup-ref', info['root_reference'], name.encode('utf-16-be').hex()], log))
                        references[name] = entry['reference']
                    for name, reference in references.items():
                        number = int(reference, 16) & REFERENCE_RECORD_MASK
                        native_info = capture([args.tools / 'ntfsinfo', '-i', number, image], log)
                        (args.output / f'ntfsinfo-s{sector}-c{cluster}-r{number}.log').write_bytes(native_info)
                        ids = re.findall(rb'^\s*Security ID:\s*(\d+)\s*\(', native_info, re.MULTILINE)
                        if len(ids) == 1:
                            security_id = int(ids[0])
                        elif not ids:
                            standard = capture([args.tools / 'ntfscat', '-i', number, '-a', ATTRIBUTE_STANDARD, image], log)
                            if len(standard) != STANDARD_LEGACY_BYTES:
                                raise ValueError('Oracle SI must have one security ID or a verified legacy header')
                            security_id = 0
                        else:
                            raise ValueError('Oracle reported multiple standard-information security IDs')
                        metadata = json.loads(capture([args.reader, image, 'stat-ref', reference], log))
                        if metadata['security_id'] != security_id:
                            raise ValueError('Core and external security IDs differ')
                        if security_id != 0:
                            expected = indexed_bytes(sds, locators[security_id])
                        else:
                            expected = capture([args.tools / 'ntfscat', '-i', number, '-a', ATTRIBUTE_SECURITY_DESCRIPTOR, image], log)
                        actual = capture([args.reader, image, 'security-ref', reference], log)
                        if actual != expected:
                            raise ValueError(f'Resolved descriptor differs from external bytes: {name}')
                        (args.output / f'descriptor-s{sector}-c{cluster}-r{number}.bin').write_bytes(actual)
                        profile['descriptors'].append({'subject': name, 'reference': reference,
                            'security_id': security_id, 'source': 'indexed' if security_id else 'inline',
                            'bytes': len(actual), 'sha256': hashlib.sha256(actual).hexdigest(), 'status': 'pass'})
                    for security_id, locator in sorted(locators.items()):
                        expected = indexed_bytes(sds, locator)
                        actual = capture([args.reader, image, 'security-id', f'{security_id:x}'], log)
                        if actual != expected:
                            raise ValueError('Direct indexed descriptor differs from external bytes')
                        (args.output / f'descriptor-s{sector}-c{cluster}-id{security_id}.bin').write_bytes(actual)
                        profile['descriptors'].append({'subject': 'indexed descriptor', 'source': 'indexed',
                            'security_id': security_id, 'sds_hash': f'{locator.hash:08x}', 'sds_offset': locator.offset,
                            'bytes': len(actual), 'sha256': hashlib.sha256(actual).hexdigest(), 'status': 'pass'})
                    profile['status'] = 'pass'
                finally:
                    profile['image_sha256_after'] = file_hash(image)
                    if profile['image_sha256_before'] != profile['image_sha256_after']:
                        profile['status'] = 'fail'
                        raise ValueError('An input image changed during read-only comparison')
                    if profile['status'] == 'running':
                        profile['status'] = 'fail'
                    report_path.write_text(json.dumps(report, indent=2) + '\n')
        report['status'] = 'pass'
    except BaseException as error:
        report['status'] = 'fail'
        report['error'] = str(error)
        raise
    finally:
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    count = sum(len(profile['descriptors']) for profile in report['profiles'])
    print(f'PASS: {len(images)} geometries, {count} external descriptor-byte/ID oracles, unchanged images; Windows and native authorization unqualified')


if __name__ == '__main__':
    main()
