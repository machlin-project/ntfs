#!/usr/bin/env python3
"""Compare full diagnostic counts with independent NTFS-3G bitmap exports."""
from pathlib import Path
import argparse
import json
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from secure_oracle import capture, file_hash, GEOMETRIES
from validation_cli import invoke

MFT_RECORD, BITMAP_RECORD = 0, 6
DATA_TYPE, BITMAP_TYPE = '0x80', '0xb0'
BYTE_BITS = 8


def allocated_bits(data, count):
    if len(data) * BYTE_BITS < count:
        raise ValueError('Independent allocation bitmap is shorter than the validated geometry')
    whole, tail = divmod(count, BYTE_BITS)
    return sum(byte.bit_count() for byte in data[:whole]) + (
        (data[whole] & ((1 << tail) - 1)).bit_count() if tail else 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--images', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New evidence directory')
    parser.add_argument('--tools', type=Path, default=ROOT / 'vendor/ntfs-tools/bin')
    parser.add_argument('--validator', type=Path, default=ROOT / '.build/ntfs-validate')
    parser.add_argument('--reader', type=Path, default=ROOT / '.build/ntfs-inspect')
    args = parser.parse_args()
    images = [(sector, cluster, args.images / f'ntfs-s{sector}-c{cluster}.img')
              for sector, cluster in GEOMETRIES]
    for path in (args.validator, args.reader, args.tools / 'ntfscat', *(item[2] for item in images)):
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            parser.error(f'A regular file is required: {path}')
    args.output.mkdir(parents=True, exist_ok=False)
    report = {'status': 'running', 'scope': 'supported metadata consistency and independent bitmaps',
              'windows_acceptance': 'not run', 'journal_recovery': 'not checked', 'profiles': []}
    destination = args.output / 'report.json'
    try:
        with (args.output / 'commands.log').open('x') as log:
            for sector, cluster, image in images:
                profile = {'sector': sector, 'cluster': cluster, 'status': 'running',
                           'image_sha256_before': file_hash(image)}
                report['profiles'].append(profile)
                try:
                    log.write(json.dumps([str(args.validator), str(image)]) + '\n')
                    diagnostic = invoke(args.validator, [image], None)
                    profile['diagnostic'] = diagnostic
                    if not diagnostic['complete']:
                        raise ValueError('Incomplete diagnostic: ' + diagnostic['result']
                                         + ', stage ' + str(diagnostic['stage'])
                                         + ', reference ' + diagnostic['reference'])
                    info = json.loads(capture([args.reader, image, 'info-json'], log))
                    mft = capture([args.tools / 'ntfscat', '-i', MFT_RECORD, '-a', BITMAP_TYPE, image], log)
                    allocation = capture([args.tools / 'ntfscat', '-i', BITMAP_RECORD, '-a', DATA_TYPE, image], log)
                    active = allocated_bits(mft, int(diagnostic['record_slots']))
                    clusters = allocated_bits(allocation, int(info['cluster_count']))
                    profile.update({'independent_active_records': active,
                                    'independent_allocated_clusters': clusters})
                    if active != int(diagnostic['base_records']) + int(diagnostic['extension_records']):
                        raise ValueError('Core record counts differ from independently exported bitmap')
                    if clusters != int(diagnostic['allocated_clusters']) or clusters != int(diagnostic['claimed_clusters']):
                        raise ValueError('Core physical ownership differs from independently exported bitmap')
                    profile['status'] = 'pass'
                except BaseException as error:
                    profile['status'] = 'fail'
                    profile['error'] = str(error)
                    raise
                finally:
                    profile['image_sha256_after'] = file_hash(image)
                    profile['image_unchanged'] = profile['image_sha256_before'] == profile['image_sha256_after']
                    if not profile['image_unchanged']:
                        profile['status'] = 'fail'
                        raise ValueError('Independent image changed during read-only diagnostics')
                    destination.write_text(json.dumps(report, indent=2) + '\n')
        report['status'] = 'pass'
        print(f'PASS: {len(images)} independent image geometries, active records, cluster ownership and unchanged hashes')
    except BaseException:
        report['status'] = 'fail'
        raise
    finally:
        destination.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
