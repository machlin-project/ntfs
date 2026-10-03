#!/usr/bin/env python3
"""Compare diagnostic inventories, mirrors and boot copies with NTFS-3G exports."""
from pathlib import Path
import argparse
import hashlib
import json
import stat
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from secure_oracle import capture, file_hash, GEOMETRIES
from validation_cli import invoke

MFT_RECORD, MIRROR_RECORD, BITMAP_RECORD, BOOT_RECORD = 0, 1, 6, 7
REQUIRED_MIRROR_RECORDS = 4
DATA_TYPE, BITMAP_TYPE = '0x80', '0xb0'
BYTE_BITS = 8
RECORD_HEADER = struct.Struct('<4sHHQHHHHIIQH')
RECORD_FIELDS = ('magic', 'usa_offset', 'usa_count', 'lsn', 'sequence', 'links',
                 'attrs_offset', 'flags', 'used', 'allocated', 'base_reference',
                 'next_instance')
BOOT_PREFIX = struct.Struct('<3s8sHBHBHHBHHHII4sQ')
BOOT_FIELDS = ('jump', 'oem', 'sector_size', 'sectors_per_cluster', 'reserved_sectors',
               'fat_count', 'root_entries', 'small_sectors', 'media', 'sectors_per_fat',
               'sectors_per_track', 'heads', 'hidden_sectors', 'large_sectors',
               'extended_reserved', 'sectors')


def boot_copies(image, exported, sector, cluster, info):
    """Observe the declared reserved copy independently of the core diagnostic."""
    with image.open('rb') as source:
        prefix = source.read(BOOT_PREFIX.size)
        if len(prefix) != BOOT_PREFIX.size:
            raise ValueError('Independent source lacks the NTFS boot prefix')
        header = dict(zip(BOOT_FIELDS, BOOT_PREFIX.unpack(prefix)))
        if (header['sector_size'] != sector
                or header['sectors_per_cluster'] * sector != cluster):
            raise ValueError('Independent boot geometry differs from the authored profile')
        backup_offset = header['sectors'] * sector
        if backup_offset != int(info['size_bytes']):
            raise ValueError('Core data span differs from the independently decoded boot field')
        if backup_offset > image.stat().st_size - sector:
            raise ValueError('Independent resource lacks the declared reserved boot sector')
        source.seek(0)
        primary = source.read(sector)
        source.seek(backup_offset)
        backup = source.read(sector)
    if (len(primary) != sector or len(backup) != sector or len(exported) < sector
            or primary != exported[:sector] or primary != backup):
        raise ValueError('Independent $Boot export, primary and reserved sectors differ')
    return {'independent_boot_stream_bytes': len(exported),
            'independent_boot_sector_bytes': sector,
            'independent_boot_backup_offset': backup_offset,
            'independent_boot_sector_sha256': hashlib.sha256(primary).hexdigest()}


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
    report = {'status': 'running', 'scope': 'supported metadata, independent bitmaps, mandatory mirror prefix and declared boot copy',
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
                    mft_data = capture([args.tools / 'ntfscat', '-i', MFT_RECORD, '-a', DATA_TYPE, image], log)
                    mirror_data = capture([args.tools / 'ntfscat', '-i', MIRROR_RECORD, '-a', DATA_TYPE, image], log)
                    boot_data = capture([args.tools / 'ntfscat', '-i', BOOT_RECORD, '-a', DATA_TYPE, image], log)
                    profile.update(boot_copies(image, boot_data, sector, cluster, info))
                    if min(len(mft_data), len(mirror_data)) < RECORD_HEADER.size:
                        raise ValueError('Independent MFT/mirror exports lack their FILE headers')
                    primary_header = dict(zip(RECORD_FIELDS, RECORD_HEADER.unpack_from(mft_data)))
                    mirror_header = dict(zip(RECORD_FIELDS, RECORD_HEADER.unpack_from(mirror_data)))
                    record_bytes = primary_header['allocated']
                    if (primary_header['magic'] != b'FILE' or mirror_header['magic'] != b'FILE'
                            or record_bytes < RECORD_HEADER.size
                            or record_bytes != mirror_header['allocated']
                            or record_bytes != int(info['record_size'])):
                        raise ValueError('Core record geometry differs from independently exported headers')
                    prefix_bytes = REQUIRED_MIRROR_RECORDS * record_bytes
                    if len(mft_data) % record_bytes or len(mirror_data) % record_bytes:
                        raise ValueError('Independent MFT/mirror exports contain a partial record')
                    if len(mft_data) < prefix_bytes or len(mirror_data) < prefix_bytes:
                        raise ValueError('Independent exports are shorter than the required mirror prefix')
                    # These immutable mkntfs images have exact replica bytes.
                    # The core deliberately supports distinct protection/slack;
                    # this oracle does not generalize exact raw equality to Windows.
                    if mft_data[:prefix_bytes] != mirror_data[:prefix_bytes]:
                        raise ValueError('Independent mkntfs mirror prefix differs from its MFT export')
                    mirror_slots = len(mirror_data) // record_bytes
                    if (len(mft_data) // record_bytes != int(diagnostic['record_slots'])
                            or mirror_slots != int(diagnostic['mirror_record_slots'])
                            or int(diagnostic['mirror_records_compared']) != REQUIRED_MIRROR_RECORDS
                            or int(diagnostic['mirror_unchecked_records']) != mirror_slots - REQUIRED_MIRROR_RECORDS):
                        raise ValueError('Core mirror coverage differs from independently exported geometry')
                    profile.update({'independent_mirror_record_slots': mirror_slots,
                                    'independent_mirror_prefix_bytes': prefix_bytes,
                                    'independent_mirror_prefix_sha256': hashlib.sha256(
                                        mirror_data[:prefix_bytes]).hexdigest()})
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
        print(f'PASS: {len(images)} independent geometries, bitmap inventories, exact required mirror prefixes, declared boot copies and unchanged hashes')
    except BaseException:
        report['status'] = 'fail'
        raise
    finally:
        destination.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
