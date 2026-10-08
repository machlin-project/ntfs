#!/usr/bin/env python3
"""Package accepted local directory inputs for the existing strict Windows collector.

No VM transport, attachment or repair occurs here. Whole virtual-disk comparison
must pass before a product is admitted. Every group uses a new guest directory;
the collector's original T: disk identity checks remain unchanged.
"""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import re
import shutil
import struct

import fixtures as wire
import filename_storage as storage
from secure_fixtures import FILE_HEADER_FIELDS
from gpt_identity import unique_gpt, read_at
from native_growth_faults import sha, apply
from native_directory_batch import Batch
from windows_torn_pages import logfile_torn_pages

ROOT = Path(__file__).resolve().parents[1]
COPY_BYTES = 4 * 1024 * 1024
GROUP_CASES = 8
VHD_MAX_BYTES = 128 * 1024 * 1024
PARTITION_FIRST = 16 * 1024 * 1024
PARTITION_BYTES = 8572108800
DISK_BYTES = 8 * 1024 * 1024 * 1024
LOGFILE_RECORD = 2


def logfile_layout(image):
    with image.open('rb') as source:
        boot = read_at(source, 0, wire.SECTOR)
        sector, = struct.unpack_from('<H', boot, wire.BOOT_FIELDS['sector_size'])
        mft_lcn, = struct.unpack_from('<Q', boot, wire.BOOT_FIELDS['mft'])
        assert sector == wire.SECTOR and boot[wire.BOOT_FIELDS['cluster_sectors']] * sector == wire.CLUSTER
        _, attrs = storage.record_parts(read_at(source, mft_lcn * wire.CLUSTER, wire.RECORD))
        data = next(value for value in attrs if storage.attr_header(value)['type'] == wire.DATA and not storage.attr_name(value))
        _, runs = storage.mapping(data)
        assert runs[0][1] == mft_lcn and runs[0][0] * wire.CLUSTER >= (LOGFILE_RECORD + 1) * wire.RECORD
        _, attrs = storage.record_parts(read_at(source, mft_lcn * wire.CLUSTER + LOGFILE_RECORD * wire.RECORD, wire.RECORD))
        data = next(value for value in attrs if storage.attr_header(value)['type'] == wire.DATA and not storage.attr_name(value))
        stream, runs = storage.mapping(data)
        assert len(runs) == 1 and runs[0][1] is not None
        assert stream['initialized'] == stream['size'] == stream['allocated'] == runs[0][0] * wire.CLUSTER
        return runs[0][1] * wire.CLUSTER, stream['size']


def metadata_tears(image, regions, root):
    result = []
    with image.open('rb') as source:
        for region in regions:
            if region['attribute_type'] == wire.INDEX_ALLOC:
                # The directory batch's structural transitions all edit this directory.
                spans = [(0, wire.CLUSTER, '\\' + root[3:] + '\\native-growth',
                          region['reference'] & ((1 << wire.REFERENCE_SEQUENCE_SHIFT) - 1))]
            elif region['attribute_type'] == wire.DATA and region['reference'] & ((1 << wire.REFERENCE_SEQUENCE_SHIFT) - 1) == 0:
                spans = [(offset, wire.RECORD, '\\$MftMirr' if region['mirror'] else '\\$Mft',
                          1 if region['mirror'] else 0) for offset in range(0, region['bytes'], wire.RECORD)]
            else:
                continue
            page = read_at(source, region['physical'], region['bytes'])
            for offset, size, name, reference in spans:
                value = page[offset:offset + size]
                if value[:4] not in (b'FILE', b'INDX'):
                    continue
                fields = dict(zip(FILE_HEADER_FIELDS, wire.FILE_HEADER_LEGACY.unpack_from(value)))
                # FILE and INDX share the named MST prefix in the fixture layout.
                usa_first, usa_count = fields['usa_offset'], fields['usa_count']
                assert usa_count == size // wire.SECTOR + 1
                assert usa_first + usa_count * wire.U16_BYTES <= wire.SECTOR - wire.U16_BYTES
                sequence, = struct.unpack_from('<H', value, usa_first)
                for block in range(usa_count - 1):
                    actual, = struct.unpack_from('<H', value, (block + 1) * wire.SECTOR - wire.U16_BYTES)
                    if actual != sequence:
                        assert (region['logical'] + offset) % wire.CLUSTER == 0
                        result.append(dict(FileName=name, FileReference=str(reference),
                            BufferOffset=str(region['logical'] + offset), TornStructureOffset='0',
                            BlockIndex=str(block), ExpectedSequenceNumber=str(sequence),
                            ActualSequenceNumber=str(actual)))
                        break
    return result


def overlay_partition(image, raw, wanted_hash, partition_first=PARTITION_FIRST,
                      partition_bytes=PARTITION_BYTES, disk_bytes=DISK_BYTES):
    assert image.stat().st_size == partition_bytes and raw.stat().st_size == disk_bytes
    digest = hashlib.sha256()
    with image.open('rb') as source, raw.open('r+b') as target:
        offset = 0
        while offset < partition_bytes:
            value = source.read(min(COPY_BYTES, partition_bytes - offset))
            assert value
            digest.update(value)
            target.seek(partition_first + offset)
            previous = target.read(len(value))
            assert len(previous) == len(value)
            if previous != value:
                target.seek(partition_first + offset)
                assert target.write(value) == len(value)
            offset += len(value)
        assert not source.read(1)
    assert digest.hexdigest() == wanted_hash
    observed = hashlib.sha256()
    with raw.open('rb') as source:
        source.seek(partition_first)
        remaining = partition_bytes
        while remaining:
            value = source.read(min(COPY_BYTES, remaining))
            assert value
            observed.update(value)
            remaining -= len(value)
    assert observed.hexdigest() == wanted_hash


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local', type=Path, required=True, help='Completed native_directory_batch output')
    parser.add_argument('--collector-profile', type=Path, help='Retained accepted batch.json for original T: expectations')
    parser.add_argument('--raw-container', type=Path)
    parser.add_argument('--base-vhd', type=Path)
    parser.add_argument('--cloud-manifest', type=Path, help='Validated windows_cloud_inputs.py output')
    parser.add_argument('--tag', required=True, help='Fresh group identity, ASCII letters/digits/hyphens')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, default=Path(shutil.which('qemu-img') or '/opt/homebrew/bin/qemu-img'))
    args = parser.parse_args()
    assert re.fullmatch('[A-Za-z0-9-]{1,32}', args.tag)
    local = json.loads((args.local / 'result.json').read_text())
    assert local['status'] == 'pass' and local['vmCommands'] == 0
    baseline = json.loads(Path(local['baselineManifest']).read_text())
    disk_bytes, partition_first, partition_bytes = DISK_BYTES, PARTITION_FIRST, PARTITION_BYTES
    if args.cloud_manifest:
        if args.collector_profile or args.raw_container or args.base_vhd:
            parser.error('Cloud manifest cannot be combined with historical container arguments')
        cloud = json.loads(args.cloud_manifest.read_text())
        assert cloud['status'] == 'pass' and cloud['nativeWindowsRecoveryPending'] is True
        assert re.fullmatch(r'R:\\MachlinCloudNTFS-[0-9a-f]{32}', cloud['root'])
        assert local['cloudManifest'] == str(args.cloud_manifest.resolve()) and baseline['root'] == cloud['root']
        disk_bytes, partition_first, partition_bytes = cloud['diskBytes'], cloud['partitionOffset'], cloud['partitionBytes']
        assert 128 * 1024 * 1024 <= disk_bytes <= 4096 * 1024 * 1024
        assert partition_first >= 1024 * 1024 and 0 < partition_bytes <= disk_bytes - partition_first
        assert partition_first % wire.SECTOR == partition_bytes % wire.SECTOR == 0
        args.raw_container, args.base_vhd = Path(cloud['rawContainer']), Path(cloud['baseVhd'])
        assert sha(args.raw_container) == cloud['rawContainerSha256']
        original = dict(cloudInput=True, diskBytes=disk_bytes, partitionOffset=partition_first,
                        partitionBytes=partition_bytes, partitionNumber=cloud['partitionNumber'],
                        volumeLabel='MachlinCloudNTFS', baseline=baseline,
                        bootstrapSha256=cloud['bootstrapSha256'],
                        baseVhdSha256=cloud['baseVhdSha256'], baseVhdBytes=cloud['baseVhdBytes'],
                        targetAcl=cloud['targetAcl'], fileId=cloud['fileId'])
    else:
        if not args.collector_profile or not args.raw_container or not args.base_vhd:
            parser.error('Supply --cloud-manifest or every historical container argument')
        original = json.loads(args.collector_profile.read_text())
    raw_source, base_vhd = args.raw_container.resolve(strict=True), args.base_vhd.resolve(strict=True)
    assert raw_source.stat().st_mode & 0o777 == base_vhd.stat().st_mode & 0o777 == 0o444
    assert raw_source.stat().st_size == disk_bytes and sha(base_vhd) == original['baseVhdSha256']
    assert base_vhd.stat().st_size == original['baseVhdBytes'] <= VHD_MAX_BYTES
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    batch = Batch(output, ROOT / '.build', args.qemu.resolve(strict=True))
    batch.report.update(products=[], groups=[], sourceReport=str((args.local / 'result.json').resolve()),
                        rawContainerSha256=sha(raw_source), nativeWindowsPending=True)
    inputs = [dict(row, case='directory-' + row['phase']) for row in local['snapshots']] + local['cuts']
    try:
        for entry in inputs:
            directory = output / entry['case']
            directory.mkdir()
            image = Path(entry['image'])
            assert image.stat().st_mode & 0o777 == 0o444 and sha(image) == entry['sha256']
            objects = json.loads(Path(entry['objects']).read_text())
            raw, vhd = directory / 'expected.raw', directory / ('input-' + entry['case'] + '.vhd')
            batch.clone(directory, 'clone-raw', raw_source, raw)
            overlay_partition(image, raw, entry['sha256'], partition_first, partition_bytes, disk_bytes)
            with raw.open('rb') as source:
                patches, disk_id, partition_id = unique_gpt(source, disk_bytes, partition_first, partition_bytes)
            apply(raw, patches)
            batch.command(directory, 'convert-vhd', [batch.qemu, 'convert', '-f', 'raw', '-O', 'vpc',
                          '-o', 'subformat=dynamic,force_size=on', raw, vhd])
            assert 0 < vhd.stat().st_size <= VHD_MAX_BYTES
            batch.command(directory, 'whole-virtual-disk', [batch.qemu, 'compare', '-f', 'raw', '-F', 'vpc', raw, vhd])
            journal_first, journal_bytes = logfile_layout(image)
            with image.open('rb') as source:
                torn = logfile_torn_pages(source, journal_first, range(journal_first, journal_first + journal_bytes, wire.CLUSTER))
            product = copy.deepcopy(baseline)
            for name in ('ordinaryObjects', 'mountedMutationObjects', 'sequenceObjects', 'expectedTornMetadataPages'):
                product.pop(name, None)
            regions = []
            if 'transition' in entry:
                transition = json.loads(Path(entry['transition']).read_text())
                regions = json.loads((Path(transition['trace']) / 'plan.json').read_text())['regions']
            product.update(case=entry['case'], diskGuid=disk_id, partitionGuid=partition_id,
                expectedVhdSha256=sha(vhd), expectedTornLogPages=torn,
                expectedTornMetadataPages=metadata_tears(image, regions, product['root']),
                sequenceObjects=objects, patches=[], preparedVhdName=vhd.name, preparedVhdBytes=vhd.stat().st_size)
            (directory / 'manifest.json').write_text(json.dumps(product, indent=2) + '\n')
            vhd.chmod(0o444)
            raw.unlink()
            batch.report['products'].append(dict(case=entry['case'], vhd=str(vhd),
                manifest=str(directory / 'manifest.json'), sha256=product['expectedVhdSha256'],
                bytes=vhd.stat().st_size, wholeVirtualDiskCompared=True))
            batch.save()
        for first in range(0, len(batch.report['products']), GROUP_CASES):
            number = first // GROUP_CASES
            directory = output / f'group-{number:02d}'
            directory.mkdir()
            group = copy.deepcopy(original)
            group.update(directory=rf'C:\Windows\Temp\MachlinNTFSImageRecovery-{args.tag}-{number:02d}',
                         products=[json.loads(Path(row['manifest']).read_text()) for row in batch.report['products'][first:first + GROUP_CASES]])
            (directory / 'batch.json').write_text(json.dumps(group, indent=2) + '\n')
            transfer = [dict(path=str(base_vhd), name='base.vhd', bytes=base_vhd.stat().st_size, sha256=sha(base_vhd)),
                        *[dict(path=row['vhd'], name=Path(row['vhd']).name, bytes=row['bytes'], sha256=row['sha256'])
                          for row in batch.report['products'][first:first + GROUP_CASES]]]
            (directory / 'transfer.json').write_text(json.dumps(transfer, indent=2) + '\n')
            batch.report['groups'].append(dict(manifest=str(directory / 'batch.json'),
                transfer=str(directory / 'transfer.json'), guestDirectory=group['directory'],
                reportName=f'MachlinDirectory-{args.tag}-{number:02d}'))
        assert sha(raw_source) == batch.report['rawContainerSha256']
        batch.report['status'] = 'pass'
    except BaseException:
        batch.report['status'] = 'fail'
        raise
    finally:
        batch.save()


if __name__ == '__main__':
    main()
