#!/usr/bin/env python3
"""Validate detached native scratch evidence and prepare relocatable harness inputs.

This does not mount a disk or infer a recovery verdict. Native provenance records
an acquisition, not cryptographic attestation. C admission must still succeed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

from environment import tool_environment
from benchmark_toolchain import command as bounded_command

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from windows_corpus import validate_manifest as corpus_manifest, units

MIB = 1024 * 1024
MAX_MANIFEST_BYTES = 8 * MIB
SECTOR_BYTES = 512
ROOT_PATTERN = re.compile(r'MachlinCloudNTFS-[0-9a-f]{32}')
HASH_PATTERN = re.compile(r'[0-9a-f]{64}')
BASIC_DATA_TYPE = uuid.UUID('ebd0a0a2-b9e5-4433-87c0-68b6b72699c7')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_json(pairs):
    value = {}
    for name, item in pairs:
        require(name not in value, 'Duplicate manifest field')
        value[name] = item
    return value


def plain_file(directory, name):
    directory = Path(directory)
    require(directory.resolve(strict=True) == directory.absolute(), 'Artifact directory has a symbolic-link ancestor')
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name,
            'Expected a contained POSIX artifact name')
    relative = Path(name)
    require(not relative.is_absolute() and '..' not in relative.parts,
            'Artifact escapes its acquisition directory')
    path = directory
    for component in relative.parts:
        path = path / component
        require(not path.is_symlink(), 'Artifact has a symbolic-link component')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            'Artifact must be a private regular file')
    return path


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def json_file(path):
    require(path.stat().st_size <= MAX_MANIFEST_BYTES, 'Manifest exceeds byte budget')
    return json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=unique_json)


def checked_hash(path, expected):
    require(isinstance(expected, str) and HASH_PATTERN.fullmatch(expected) is not None,
            'Invalid artifact SHA-256')
    require(digest(path) == expected, 'Retained artifact hash changed')


def geometry(data):
    require(data.get('schema_version') == 1 and data.get('provenance') == 'Windows native scratch VHD bootstrap'
            and data.get('acquisition_status') == 'complete' and data.get('stage') == 'complete'
            and data.get('errors') == [] and data.get('automatic_retry') is False
            and data.get('native_recovery_qualified') is False,
            'A complete unqualified native bootstrap is required')
    require(data.get('volume_lock_and_flush_succeeded') is True,
            'Native volume locking and flushing were not observed')
    require(data['platform']['system'] == 'Windows' and bool(data['platform']['version']),
            'Missing actual Windows platform provenance')
    require(isinstance(data['root_name'], str) and ROOT_PATTERN.fullmatch(data['root_name']) is not None,
            'Unexpected fresh namespace identity')
    disk, partition = data['disk'], data['partition']
    size = data['disk_bytes']
    require(type(size) is int and 128 * MIB <= size <= 4096 * MIB and size % MIB == 0,
            'Disk size outside scratch budget')
    require(type(disk['Number']) is int and disk['Number'] >= 0 and
            disk['Number'] not in data['protected_disk_numbers'] and disk['Size'] == size and
            disk['LogicalSectorSize'] == SECTOR_BYTES and disk['IsBoot'] is False and
            disk['IsSystem'] is False and bool(disk['UniqueId']), 'Unsafe native disk identity')
    require(uuid.UUID(disk['Guid'].strip('{}')).int != 0 and
            uuid.UUID(partition['Guid'].strip('{}')).int != 0 and
            uuid.UUID(partition['GptType'].strip('{}')) == BASIC_DATA_TYPE,
            'Invalid GPT identity')
    offset, length = partition['Offset'], partition['Size']
    require(type(offset) is int and type(length) is int and offset >= MIB and length > 0 and
            offset % SECTOR_BYTES == length % SECTOR_BYTES == 0 and offset < size and
            length <= size - offset and type(partition['PartitionNumber']) is int and
            partition['PartitionNumber'] > 0 and partition['IsBoot'] is False and partition['IsSystem'] is False,
            'Invalid native partition geometry')
    return size, offset, length


def validate(path):
    path = Path(path).absolute()
    plain_file(path.parent, path.name)
    data = json_file(path)
    size, offset, length = geometry(data)
    require(data['vhd']['file'] == 'base.vhd' and data['vhd']['detached'] is True,
            'A detached scratch VHD is required')
    vhd = plain_file(path.parent, data['vhd']['file'])
    require(type(data['vhd']['bytes']) is int and 0 < vhd.stat().st_size == data['vhd']['bytes'] <= size + 16 * MIB,
            'Invalid retained VHD size')
    checked_hash(vhd, data['vhd']['sha256'])
    require(data['corpus']['file'] == 'corpus/manifest.json', 'Unexpected corpus manifest location')
    corpus_path = plain_file(path.parent, data['corpus']['file'])
    checked_hash(corpus_path, data['corpus']['sha256'])
    corpus, image = corpus_manifest(corpus_path)
    require(corpus['provenance'] == 'Windows native NTFS API' and corpus['acquisition_status'] == 'complete'
            and corpus['observation_errors'] == [], 'Incomplete or synthetic native corpus')
    require(corpus['scope_utf16'] == [[ord(char) for char in data['root_name']]], 'Corpus namespace binding changed')
    require(corpus['volume']['sector_size'] == SECTOR_BYTES and corpus['volume']['cluster_size'] == 4096
            and corpus['volume']['record_size'] == 1024 and
            corpus['volume']['native_flags'] & 0x00080000, 'Unsupported or writable native corpus geometry')
    image = plain_file(corpus_path.parent, corpus['image']['file'])
    require(length - SECTOR_BYTES <= image.stat().st_size <= length, 'Corpus extent differs from the native partition')
    checked_hash(image, corpus['image']['sha256'])
    for entry in corpus['entries']:
        require(entry['stat']['reparse'] is False, 'Bootstrap namespace contains a reparse point')
        for stream in entry.get('streams', []):
            payload = plain_file(corpus_path.parent, stream['payload'])
            checked_hash(payload, stream['sha256'])
    return data, corpus, image, vhd


def baseline(data, corpus):
    root = data['root_name']
    by_name = {}
    for entry in corpus['entries']:
        components = [''.join(map(chr, units(component))) for component in entry['path_utf16']]
        require(components and components[0] == root, 'Observation is outside the authored root')
        name = '\\'.join(components[1:])
        require(name not in by_name, 'Duplicate baseline observation')
        by_name[name] = entry
    files = ('initialized.bin', 'rename-after.txt', 'resident.txt', 'child\\nested.txt')
    require(set(by_name) == {'', 'child', *files}, 'Native namespace differs from the bootstrap workload')
    require(by_name['']['stat']['directory'] and by_name['child']['stat']['directory'],
            'Authored root/child directories changed type')
    expected_bytes = {'initialized.bin': bytes((index * 17 + 3) % 256 for index in range(256)) * 4096,
                      'rename-after.txt': b'original rename witness',
                      'resident.txt': b'Machlin original resident NTFS write witness.\r\n',
                      'child\\nested.txt': b'original directory witness'}
    result = dict(root='R:\\' + root, files=[])
    for name in files:
        entry = by_name[name]
        require(not entry['stat']['directory'], 'Expected an ordinary baseline file')
        streams = {tuple(row['name_utf16']): row for row in entry['streams']}
        require(() in streams, 'Missing native unnamed stream')
        stream = streams[()]
        require(int(stream['size']) == len(expected_bytes[name]) and
                stream['sha256'] == hashlib.sha256(expected_bytes[name]).hexdigest(),
                'Native baseline content differs from the authored byte oracle')
        result['files'].append(dict(relativePath=name, bytes=int(stream['size']), sha256=stream['sha256'],
                                   lastWriteFileTime=entry['stat']['modified_ticks']))
    stream = next(row for row in by_name['resident.txt']['streams']
                  if row['name_utf16'] == list(map(ord, 'original-stream')))
    require(int(stream['size']) == 29 and stream['sha256'] == hashlib.sha256(b'original named stream witness').hexdigest(),
            'Native named stream differs from authored bytes')
    result['namedStream'] = dict(relativePath='resident.txt', name='original-stream',
                                bytes=int(stream['size']), sha256=stream['sha256'])
    result.update(residentAcl=data['native_files']['resident_acl'], residentFileId=data['native_files']['resident_file_id'])
    return result


def prepare(path, output, qemu):
    data, corpus, image, vhd = validate(path)
    expected = baseline(data, corpus)
    size, offset, length = geometry(data)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    raw, source = output / 'container.raw', output / 'source.ntfs'
    command = [str(qemu), 'convert', '-f', 'vpc', '-O', 'raw', str(vhd), str(raw)]
    report = dict(status='running', nativeWindowsRecoveryPending=True, bootstrap=str(Path(path).resolve()),
                  bootstrapSha256=digest(Path(path)), commands=[], diskBytes=size,
                  partitionOffset=offset, partitionBytes=length, partitionNumber=data['partition']['PartitionNumber'])
    try:
        report['commands'].append(dict(argv=command))
        bounded_command(command, output, 'convert', tool_environment(), timeout=120, text=False)
        report['commands'][-1]['exitCode'] = 0
        require(raw.stat().st_size == size, 'VHD raw conversion changed geometry')
        observed = hashlib.sha256()
        with raw.open('rb') as source_disk, source.open('xb') as destination:
            source_disk.seek(offset)
            remaining = length
            corpus_remaining = image.stat().st_size
            while remaining:
                value = source_disk.read(min(MIB, remaining))
                require(bool(value), 'Truncated raw partition')
                observed.update(value[:corpus_remaining])
                corpus_remaining = max(0, corpus_remaining - len(value))
                destination.write(value)
                remaining -= len(value)
            destination.flush()
            os.fsync(destination.fileno())
        require(observed.hexdigest() == corpus['image']['sha256'], 'Raw VHD partition disagrees with native corpus bytes')
        # Both GPT copies and their entry-array checksums must match the native geometry.
        from gpt_identity import unique_gpt, checked_header, PRIMARY_HEADER_LBA, ENTRY
        from write_journal_fixtures import fields
        with raw.open('rb') as native:
            unique_gpt(native, size, offset, length)
            _, header, entries = checked_header(native, PRIMARY_HEADER_LBA, size)
        require(uuid.UUID(bytes_le=header['disk_guid']) == uuid.UUID(data['disk']['Guid'].strip('{}')),
                'Raw GPT disk identity disagrees with the observed native disk')
        matched = [fields(ENTRY, entries, first) for first in range(0, len(entries), ENTRY.size)
                   if fields(ENTRY, entries, first)['type_guid'] == BASIC_DATA_TYPE.bytes_le]
        require(len(matched) == 1 and uuid.UUID(bytes_le=matched[0]['unique_guid']) ==
                uuid.UUID(data['partition']['Guid'].strip('{}')),
                'Raw GPT partition identity disagrees with the observed native partition')
        checked_hash(vhd, data['vhd']['sha256'])
        raw.chmod(0o444)
        source.chmod(0o444)
        vhd.chmod(0o444)
        descriptor = dict(source=str(source), sourceSha256=digest(source), provenance=data['provenance'])
        (output / 'source-descriptor.json').write_text(json.dumps(descriptor, indent=2) + '\n')
        (output / 'baseline-manifest.json').write_text(json.dumps(expected, indent=2) + '\n')
        report.update(status='pass', sourceDescriptor=str(output / 'source-descriptor.json'),
                      baselineManifest=str(output / 'baseline-manifest.json'),
                      rawContainer=str(raw), rawContainerSha256=digest(raw),
                      baseVhd=str(vhd), baseVhdSha256=data['vhd']['sha256'],
                      baseVhdBytes=data['vhd']['bytes'], root=expected['root'],
                      targetAcl=data['native_files']['target_acl'], fileId=data['native_files']['file_id'])
    except BaseException:
        report['status'] = 'fail'
        raise
    finally:
        (output / 'cloud-manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, default=Path('qemu-img'))
    args = parser.parse_args()
    result = prepare(args.bootstrap, args.output, args.qemu)
    print(json.dumps({key: result[key] for key in ('status', 'nativeWindowsRecoveryPending', 'root')}))


if __name__ == '__main__':
    main()
