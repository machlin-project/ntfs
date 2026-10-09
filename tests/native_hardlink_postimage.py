#!/usr/bin/env python3
"""Read-only byte-preservation review of first detached Windows hard-link outputs.

The expected FILE_NAME caches come from original pre-Windows C predecessors.
This gate never adjusts them from Windows output and never mounts or repairs.
Original detached VHDs and reports remain unchanged, including on failure.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import sys
import uuid

import fixtures as wire
import filename_storage as storage
from gpt_identity import BASIC_DATA_TYPE, ENTRY, PRIMARY_HEADER_LBA, checked_header
from native_hardlink_observer import Image, attribute, restore, verify_transform
from write_journal_fixtures import fields
from write_metadata_fixtures import FILE

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from benchmark_toolchain import command
from environment import tool_environment
from review_windows_hardlink import digest, read, require, review as review_verdicts

SECURE_RECORD = 9
MAX_SECURITY_STORAGE = 16 * 1024 * 1024
COPY_BYTES = 1024 * 1024
PROFILES = ('cross-parent', 'same-parent', 'index-split')


def canonical_file(logical, header):
    result = bytearray(logical)
    FILE.put(result, 'lsn', 0)
    first = header['usa_offset']
    count = header['usa_count'] * wire.U16_BYTES
    result[first:first + count] = bytes(count)
    return bytes(result)


def by_number(image, number):
    raw = image.mapped(image.mft_runs, number * wire.RECORD, wire.RECORD)
    restore(raw, b'FILE')
    header, _ = storage.record_parts(raw)
    return image.record(wire.file_reference(number, header['sequence']))


def stored_attribute(image, value):
    header = storage.attr_header(value)
    if not header['nonresident']:
        return storage.resident_value(value)
    info, runs = storage.mapping(value)
    require(info['lowest'] == 0 and info['initialized'] == info['size'] <= MAX_SECURITY_STORAGE,
            'Security storage exceeds the complete base-record observer profile')
    remaining, result = info['size'], bytearray()
    for count, lcn in runs:
        take = min(count * wire.CLUSTER, remaining)
        if take:
            result += bytes(take) if lcn is None else image.at(lcn * wire.CLUSTER, take)
            remaining -= take
    require(remaining == 0, 'Security storage mapping is incomplete')
    return bytes(result)


def security_unchanged(before, after):
    old_record, old_header, old_attrs = by_number(before, SECURE_RECORD)
    new_record, new_header, new_attrs = by_number(after, SECURE_RECORD)
    require(canonical_file(old_record, old_header) == canonical_file(new_record, new_header),
            'The original complete $Secure FILE changed')
    require(old_attrs == new_attrs, 'The original security store attributes changed')
    contents = []
    for value in old_attrs:
        header = storage.attr_header(value)
        if header['nonresident']:
            original = stored_attribute(before, value)
            observed = stored_attribute(after, value)
            require(original == observed, 'The original security-store stream bytes changed')
            contents.append(dict(type=header['type'], name=storage.attr_name(value),
                bytes=len(original), sha256=hashlib.sha256(original).hexdigest()))
    return dict(completeFile=True, exactNonresidentAttributes=contents)


def old_endpoint(before, after, reference, source_parent, destination_parent):
    old_record, old_header, old_attrs = before.record(reference)
    new_record, new_header, new_attrs = after.record(reference)
    require(canonical_file(old_record, old_header) == canonical_file(new_record, new_header),
            'Loser target FILE differs from the complete old record')
    require(old_attrs == new_attrs and before.streams(reference) == after.streams(reference),
            'Loser original names or data/ADS changed')
    for parent in {source_parent, destination_parent}:
        require(before.keys(parent) == after.keys(parent), 'Loser original I30 keys changed')
        _, _, old = before.record(parent)
        _, _, new = after.record(parent)
        excluded = (wire.INDEX_ROOT, wire.INDEX_ALLOC, wire.BITMAP)
        require([value for value in old if storage.attr_header(value)['type'] not in excluded] ==
                [value for value in new if storage.attr_header(value)['type'] not in excluded],
                'Loser parent unselected attributes changed')
    return dict(completeTargetFile=True, originalNames=True, originalKeys=True,
                exactDataAndAds=True, parentUnselectedAttributes=True)


def all_alias_parents(before, after, reference, destination_parent, destination_name, committed):
    _, _, attrs = before.record(reference)
    parents = {wire.FILENAME_HEADER.unpack_from(storage.resident_value(value))[0]
               for value in attrs if storage.attr_header(value)['type'] == wire.FILENAME}
    require(parents, 'The original FILE has no stored names')
    parents.add(destination_parent)
    name_units = destination_name.encode('utf-16le')
    for parent in parents:
        original, observed = before.keys(parent), after.keys(parent)
        if committed and parent == destination_parent:
            added = [(child, key) for child, key in observed if child == reference and
                     key[wire.FILENAME_HEADER.size:] == name_units and
                     wire.FILENAME_HEADER.unpack_from(key)[-1] == wire.NAMESPACE_POSIX]
            require(len(added) == 1 and added[0] not in original,
                    'The committed new edge is missing or was already present')
            observed.remove(added[0])
        require(original == observed, 'An original alias parent I30 key changed')
        _, _, old = before.record(parent)
        _, _, new = after.record(parent)
        excluded = (wire.INDEX_ROOT, wire.INDEX_ALLOC, wire.BITMAP)
        require([value for value in old if storage.attr_header(value)['type'] not in excluded] ==
                [value for value in new if storage.attr_header(value)['type'] not in excluded],
                'An original alias parent unselected attribute changed')
    return dict(parentReferences=[str(parent) for parent in sorted(parents)], exactOriginalKeys=True)


def verify_namespace(image, root, products):
    observed = []
    for parent in (row for row in products if row['directory'] and row['present']):
        reference = image.resolve(root + '/' + parent['relativePath'])
        require(reference == int(parent['reference']), 'Post-Windows parent identity changed')
        prefix = parent['relativePath'] + '\\'
        expected = {row['relativePath'][len(prefix):]: row for row in products
                    if not row['directory'] and row['present'] and row['relativePath'].startswith(prefix)}
        keys = image.keys(reference)
        names = {key[wire.FILENAME_HEADER.size:].decode('utf-16le'): child for child, key in keys}
        require(len(names) == len(keys) and set(names) == set(expected), 'Post-Windows exact namespace differs')
        for name, child in names.items():
            wanted = expected[name]
            data = image.streams(child)['']
            require(child == int(wanted['reference']) and len(data) == wanted['bytes'] and
                    hashlib.sha256(data).hexdigest() == wanted['sha256'],
                    'Post-Windows original payload or full identity differs')
        observed.append(dict(parentReference=str(reference), entries=len(keys)))
    return observed


def partition(source, destination, offset, length):
    require(offset >= 0 and length > 0 and offset + length <= source.stat().st_size,
            'Partition slice exceeds its exact converted disk')
    expected = hashlib.sha256()
    with source.open('rb') as raw, destination.open('xb') as out:
        raw.seek(offset)
        for first in range(0, length, COPY_BYTES):
            count = min(COPY_BYTES, length - first)
            value = raw.read(count)
            require(len(value) == count, 'Converted disk ended early')
            expected.update(value)
            if any(value):
                require(out.write(value) == count, 'Partition output transfer was incomplete')
            else:
                out.seek(count, os.SEEK_CUR)
        out.truncate(length)
        out.flush()
        os.fsync(out.fileno())
    require(destination.stat().st_size == length and digest(destination) == expected.hexdigest(),
            'Complete extracted partition bytes differ')
    destination.chmod(0o444)
    return expected.hexdigest()


def gpt(source, batch, product):
    require(source.stat().st_size == batch['diskBytes'], 'Converted virtual disk size differs')
    with source.open('rb') as raw:
        _, primary, entries = checked_header(raw, PRIMARY_HEADER_LBA, batch['diskBytes'])
        _, backup, backup_entries = checked_header(raw, primary['backup_lba'], batch['diskBytes'])
    require(backup['backup_lba'] == PRIMARY_HEADER_LBA and
            backup['current_lba'] == batch['diskBytes'] // wire.SECTOR - 1 and entries == backup_entries,
            'Complete GPT copies differ')
    require(primary['disk_guid'] == backup['disk_guid'] and
            uuid.UUID(bytes_le=primary['disk_guid']) == uuid.UUID(product['diskGuid']),
            'Post-Windows disk GUID differs')
    selected = [fields(ENTRY, entries, first) for first in range(0, len(entries), ENTRY.size)
                if fields(ENTRY, entries, first)['type_guid'] == BASIC_DATA_TYPE]
    require(len(selected) == 1, 'Ambiguous native basic-data partition')
    entry = selected[0]
    require(uuid.UUID(bytes_le=entry['unique_guid']) == uuid.UUID(product['partitionGuid']) and
            entry['first_lba'] * wire.SECTOR == batch['partitionOffset'] and
            (entry['last_lba'] - entry['first_lba'] + 1) * wire.SECTOR == batch['partitionBytes'],
            'Post-Windows partition identity or geometry differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preparation', type=Path, required=True)
    parser.add_argument('--packages', type=Path, required=True)
    parser.add_argument('--replay', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--collector-source', type=Path,
                        help='Exact producer-revision collector for a later independent review checkout')
    parser.add_argument('--artifact-binding', type=Path,
                        help='Immutable artifact IDs and source identity resolved by the trusted workflow')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    preparation = args.preparation.resolve(strict=True)
    packages = args.packages.resolve(strict=True)
    replay = args.replay.resolve(strict=True)
    qemu = args.qemu.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = dict(status='running', cases=[], nativeMounts=0, automaticRetry=False,
                  expectedCacheSource='original pre-Windows predecessor', generalOwnerAdmitted=False,
                  sourceSha256=digest(Path(__file__)), decoderSha256=digest(qemu),
                  observerSha256=digest(ROOT / 'tests/native_hardlink_observer.py'),
                  verdictReviewerSha256=digest(ROOT / 'scripts/review_windows_hardlink.py'))
    try:
        if args.artifact_binding:
            binding = read(args.artifact_binding)
            require(isinstance(binding['sourceRun'], int) and binding['sourceRun'] > 0 and
                    re.fullmatch('[a-f0-9]{40}', binding['sourceSha']) is not None,
                    'Artifact producer identity is incomplete')
            artifacts = binding['artifacts']
            require(len(artifacts) == 3 and {row['name'] for row in artifacts} ==
                    {'hardlink-c-preparation', 'hardlink-recovery-packages', 'hardlink-native-recovery'} and
                    len({row['id'] for row in artifacts}) == 3 and
                    all(isinstance(row['id'], int) and row['id'] > 0 for row in artifacts),
                    'Immutable artifact identities are incomplete')
            result['artifactBinding'] = binding
        collector = args.collector_source.resolve(strict=True) if args.collector_source else None
        verdicts = review_verdicts(packages, replay, output / 'original-verdict-binding', collector)
        native_hashes = {row['case']: row['postimageSha256'] for row in verdicts['cases']}
        local = read(preparation / 'result.json')
        require(local['status'] == 'pass' and local['storageFamily'] == 'selected-cache-posix-hardlink',
                'Complete original C family report required')
        expected = {row['case']: row for row in local['cuts']}
        require(len(expected) == len(local['cuts']) == len(verdicts['cases']),
                'Original preparation/native case sets differ')
        package = read(packages / 'result.json')
        for group in range(len(package['groups'])):
            group_name = f'group-{group:02d}'
            batch = read(packages / group_name / 'batch.json')
            for product in batch['products']:
                identifier = product['case']
                require(identifier in expected, 'Native candidate has no original C expectation')
                match = re.fullmatch(r'hardlink-(cross-parent|same-parent|index-split)-(complete|cut-[0-9]{2})', identifier)
                require(match is not None, 'Unexpected hard-link family case')
                profile = match.group(1)
                transition_dir = preparation / profile / 'selected-operation'
                transition = read(transition_dir / 'hardlink-transition.json')
                before = transition_dir / 'before.ntfs'
                require(digest(before) == transition['sourceSha256'], 'Original pre-Windows predecessor changed')
                selected = expected[identifier]
                committed = selected['winner']
                require(isinstance(committed, bool), 'Missing original winner/loser expectation')
                source = replay / group_name / (identifier + '.vhd')
                source_hash = digest(source)
                require(source_hash == native_hashes[identifier],
                        'The detached VHD changed after original native-report binding')
                directory = output / identifier
                directory.mkdir()
                raw, volume = directory / 'postimage.raw', directory / 'postimage.ntfs'
                command([str(qemu), 'convert', '-f', 'vpc', '-O', 'raw', str(source), str(raw)],
                        directory, 'decode-vhd', tool_environment(), timeout=300, text=False)
                gpt(raw, batch, product)
                volume_hash = partition(raw, volume, batch['partitionOffset'], batch['partitionBytes'])
                original, observed = Image(before), Image(volume)
                reference = int(transition['reference'])
                source_parent = int(transition['sourceParent'])
                parent = int(transition['destinationParent'])
                if committed:
                    witness = verify_transform(before, volume, reference, source_parent,
                        transition['sourcePath'].rsplit('/', 1)[-1], parent,
                        transition['destinationPath'].rsplit('/', 1)[-1])
                else:
                    witness = old_endpoint(original, observed, reference, source_parent, parent)
                aliases = all_alias_parents(original, observed, reference, parent,
                    transition['destinationPath'].rsplit('/', 1)[-1], committed)
                security = security_unchanged(original, observed)
                namespaces = verify_namespace(observed, product['root'][2:].replace('\\', '/'),
                                               product['sequenceObjects'])
                require(digest(source) == source_hash and digest(before) == transition['sourceSha256'],
                        'Original VHD or expectation was changed by observation')
                result['cases'].append(dict(case=identifier, winner=committed, rawWitness=witness,
                    securityStore=security, originalAliases=aliases, namespaces=namespaces, postimageVhdSha256=source_hash,
                    completePartitionSha256=volume_hash, partitionBytes=batch['partitionBytes']))
                (output / 'review.json').write_text(json.dumps(result, indent=2) + '\n')
                # These are newly created decoder products. Exact original VHDs,
                # reports and pre-Windows expectations remain retained unchanged.
                volume.unlink()
                raw.unlink()
        require({row['case'] for row in result['cases']} == set(expected), 'Missing exact raw postimage review')
        result['status'] = 'pass'
    except BaseException as error:
        result.update(status='fail', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        (output / 'review.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(status=result['status'], cases=len(result['cases']), nativeMounts=0)))


if __name__ == '__main__':
    main()
