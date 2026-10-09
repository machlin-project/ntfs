#!/usr/bin/env python3
"""Qualify selected-cache hard-link storage on fresh Windows-authored image clones.

The general mutation owner stays closed. This private batch uses the sealed
planner/program/executor and fresh journal-derived recovery. It emits explicitly
named hardlink candidates for the unchanged guarded Windows collector/packager.
No VM command, mount, synthetic Windows verdict, or native API cache policy exists
in this command. Every output directory must be new; failures retain their inputs.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import re

import directory_scenarios as scenario
import fixtures as wire
from native_directory_batch import Batch, TRACE_CAPACITY, filetime, native_cuts
from native_growth_faults import at, apply, logical_protected, sha, stage_values, FRAME_BYTES
from native_hardlink_observer import Image, REFERENCE_MASK, attribute, restore, storage, verify_transform

ROOT = Path(__file__).resolve().parents[1]
RESIDENT_BYTES = b'Machlin original resident NTFS write witness.\r\n'
ADS_BYTES = b'original named stream witness'
MAX_FILLERS = 80


def same_metadata(actual, before, expected, region):
    if region['attribute_type'] == wire.DATA and region['reference'] & REFERENCE_MASK == 0:
        for first in range(0, len(expected), wire.RECORD):
            old = before[first:first + wire.RECORD]
            wanted = expected[first:first + wire.RECORD]
            value = actual[first:first + wire.RECORD]
            if old == wanted:
                assert value == wanted
            else:
                restore(value, b'FILE')
                assert logical_protected(value, region) == logical_protected(wanted, region)
    elif region['attribute_type'] == wire.INDEX_ALLOC:
        restore(actual, b'INDX')
        assert logical_protected(actual, region) == logical_protected(expected, region)
    else:
        assert actual == expected


class Hardlinks(Batch):
    def compare_images(self, directory, name, expected, actual):
        size = expected.stat().st_size
        assert actual.stat().st_size == size
        expected_hash, actual_hash = hashlib.sha256(), hashlib.sha256()
        with expected.open('rb') as left, actual.open('rb') as right:
            for first in range(0, size, 1024 * 1024):
                count = min(1024 * 1024, size - first)
                before, after = left.read(count), right.read(count)
                assert len(before) == len(after) == count and before == after
                expected_hash.update(before)
                actual_hash.update(after)
        report = dict(complete=True, bytes=size, expected=str(expected), actual=str(actual),
                      expectedSha256=expected_hash.hexdigest(), actualSha256=actual_hash.hexdigest())
        (directory / (name + '.json')).write_text(json.dumps(report, indent=2) + '\n')

    def observe(self, directory, prefix, image, wanted):
        raw = Image(image)
        objects = []
        for number, folder in enumerate(scenario.DIRECTORIES):
            reference = raw.resolve(self.native_root + '/' + folder)
            metadata = self.json_command(directory, f'{prefix}-stat-{number}',
                [self.tool('ntfs-inspect'), image, 'stat-ref', format(reference, 'x')])
            descriptor = self.command(directory, f'{prefix}-acl-{number}',
                [self.tool('ntfs-inspect'), image, 'security-ref', format(reference, 'x')])
            assert metadata['directory'] and int(metadata['reference'], 16) == reference
            objects.append(dict(relativePath=folder, directory=True, present=True, reference=str(reference),
                lastWriteFileTime=str(filetime(metadata['modified'])),
                securityDescriptor=base64.b64encode(descriptor).decode('ascii')))
            entries = raw.keys(reference)
            names = {key[wire.FILENAME_HEADER.size:].decode('utf-16le'): child for child, key in entries}
            expected = {path[len(folder) + 1:]: content for path, content in wanted.items()
                        if path.startswith(folder + '/')}
            assert len(names) == len(entries) and set(names) == set(expected)
            for ordinal, (name, child) in enumerate(sorted(names.items())):
                content = raw.streams(child)['']
                assert content == expected[name]
                metadata = self.json_command(directory, f'{prefix}-stat-{number}-{ordinal}',
                    [self.tool('ntfs-inspect'), image, 'stat-ref', format(child, 'x')])
                descriptor = self.command(directory, f'{prefix}-acl-{number}-{ordinal}',
                    [self.tool('ntfs-inspect'), image, 'security-ref', format(child, 'x')])
                _, header, attrs = raw.record(child)
                filename_values = [storage.resident_value(value) for value in attrs
                                   if storage.attr_header(value)['type'] == wire.FILENAME]
                primary = sum(wire.FILENAME_HEADER.unpack_from(value)[-1] != wire.NAMESPACE_DOS
                              for value in filename_values)
                assert header['links'] == len(filename_values) and metadata['links'] == primary
                objects.append(dict(relativePath=folder + '\\' + name, directory=False, present=True,
                    reference=str(child), lastWriteFileTime=str(filetime(metadata['modified'])),
                    bytes=len(content), sha256=hashlib.sha256(content).hexdigest(),
                    securityDescriptor=base64.b64encode(descriptor).decode('ascii')))
        source = raw.resolve(self.native_root + '/resident.txt')
        assert raw.streams(source) == {'': RESIDENT_BYTES, 'original-stream': ADS_BYTES}
        return objects

    def mutation(self, directory, operation, path, extra=(), stamp=0, prepare=False):
        trace = directory / 'trace'
        trace.mkdir()
        args = [self.tool('ntfs-write-operation-image-tests'), 'prepare' if prepare else 'interrupt',
                self.image, operation, self.native_root + '/' + path, stamp, trace, *extra]
        if not prepare:
            args += ['--fault', 0, 0, 0, TRACE_CAPACITY]
        result = self.json_command(directory, 'prepare' if prepare else 'writer', args)
        assert result['result'] == 0 and not result['poisoned']
        plan = json.loads((trace / 'plan.json').read_text())
        if prepare:
            assert not result['execution_requested'] and not result['executed'] and result['writes'] == 0
        else:
            assert result['executed'] and result['completed'] and result['initial_persistence']
            self.events(trace, plan)
        return trace, plan

    def exact_outside(self, original, current, plan):
        raw = Image(original)
        logfile_raw = raw.mapped(raw.mft_runs, 2 * wire.RECORD, wire.RECORD)
        _, attrs = storage.record_parts(logfile_raw)
        _, runs = storage.mapping(attribute(attrs, wire.DATA))
        managed = [(lcn * wire.CLUSTER, (lcn + count) * wire.CLUSTER) for count, lcn in runs]
        managed += [(row['physical'], row['physical'] + row['bytes']) for row in plan['regions']]
        size = original.stat().st_size
        assert current.stat().st_size == size
        with original.open('rb') as source, current.open('rb') as result:
            for first in range(0, size, FRAME_BYTES):
                count = min(FRAME_BYTES, size - first)
                left, right = source.read(count), result.read(count)
                assert len(left) == len(right) == count
                if any(start <= first and first + count <= end for start, end in managed):
                    continue
                assert not any(start < first + count and end > first for start, end in managed)
                assert left == right

    def capture(self, name, directory, before, trace, plan, source_path, destination_path, wanted):
        before_raw, after_raw = Image(before), Image(self.image)
        reference = before_raw.resolve(self.native_root + '/' + source_path)
        source_parent = before_raw.resolve(self.native_root + '/' + source_path.rsplit('/', 1)[0]) if '/' in source_path else before_raw.resolve(self.native_root)
        parent = before_raw.resolve(self.native_root + '/' + destination_path.rsplit('/', 1)[0])
        witness = verify_transform(before, self.image, reference, source_parent, source_path.rsplit('/', 1)[-1],
                                   parent, destination_path.rsplit('/', 1)[-1])
        assert after_raw.resolve(self.native_root + '/' + destination_path) == reference
        old_acl = self.command(directory, 'source-acl-before',
            [self.tool('ntfs-inspect'), before, 'security-ref', format(reference, 'x')])
        new_acl = self.command(directory, 'source-acl-after',
            [self.tool('ntfs-inspect'), self.image, 'security-ref', format(reference, 'x')])
        assert old_acl == new_acl
        old_wanted = dict(wanted)
        old_wanted.pop(destination_path)
        old_objects = self.observe(directory, 'before', before, old_wanted)
        new_objects = self.observe(directory, 'after', self.image, wanted)
        state = self.state(directory, 'before-state', before, parent)
        cuts = native_cuts(plan, int(state['mftInitializedBytes']))
        selected = {(cut['complete'], cut['prefixBytes']) for cut in cuts}
        commit = next(index for index, row in enumerate(plan['publications'])
                      if row['stage'] == stage_values()['COMMIT_COPY'])
        for index, row in enumerate(plan['publications']):
            if row['stage'] == stage_values()['METADATA_HOME']:
                selected.update((index, prefix) for prefix in (0, wire.SECTOR))
        cuts = [dict(complete=index, prefixBytes=prefix, winner=index > commit)
                for index, prefix in sorted(selected)]
        transition = dict(kind='hardlink-' + name, source=str(before), sourceSha256=sha(before),
            trace=str(trace), beforeState=state, cases=cuts, loserObjects=old_objects, winnerObjects=new_objects,
            sourcePath=source_path, destinationPath=destination_path, reference=str(reference),
            sourceParent=str(source_parent), destinationParent=str(parent), independentWitness=witness)
        transition_path = directory / 'hardlink-transition.json'
        transition_path.write_text(json.dumps(transition, indent=2) + '\n')
        self.report['transitions'].append(dict(kind=transition['kind'], path=str(transition_path)))
        self.compare_images(directory, 'complete-image-oracle', self.oracle, self.image)
        self.exact_outside(before, self.image, plan)
        validation = self.json_command(directory, 'complete-validate', [self.tool('ntfs-validate'), self.image])
        assert validation['complete'] and validation['result'] == 'success'
        quiet_trace = directory / 'complete-reopen'
        quiet_trace.mkdir()
        quiet = self.json_command(directory, 'complete-reopen',
            [self.tool('ntfs-native-checkpoint'), '--recover', self.image, quiet_trace])
        assert quiet['result'] == 0 and quiet['completed'] and quiet['writes'] == 0
        completed = directory / 'completed.ntfs'
        self.clone(directory, 'retain-complete', self.image, completed)
        completed.chmod(0o444)
        objects_path = directory / 'objects.json'
        objects_path.write_text(json.dumps(new_objects, indent=2) + '\n')
        self.report['cuts'].append(dict(case='hardlink-' + name + '-complete', image=str(completed),
            sha256=sha(completed), objects=str(objects_path), localRecovery=True, winner=True,
            storageFamily='selected-cache-posix-hardlink'))
        self.save()
        for number, cut in enumerate(cuts):
            case = self.output / f'hardlink-{name}-cut-{number:02d}'
            case.mkdir()
            crash, recovered, oracle = case / 'crash.ntfs', case / 'recovered.ntfs', case / 'recovery-oracle.ntfs'
            self.clone(case, 'clone-crash', before, crash)
            changes = [(row['physical'], (trace / f'publication-{index}.bin').read_bytes())
                       for index, row in enumerate(plan['publications'][:cut['complete']])]
            if cut['prefixBytes']:
                index = cut['complete']
                changes.append((plan['publications'][index]['physical'],
                                (trace / f'publication-{index}.bin').read_bytes()[:cut['prefixBytes']]))
            apply(crash, changes)
            crash.chmod(0o444)
            self.clone(case, 'clone-recovered', crash, recovered)
            self.clone(case, 'clone-recovery-oracle', crash, oracle)
            recovery_trace = case / 'recovery'
            recovery_trace.mkdir()
            result = self.json_command(case, 'recover',
                [self.tool('ntfs-native-checkpoint'), '--recover', recovered, recovery_trace])
            assert result['result'] == 0 and result['completed'] and not result['poisoned']
            events = json.loads((recovery_trace / 'events.json').read_text())
            assert not events['triggered'] and not events['native_failure']
            recovered_changes = []
            for event_index, event in enumerate(events['events']):
                assert event['result'] == event['native_result'] == 0
                if not event['barrier']:
                    value = (recovery_trace / f'event-{event_index}.bin').read_bytes()
                    assert len(value) == event['bytes'] == event['completed'] == FRAME_BYTES
                    recovered_changes.append((event['physical'], value))
            apply(oracle, recovered_changes)
            self.compare_images(case, 'complete-recovery-oracle', oracle, recovered)
            self.exact_outside(before, recovered, plan)
            for region_index, region in enumerate(plan['regions']):
                expected = (trace / f'region-after-{region_index}.bin').read_bytes() if cut['winner'] else at(before, region['physical'], region['bytes'])
                actual = at(recovered, region['physical'], region['bytes'])
                if cut['winner']:
                    same_metadata(actual, at(before, region['physical'], region['bytes']), expected, region)
                else:
                    assert actual == expected
            if cut['winner']:
                verify_transform(before, recovered, reference, source_parent, source_path.rsplit('/', 1)[-1],
                                 parent, destination_path.rsplit('/', 1)[-1])
            objects = self.observe(case, 'recovered', recovered, wanted if cut['winner'] else old_wanted)
            assert objects == (new_objects if cut['winner'] else old_objects)
            validation = self.json_command(case, 'validate', [self.tool('ntfs-validate'), recovered])
            assert validation['complete'] and validation['result'] == 'success'
            quiet_trace = case / 'quiet'
            quiet_trace.mkdir()
            quiet = self.json_command(case, 'quiet',
                [self.tool('ntfs-native-checkpoint'), '--recover', recovered, quiet_trace])
            assert quiet['result'] == 0 and quiet['completed'] and quiet['writes'] == 0
            object_path = case / 'objects.json'
            object_path.write_text(json.dumps(objects, indent=2) + '\n')
            self.report['cuts'].append(dict(case=case.name, **cut, image=str(crash), sha256=sha(crash),
                objects=str(object_path), transition=str(transition_path), localRecovery=True,
                storageFamily='selected-cache-posix-hardlink'))
            self.save()

    def profile(self, name, source, stamp):
        folder = self.output / name
        folder.mkdir()
        self.image, self.oracle = folder / 'candidate.ntfs', folder / 'publication-oracle.ntfs'
        self.clone(folder, 'clone-source', source, self.image)
        self.clone(folder, 'clone-oracle', source, self.oracle)
        wanted = {}
        for ordinal, directory in enumerate(scenario.DIRECTORIES):
            step = folder / f'mkdir-{ordinal}'
            step.mkdir()
            self.mutation(step, 'mkdir', directory, stamp=stamp + ordinal)
        self.checkpoint('hardlink-' + name + '-seed')
        source_path, destination = 'resident.txt', 'native-growth/sustained-file'
        if name == 'same-parent':
            step = folder / 'seed-link'
            step.mkdir()
            self.mutation(step, 'hardlink-storage', source_path,
                          [self.native_root + '/' + destination])
            wanted[destination] = RESIDENT_BYTES
            source_path, destination = destination, 'native-growth/replacement-0000'
            self.checkpoint('hardlink-' + name + '-link')
        if name == 'index-split':
            destination = 'native-growth/' + scenario.pressure_name(scenario.PRESSURE_FILES - 1)
            for ordinal in range(MAX_FILLERS):
                probe = folder / f'probe-{ordinal:03d}'
                probe.mkdir()
                _, plan = self.mutation(probe, 'hardlink-storage', source_path,
                                        [self.native_root + '/' + destination], prepare=True)
                parent = Image(self.image).resolve(self.native_root + '/native-growth')
                state = self.state(probe, 'state', self.image, parent)
                if state['directoryLiveIndexBlocks'] >= 3 and any(
                    row['attribute_type'] == wire.INDEX_ALLOC and not row['index_allocated']
                    for row in plan['regions']):
                    break
                step = folder / f'filler-{ordinal:03d}'
                step.mkdir()
                path = 'native-growth/' + scenario.pressure_name(ordinal)
                self.mutation(step, 'create', path, stamp=stamp + ordinal + 2)
                wanted[path] = b''
                if ordinal % 4 == 3:
                    self.checkpoint('hardlink-' + name + f'-{ordinal:03d}')
            else:
                raise AssertionError('No hard-link index split found within the authored filler bound')
        step = folder / 'selected-operation'
        step.mkdir()
        before = step / 'before.ntfs'
        self.clone(step, 'clone-before', self.image, before)
        before.chmod(0o444)
        trace, plan = self.mutation(step, 'hardlink-storage', source_path,
                                    [self.native_root + '/' + destination])
        wanted[destination] = RESIDENT_BYTES
        self.capture(name, step, before, trace, plan, source_path, destination, wanted)

    def checkpoint(self, identity):
        directory = self.output / ('checkpoint-' + str(identity))
        directory.mkdir()
        trace = directory / 'trace'
        trace.mkdir()
        result = self.json_command(directory, 'checkpoint',
            [self.tool('ntfs-native-checkpoint'), '--image', self.image, trace])
        assert result['result'] == 0 and result['completed'] and not result['poisoned']
        self.events(trace)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cloud-manifest', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    cloud = json.loads(args.cloud_manifest.read_text())
    assert cloud['status'] == 'pass' and cloud['nativeWindowsRecoveryPending'] is True
    assert re.fullmatch(r'R:\\MachlinCloudNTFS-[0-9a-f]{32}', cloud['root'])
    descriptor = json.loads(Path(cloud['sourceDescriptor']).read_text())
    source = Path(descriptor['source']).resolve(strict=True)
    assert source.is_file() and source.stat().st_mode & 0o777 == 0o444
    assert sha(source) == descriptor['sourceSha256']
    baseline = json.loads(Path(cloud['baselineManifest']).read_text())
    assert baseline['root'] == cloud['root']
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    batch = Hardlinks(output, args.build.resolve(strict=True), None,
                      cloud['root'][2:].replace('\\', '/'))
    batch.report.update(storageFamily='selected-cache-posix-hardlink', source=str(source),
        sourceSha256=sha(source), cloudManifest=str(args.cloud_manifest.resolve()),
        baselineManifest=cloud['baselineManifest'], nativeWindowsRecoveryPending=True,
        generalOwnerAdmitted=False, nativeApiCacheSemantics=False,
        binaries={name: sha(batch.tool(name)) for name in ('ntfs-inspect', 'ntfs-native-state',
            'ntfs-native-checkpoint', 'ntfs-validate', 'ntfs-write-operation-image-tests')})
    try:
        stamp = int(next(row['lastWriteFileTime'] for row in baseline['files']
                         if row['relativePath'] == 'resident.txt'))
        for name in ('cross-parent', 'same-parent', 'index-split'):
            batch.profile(name, source, stamp)
        assert sha(source) == descriptor['sourceSha256']
        batch.report['status'] = 'pass'
    except BaseException:
        batch.report['status'] = 'fail'
        raise
    finally:
        batch.save()


if __name__ == '__main__':
    main()
