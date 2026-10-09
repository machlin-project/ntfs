#!/usr/bin/env python3
"""Current-C directory transitions and preselected native crash inputs; no VM commands.

All writes target new private regular-file copies. The source descriptor names retained
native media and its hash, not a binary or verdict to reuse. Failures stop the
batch without retries. A separate packaging step and Windows collector follow.
"""
from pathlib import Path
import argparse
import base64
import copy
import hashlib
import json
import re
import shutil
import sys
import time

import directory_scenarios as scenario
from native_growth_faults import (sha, at, apply, stage_values, logical_protected,
                                  FRAME_BYTES, SECTOR_BYTES, FILETIME_TICKS_PER_SECOND,
                                  WINDOWS_EPOCH_SECONDS, NANOSECONDS_PER_TICK,
                                  metadata_class, expected_inventory, verify_inventory)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import sanitizer_environment
from benchmark_toolchain import command as bounded_command

TRACE_CAPACITY = 4096
CHECKPOINT_INTERVAL = 4
NATIVE_ROOT = '/MachlinWriteCases-native-write-alias-20261006'
TRANSITIONS = ('root-spill', 'split', 'merge', 'root-collapse')


def filetime(stat):
    return ((int(stat['seconds']) + WINDOWS_EPOCH_SECONDS) * FILETIME_TICKS_PER_SECOND
            + stat['nanoseconds'] // NANOSECONDS_PER_TICK)


def native_cuts(plan, initialized):
    """Select before recovery: roots, both prepare/commit locations and home metadata."""
    stages = stage_values()
    rows = plan['publications']
    selected = set()
    for label in ('DIRTY_FIRST', 'DIRTY_SECOND', 'PREPARE_COPY', 'PREPARE_HOME',
                  'COMMIT_COPY', 'COMMIT_HOME', 'CLEAN_FIRST', 'CLEAN_SECOND'):
        positions = [index for index, row in enumerate(rows) if row['stage'] == stages[label]]
        assert positions, label
        selected.add((positions[0], SECTOR_BYTES))
        if label.startswith('COMMIT_'):
            selected.add((positions[0], 0))
    homes = [index for index, row in enumerate(rows) if row['stage'] == stages['METADATA_HOME']]
    assert homes
    regions = {row['physical']: row for row in plan['regions']}
    classes = {}
    for index in homes:
        label = metadata_class(regions[rows[index]['physical']], initialized)
        classes.setdefault(label, index)
    selected.update((index, SECTOR_BYTES) for index in classes.values())
    commit = next(index for index, row in enumerate(rows) if row['stage'] == stages['COMMIT_COPY'])
    return [dict(complete=index, prefixBytes=prefix, winner=index > commit)
            for index, prefix in sorted(selected)]


class Batch:
    def __init__(self, output, build, qemu, native_root=NATIVE_ROOT):
        self.output, self.build, self.qemu = output, build, qemu
        self.env = sanitizer_environment()
        self.report = dict(status='running', vmCommands=0, automaticRetry=False,
                           commands=[], operations=[], checkpoints=[], transitions=[], snapshots=[], cuts=[])
        self.image, self.oracle = output / 'candidate.ntfs', output / 'publication-oracle.ntfs'
        self.files, self.directories = {}, {}
        self.native_root = native_root

    def save(self):
        (self.output / 'result.json').write_text(json.dumps(self.report, indent=2) + '\n')

    def command(self, directory, name, argv, timeout=600):
        argv = list(map(str, argv))
        started = time.monotonic()
        entry = dict(argv=argv, directory=str(directory), name=name, status='running')
        self.report['commands'].append(entry)
        self.save()
        try:
            value = bounded_command(argv, directory, name, self.env, timeout=timeout, text=False)
            assert (directory / (name + '.stderr')).stat().st_size == 0, (name, directory)
            entry.update(status='pass', exitCode=0)
            return value
        except BaseException as error:
            entry.update(status='fail', error=f'{type(error).__name__}: {error}')
            raise
        finally:
            entry['seconds'] = time.monotonic() - started
            self.save()

    def json_command(self, directory, name, argv):
        return json.loads(self.command(directory, name, argv))

    def tool(self, name):
        return self.build / name

    def clone(self, directory, name, source, destination):
        assert not destination.exists() and not destination.is_symlink()
        options = ['-c'] if sys.platform == 'darwin' else ['--reflink=auto', '--sparse=always', '--']
        self.command(directory, name, ['/bin/cp', *options, source, destination])
        destination.chmod(0o600)
        assert destination.stat().st_nlink == 1 and destination.stat().st_size == source.stat().st_size

    def state(self, directory, name, image, reference):
        return self.json_command(directory, name, [self.tool('ntfs-native-state'), image, reference])

    def objects(self, directory, prefix, image, files=None, directories=None):
        files = self.files if files is None else files
        directories = self.directories if directories is None else directories
        result = []
        for number, folder in enumerate(scenario.DIRECTORIES):
            if folder not in directories:
                result.append(dict(relativePath=folder, directory=True, present=False))
                continue
            reference = directories[folder]
            metadata = self.json_command(directory, f'{prefix}-stat-{number}',
                [self.tool('ntfs-inspect'), image, 'stat-ref', format(reference, 'x')])
            descriptor = self.command(directory, f'{prefix}-security-{number}',
                [self.tool('ntfs-inspect'), image, 'security-ref', format(reference, 'x')])
            result.append(dict(relativePath=folder, directory=True, present=True, reference=str(reference),
                lastWriteFileTime=str(filetime(metadata['modified'])),
                securityDescriptor=base64.b64encode(descriptor).decode('ascii')))
            raw = self.command(directory, f'{prefix}-inventory-{number}',
                [self.tool('ntfs-native-inventory'), image, reference])
            actual = set()
            wanted = {path: entry for path, entry in files.items() if path.startswith(folder + '/')}
            for line in raw.splitlines():
                entry = json.loads(line)
                name = folder + '/' + ''.join(chr(unit) for unit in entry['nameUnits'])
                assert name in wanted and name not in actual
                model = wanted[name]
                modified = filetime(dict(seconds=entry['modifiedSeconds'], nanoseconds=entry['modifiedNanoseconds']))
                assert int(entry['reference']) == model['reference'] and int(entry['parentReference']) == reference
                assert entry['size'] == 0 and entry['dataHex'] == '' and entry['links'] == 1
                assert modified == model['filetime']
                actual.add(name)
                result.append(dict(relativePath=name.replace('/', '\\'), directory=False, present=True,
                    reference=entry['reference'], lastWriteFileTime=str(modified), bytes=0,
                    sha256=hashlib.sha256(b'').hexdigest(),
                    securityDescriptor=base64.b64encode(bytes.fromhex(entry['descriptorHex'])).decode('ascii')))
            assert actual == set(wanted)
        return result

    def events(self, trace, plan=None):
        captured = json.loads((trace / 'events.json').read_text())
        assert not captured['triggered'] and not captured['native_failure']
        changes = []
        for number, row in enumerate(captured['events']):
            assert row['result'] == row['native_result'] == 0
            if row['barrier']:
                continue
            value = (trace / f'event-{number}.bin').read_bytes()
            assert row['native_attempted'] and not row['injected']
            assert len(value) == row['bytes'] == row['completed'] == FRAME_BYTES
            if plan is not None:
                publication = plan['publications'][len(changes)]
                assert publication['physical'] == row['physical']
                assert value == (trace / f'publication-{len(changes)}.bin').read_bytes()
            changes.append((row['physical'], value))
        if plan is not None:
            assert len(changes) == len(plan['publications'])
        apply(self.oracle, changes)
        for first, value in dict(changes).items():
            assert at(self.image, first, len(value)) == value

    def checkpoint(self, ordinal, reason='periodic'):
        assert reason in ('periodic', 'admission-pressure')
        prefix = 'checkpoint' if reason == 'periodic' else 'pressure-checkpoint'
        directory = self.output / f'{prefix}-{ordinal:04d}'
        directory.mkdir()
        trace = directory / 'trace'
        trace.mkdir()
        result = self.json_command(directory, 'checkpoint',
            [self.tool('ntfs-native-checkpoint'), '--image', self.image, trace])
        assert result['result'] == 0 and result['completed'] and not result['poisoned']
        self.events(trace)
        self.report['checkpoints'].append(dict(ordinal=ordinal, reason=reason, directory=str(directory)))
        self.save()

    def checkpoint_before_operation(self, ordinal, directory):
        if 'native-growth' not in self.directories:
            return
        reference = self.directories['native-growth']
        state = self.state(directory, 'admission-state', self.image, reference)
        assert state['settled'] and state['mftReservedAllocationMask'] == 0
        assert type(state['checkpointNeeded']) is bool
        if state['checkpointNeeded']:
            self.checkpoint(ordinal, reason='admission-pressure')
            state = self.state(directory, 'admission-after-checkpoint', self.image, reference)
            assert state['settled'] and state['mftReservedAllocationMask'] == 0
            assert state['checkpointNeeded'] is False

    def snapshot(self, phase, directory):
        self.command(directory, 'whole-publication-oracle',
                     [self.qemu, 'compare', '-f', 'raw', '-F', 'raw', self.oracle, self.image])
        validation = self.json_command(directory, 'validate', [self.tool('ntfs-validate'), self.image])
        assert validation['complete'] and validation['result'] == 'success'
        rows = self.objects(directory, 'snapshot', self.image)
        scenario.verify_objects(rows, phase)
        image = directory / (phase + '.ntfs')
        self.clone(directory, 'retain-snapshot', self.image, image)
        image.chmod(0o444)
        (directory / 'objects.json').write_text(json.dumps(rows, indent=2) + '\n')
        self.report['snapshots'].append(dict(phase=phase, image=str(image), sha256=sha(image),
                                            objects=str(directory / 'objects.json')))
        self.save()

    def mutate(self, ordinal, operation, path, extra, phase, start_time):
        directory = self.output / f'operation-{ordinal:04d}'
        directory.mkdir()
        trace = directory / 'trace'
        trace.mkdir()
        # Observe the existing core admission signal before freezing a crash
        # predecessor. This is scheduled maintenance, never a writer retry.
        self.checkpoint_before_operation(ordinal, directory)
        previous = directory / 'before.ntfs'
        self.clone(directory, 'clone-before', self.image, previous)
        previous.chmod(0o444)
        old_files, old_directories = copy.deepcopy(self.files), dict(self.directories)
        old_state = self.state(directory, 'before-state', previous, self.directories['native-growth']) if 'native-growth' in self.directories else None
        stamp = start_time + ordinal * FILETIME_TICKS_PER_SECOND
        arguments = (self.native_root + '/' + extra[0], extra[1]) if operation == 'rename' else extra
        result = self.json_command(directory, 'writer', [self.tool('ntfs-write-operation-image-tests'),
            'interrupt', self.image, operation, self.native_root + '/' + path, stamp, trace, *arguments,
            '--fault', 0, 0, 0, TRACE_CAPACITY])
        assert result['result'] == 0 and result['executed'] and result['completed'] and not result['poisoned']
        assert result['instrumented'] and result['initial_persistence']
        plan = json.loads((trace / 'plan.json').read_text())
        for number, row in enumerate(plan['regions']):
            assert at(self.oracle, row['physical'], row['bytes']) == (trace / f'region-before-{number}.bin').read_bytes()
        self.events(trace, plan)
        if operation == 'mkdir':
            self.directories[path] = int(result['reference'])
        elif operation == 'create':
            self.files[path] = dict(reference=int(result['reference']), filetime=stamp)
        elif operation == 'remove':
            del self.files[path]
        else:
            assert operation == 'rename'
            self.files[extra[0]] = self.files.pop(path)
        state = self.state(directory, 'after-state', self.image, self.directories['native-growth'])
        assert state['settled'] and state['mftReservedAllocationMask'] == 0
        label = None
        if old_state is not None:
            before, after = old_state['directoryLiveIndexBlocks'], state['directoryLiveIndexBlocks']
            label = ('root-spill' if before == 0 and after > 0 else
                     'root-collapse' if before > 0 and after == 0 else
                     'split' if after > before else 'merge' if after < before else None)
        if label and label not in {row['kind'] for row in self.report['transitions']}:
            before_rows = self.objects(directory, 'loser', previous, old_files, old_directories)
            after_rows = self.objects(directory, 'winner', self.image)
            cases = native_cuts(plan, int(old_state['mftInitializedBytes']))
            transition = dict(kind=label, source=str(previous), sourceSha256=sha(previous),
                trace=str(trace), beforeState=old_state, afterState=state, cases=cases,
                loserObjects=before_rows, winnerObjects=after_rows)
            (directory / 'transition.json').write_text(json.dumps(transition, indent=2) + '\n')
            self.report['transitions'].append(dict(kind=label, path=str(directory / 'transition.json')))
        else:
            previous.unlink()
        self.report['operations'].append(dict(ordinal=ordinal, operation=operation, path=path,
            arguments=list(extra), filetime=str(stamp), trace=str(trace), state=state))
        if ordinal % CHECKPOINT_INTERVAL == 0:
            self.checkpoint(ordinal)
        if phase:
            self.snapshot(phase, directory)
        self.save()

    def recover_cuts(self):
        # Selection files above are complete before the first recovery runs.
        for item in self.report['transitions']:
            transition = json.loads(Path(item['path']).read_text())
            source, trace = Path(transition['source']), Path(transition['trace'])
            assert sha(source) == transition['sourceSha256']
            plan = json.loads((trace / 'plan.json').read_text())
            homes = {row['physical']: (trace / f'publication-{index}.bin').read_bytes()
                     for index, row in enumerate(plan['publications'])
                     if row['stage'] == stage_values()['METADATA_HOME']}
            assert set(homes) == {row['physical'] for row in plan['regions']}
            for number, case in enumerate(transition['cases']):
                directory = self.output / f"{item['kind']}-cut-{number:02d}"
                directory.mkdir()
                crash, recovered = directory / 'crash.ntfs', directory / 'recovered.ntfs'
                self.clone(directory, 'clone-crash', source, crash)
                changes = [(row['physical'], (trace / f'publication-{index}.bin').read_bytes())
                           for index, row in enumerate(plan['publications'][:case['complete']])]
                if case['prefixBytes']:
                    index = case['complete']
                    changes.append((plan['publications'][index]['physical'],
                                    (trace / f'publication-{index}.bin').read_bytes()[:case['prefixBytes']]))
                apply(crash, changes)
                crash.chmod(0o444)
                self.clone(directory, 'clone-recovery', crash, recovered)
                recovery_trace = directory / 'recovery'
                recovery_trace.mkdir()
                result = self.json_command(directory, 'recover',
                    [self.tool('ntfs-native-checkpoint'), '--recover', recovered, recovery_trace])
                assert result['result'] == 0 and result['completed'] and not result['poisoned']
                for index, region in enumerate(plan['regions']):
                    if not case['winner'] and metadata_class(region, int(transition['beforeState']['mftInitializedBytes'])) in ('new-index', 'new-file-records'):
                        continue  # Reclaimed storage is unowned in the predecessor.
                    wanted = homes[region['physical']] if case['winner'] else at(source, region['physical'], region['bytes'])
                    observed = at(recovered, region['physical'], region['bytes'])
                    assert logical_protected(observed, region) == logical_protected(wanted, region)
                validation = self.json_command(directory, 'validate', [self.tool('ntfs-validate'), recovered])
                assert validation['complete'] and validation['result'] == 'success'
                objects = transition['winnerObjects' if case['winner'] else 'loserObjects']
                for folder_number, folder in enumerate(scenario.DIRECTORIES):
                    parent = next(row for row in objects if row['relativePath'] == folder and row['directory'])
                    assert parent['present']
                    raw = self.command(directory, f'recovered-inventory-{folder_number}',
                        [self.tool('ntfs-native-inventory'), recovered, parent['reference']])
                    verify_inventory(raw, expected_inventory(objects, folder + '\\'), parent['reference'])
                quiet_trace = directory / 'quiet'
                quiet_trace.mkdir()
                quiet = self.json_command(directory, 'fresh-reopen',
                    [self.tool('ntfs-native-checkpoint'), '--recover', recovered, quiet_trace])
                assert quiet['result'] == 0 and quiet['completed'] and quiet['writes'] == 0
                (directory / 'objects.json').write_text(json.dumps(objects, indent=2) + '\n')
                self.report['cuts'].append(dict(case=directory.name, **case, image=str(crash), sha256=sha(crash),
                    objects=str(directory / 'objects.json'), transition=item['path'], localRecovery=True))
                recovered.unlink()
                self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-descriptor', type=Path)
    parser.add_argument('--baseline-manifest', type=Path)
    parser.add_argument('--cloud-manifest', type=Path,
                        help='Prepared native scratch manifest from windows_cloud_inputs.py')
    parser.add_argument('--build', type=Path, default=ROOT / '.build')
    parser.add_argument('--qemu', type=Path, default=Path(shutil.which('qemu-img') or '/opt/homebrew/bin/qemu-img'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    native_root = NATIVE_ROOT
    if args.cloud_manifest:
        if args.source_descriptor or args.baseline_manifest:
            parser.error('--cloud-manifest cannot be combined with historical source arguments')
        cloud = json.loads(args.cloud_manifest.read_text())
        assert cloud['status'] == 'pass' and cloud['nativeWindowsRecoveryPending'] is True
        assert re.fullmatch(r'R:\\MachlinCloudNTFS-[0-9a-f]{32}', cloud['root'])
        args.source_descriptor = Path(cloud['sourceDescriptor'])
        args.baseline_manifest = Path(cloud['baselineManifest'])
        native_root = cloud['root'][2:].replace('\\', '/')
    elif not args.source_descriptor or not args.baseline_manifest:
        parser.error('Supply --cloud-manifest or both historical source manifests')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    batch = Batch(output, args.build.resolve(strict=True), args.qemu.resolve(strict=True), native_root)
    source_info = json.loads(args.source_descriptor.read_text())
    source = Path(source_info['source']).resolve(strict=True)
    baseline = json.loads(args.baseline_manifest.read_text())
    assert source.is_file() and source.stat().st_mode & 0o777 == 0o444
    assert sha(source) == source_info['sourceSha256']
    assert baseline['root'] == 'R:' + native_root.replace('/', '\\')
    batch.report.update(source=str(source), sourceSha256=source_info['sourceSha256'],
        baselineManifest=str(args.baseline_manifest.resolve()),
        cloudManifest=str(args.cloud_manifest.resolve()) if args.cloud_manifest else None,
        binaries={name: sha(batch.tool(name)) for name in ('ntfs-native-state', 'ntfs-native-checkpoint',
            'ntfs-native-inventory', 'ntfs-write-operation-image-tests', 'ntfs-inspect', 'ntfs-validate')},
        sanitizerOptions={key: batch.env[key] for key in ('ASAN_OPTIONS', 'UBSAN_OPTIONS')})
    try:
        batch.clone(output, 'clone-source', source, batch.image)
        batch.clone(output, 'clone-oracle', source, batch.oracle)
        start_time = int(next(row['lastWriteFileTime'] for row in baseline['files'] if row['relativePath'] == 'resident.txt'))
        for ordinal, (operation, path, extra, phase) in enumerate(scenario.operations(), 1):
            batch.mutate(ordinal, operation, path, extra, phase, start_time)
        assert {row['kind'] for row in batch.report['transitions']} == set(TRANSITIONS)
        assert [row['phase'] for row in batch.report['snapshots']] == list(scenario.PHASES)
        batch.recover_cuts()
        assert sha(source) == source_info['sourceSha256']
        batch.report['status'] = 'pass'
    except BaseException:
        batch.report['status'] = 'fail'
        raise
    finally:
        batch.save()


if __name__ == '__main__':
    main()
