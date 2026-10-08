"""Fresh C recovery of independently constructed native MFT/index growth cuts.

This manual integration test receives a frozen native predecessor, a previously
accepted growth trace and object expectations. It never accesses a running VM.
All original planners close before any crash image or recovery owner is created.
"""
from pathlib import Path
from collections import defaultdict
import base64
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import time

import fixtures as wire
import secure_fixtures as security_wire
import filename_storage as storage

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import sanitizer_environment

FILETIME_TICKS_PER_SECOND = 10000000
WINDOWS_EPOCH_SECONDS = 11644473600
NANOSECONDS_PER_TICK = 100
REFERENCE_RECORD_MASK = (1 << wire.REFERENCE_SEQUENCE_SHIFT) - 1
NATIVE_CASE_LIMIT = 32
FRAME_BYTES = wire.CLUSTER
SECTOR_BYTES = wire.SECTOR
# The existing native acceptance profile reserves at most 4096 4-KiB events,
# including event metadata, within image_fault.h's unchanged storage ceiling.
RECOVERY_TRACE_EVENT_CAPACITY = 4096
ENVIRONMENT = sanitizer_environment()


def sha(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def at(path, first, count):
    with Path(path).open('rb') as source:
        source.seek(first)
        value = source.read(count)
    assert len(value) == count
    return value


def apply(path, changes):
    with Path(path).open('r+b') as target:
        for first, value in changes:
            assert first >= 0 and first + len(value) <= path.stat().st_size
            target.seek(first)
            assert target.write(value) == len(value)


def stage_values():
    source = (ROOT / 'core/write_status.h').read_text()
    body = source.split('enum ntfs_write_execution_stage {', 1)[1].split('};', 1)[0]
    names = re.findall(r'\bNTFS_WRITE_EXECUTION_[A-Z_]+\b', body)
    assert len(names) == len(set(names)) and '=' not in body
    return {name.removeprefix('NTFS_WRITE_EXECUTION_'): index for index, name in enumerate(names)}


def metadata_class(region, initialized):
    # The region report carries explicit logical targets. The native geometry
    # and the previously accepted trace independently bind their interpretation.
    if region['attribute_type'] == wire.INDEX_ALLOC:
        return 'existing-index' if region['index_allocated'] else 'new-index'
    if region['attribute_type'] == wire.BITMAP:
        return 'mft-bitmap'
    record = region['reference'] & REFERENCE_RECORD_MASK
    if record == wire.BITMAP_RECORD:
        return 'volume-bitmap'
    assert region['attribute_type'] == wire.DATA and record == 0
    if region['mirror']:
        return 'mft-mirror'
    if region['logical'] == 0:
        return 'mft-primary'
    return 'new-file-records' if region['logical'] >= initialized else 'existing-file-records'


def cut_states(plan, initialized):
    """Freeze coverage before running any recovery; never select from verdicts."""
    stages = stage_values()
    publications = plan['publications']
    by_stage = defaultdict(list)
    by_class = defaultdict(list)
    regions = {row['physical']: row for row in plan['regions']}
    for index, row in enumerate(publications):
        assert row['bytes'] == FRAME_BYTES and row['barrier']
        by_stage[row['stage']].append(index)
        if row['stage'] == stages['METADATA_HOME']:
            by_class[metadata_class(regions[row['physical']], initialized)].append(index)
    states = {}

    def add(index, prefix, reason):
        key = (index, prefix)
        if key not in states:
            row = publications[index]
            states[key] = dict(complete=index, prefixBytes=prefix, physical=row['physical'],
                               stage=row['stage'], reasons=[], native=False)
        states[key]['reasons'].append(reason)

    for label in ('DIRTY_FIRST', 'DIRTY_SECOND', 'COMMIT_COPY', 'COMMIT_HOME', 'CLEAN_FIRST', 'CLEAN_SECOND'):
        assert len(by_stage[stages[label]]) == 1
        for prefix in (0, SECTOR_BYTES, FRAME_BYTES - SECTOR_BYTES):
            add(by_stage[stages[label]][0], prefix, label.lower())
    for label in ('PREPARE_COPY', 'PREPARE_HOME'):
        indices = by_stage[stages[label]]
        assert len(indices) > 2
        for index in (indices[0], indices[len(indices) // 2], indices[-1]):
            for prefix in (0, SECTOR_BYTES, FRAME_BYTES - SECTOR_BYTES):
                add(index, prefix, label.lower())
    for index in by_stage[stages['METADATA_HOME']]:
        for prefix in (0, SECTOR_BYTES):
            add(index, prefix, 'every-metadata-home')
    for label, indices in sorted(by_class.items()):
        add(indices[0], FRAME_BYTES - SECTOR_BYTES, label)
        for index in indices:
            states[(index, 0)]['metadataClass'] = label
            states[(index, SECTOR_BYTES)]['metadataClass'] = label

    # Native representatives cover all critical stages and every logical target
    # class. Full local per-home coverage is kept separately from this subset.
    native = set()
    for label in ('DIRTY_FIRST', 'DIRTY_SECOND', 'COMMIT_COPY', 'COMMIT_HOME', 'CLEAN_FIRST', 'CLEAN_SECOND'):
        for prefix in (0, SECTOR_BYTES):
            native.add((by_stage[stages[label]][0], prefix))
    for label in ('PREPARE_COPY', 'PREPARE_HOME'):
        indices = by_stage[stages[label]]
        for index in (indices[0], indices[-1]):
            native.add((index, SECTOR_BYTES))
    for label, indices in sorted(by_class.items()):
        for prefix in (0, SECTOR_BYTES):
            native.add((indices[0], prefix))
    assert len(native) <= NATIVE_CASE_LIMIT
    for key in sorted(states):
        if len(native) == NATIVE_CASE_LIMIT:
            break
        native.add(key)
    assert len(native) == NATIVE_CASE_LIMIT
    for key in native:
        states[key]['native'] = True
    commit = by_stage[stages['COMMIT_COPY']][0]
    result = []
    for ordinal, (key, row) in enumerate(sorted(states.items())):
        row.update(case=f'growth-cut-{ordinal:03d}', winner=row['complete'] > commit)
        result.append(row)
    return result, dict(metadataHomes=len(by_stage[stages['METADATA_HOME']]),
                        metadataClasses={name: len(indices) for name, indices in sorted(by_class.items())},
                        publications=len(publications), commitPublication=commit)


def logical_protected(value, region):
    """Compare complete metadata while separating USA and recovery-owned LSNs."""
    result = bytearray(value)
    if region['attribute_type'] == wire.INDEX_ALLOC:
        spans = [(0, len(result))]
    elif region['attribute_type'] == wire.DATA and region['reference'] & REFERENCE_RECORD_MASK == 0:
        spans = [(first, wire.RECORD) for first in range(0, len(result), wire.RECORD)]
    else:
        return bytes(result)
    for first, size in spans:
        raw = result[first:first + size]
        if raw[:4] not in (b'FILE', b'INDX'):
            continue
        common = dict(zip(security_wire.FILE_HEADER_FIELDS, wire.FILE_HEADER_LEGACY.unpack_from(raw)))
        usa_first, usa_count = common['usa_offset'], common['usa_count']
        assert usa_count == size // SECTOR_BYTES + 1
        assert usa_first + usa_count * wire.U16_BYTES <= SECTOR_BYTES - wire.U16_BYTES
        for sector in range(1, usa_count):
            tail = first + sector * SECTOR_BYTES - wire.U16_BYTES
            saved = first + usa_first + sector * wire.U16_BYTES
            result[tail:tail + wire.U16_BYTES] = result[saved:saved + wire.U16_BYTES]
        # The shared MST prefix gives LSN the same named field position in FILE
        # and INDX. USA storage is separate from the restored logical tail bytes.
        lsn_first = struct.calcsize('<4sHH')
        result[first + lsn_first:first + lsn_first + wire.U64_BYTES] = bytes(wire.U64_BYTES)
        result[first + usa_first:first + usa_first + usa_count * wire.U16_BYTES] = bytes(usa_count * wire.U16_BYTES)
    return bytes(result)


def expected_inventory(objects, prefix):
    result = {}
    for row in objects:
        if row['directory'] or not row['present'] or not row['relativePath'].startswith(prefix):
            continue
        name = row['relativePath'][len(prefix):]
        assert '\\' not in name and name not in result and row['bytes'] == 0
        result[name] = row
    return result


def verify_inventory(output, expected, parent_reference):
    actual = {}
    for line in output.decode().splitlines():
        row = json.loads(line)
        name = bytes().join(unit.to_bytes(wire.U16_BYTES, 'little') for unit in row['nameUnits']).decode('utf-16le')
        assert name not in actual
        actual[name] = row
    assert set(actual) == set(expected)
    for name, row in actual.items():
        wanted = expected[name]
        assert row['reference'] == wanted['reference'] and int(row['parentReference']) == int(parent_reference)
        assert row['links'] == 1 and row['size'] == wanted['bytes'] == 0 and row['dataHex'] == ''
        assert bytes.fromhex(row['descriptorHex']) == base64.b64decode(wanted['securityDescriptor'], validate=True)
        modified = (int(row['modifiedSeconds']) + WINDOWS_EPOCH_SECONDS) * FILETIME_TICKS_PER_SECOND
        modified += row['modifiedNanoseconds'] // NANOSECONDS_PER_TICK
        assert modified == int(wanted['lastWriteFileTime'])


def run_matrix(config, output):
    output.mkdir(parents=True, exist_ok=False)
    (output / 'test-source.py').write_bytes(Path(__file__).read_bytes())
    (output / 'input.json').write_text(json.dumps(config, indent=2) + '\n')
    commands, verdicts = [], []
    source, old_trace = Path(config['source']), Path(config['acceptedTrace'])
    assert source.is_file() and not source.is_symlink() and source.stat().st_mode & 0o777 == 0o444
    assert sha(source) == config['sourceSha256']
    tools = {name: Path(path) for name, path in config['tools'].items()}
    for name, path in tools.items():
        assert path.is_file() and not path.is_symlink()
    binaries = {name: sha(path) for name, path in tools.items()}

    def save():
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        (output / 'progress.json').write_text(json.dumps(dict(cases=verdicts, completed=len(verdicts)), indent=2) + '\n')

    def command(directory, name, argv):
        argv = list(map(str, argv))
        started = time.monotonic()
        with (directory / (name + '.stdout')).open('xb') as stdout, (directory / (name + '.stderr')).open('xb') as stderr:
            process = subprocess.run(argv, cwd=ROOT, env=ENVIRONMENT, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, timeout=600)
        commands.append(dict(directory=str(directory), name=name, argv=argv, exitCode=process.returncode,
                             seconds=time.monotonic() - started,
                             sanitizerSettings={key: ENVIRONMENT[key] for key in ('ASAN_OPTIONS', 'UBSAN_OPTIONS')}))
        save()
        assert process.returncode == 0 and (directory / (name + '.stderr')).stat().st_size == 0, (directory, name)
        return (directory / (name + '.stdout')).read_bytes()

    def clone(directory, name, original, destination):
        command(directory, name, ['/bin/cp', '-c', original, destination])
        destination.chmod(0o600)
        assert destination.stat().st_size == original.stat().st_size and destination.stat().st_nlink == 1

    try:
        plan_directory = output / 'current-plan'
        plan_directory.mkdir()
        image = plan_directory / 'candidate.ntfs'
        trace = plan_directory / 'trace'
        previous = Path(config['preparedPrefix']) if 'preparedPrefix' in config else None
        if previous is not None:
            old_config = json.loads((previous / 'input.json').read_text())
            assert {key: value for key, value in old_config.items() if key != 'tools'} == {
                key: value for key, value in config.items() if key not in ('tools', 'preparedPrefix')}
            assert all(sha(Path(old_config['tools'][name])) == binaries[name] for name in binaries)
            assert json.loads((previous / 'failure.json').read_text())['completed'] == 0
            old_plan = previous / 'current-plan'
            image = old_plan / 'candidate.ntfs'
            shutil.copytree(old_plan / 'trace', trace)
            for name in ('prepare.stdout', 'prepare.stderr', 'predecessor-inventory.stdout', 'predecessor-inventory.stderr'):
                shutil.copyfile(old_plan / name, plan_directory / name)
            assert (plan_directory / 'prepare.stderr').stat().st_size == (plan_directory / 'predecessor-inventory.stderr').stat().st_size == 0
            prepared = json.loads((plan_directory / 'prepare.stdout').read_text())
            (plan_directory / 'reused-prefix.json').write_text(json.dumps(dict(directory=str(previous),
                preparationAndInventoryReexecuted=False, sourceHashVerified=True), indent=2) + '\n')
        else:
            clone(plan_directory, 'clone', source, image)
            trace.mkdir()
            prepared = json.loads(command(plan_directory, 'prepare', [tools['writer'], 'prepare', image,
                config['operation'], config['path'], config['filetime'], trace]))
        assert prepared['result'] == 0 and not prepared['executed'] and prepared['writes'] == prepared['barriers'] == 0
        plan = json.loads((trace / 'plan.json').read_text())
        old_plan = json.loads((old_trace / 'plan.json').read_text())
        assert plan == old_plan
        for stem, count in (('publication', len(plan['publications'])), ('region-before', len(plan['regions'])),
                            ('region-after', len(plan['regions']))):
            for index in range(count):
                assert (trace / f'{stem}-{index}.bin').read_bytes() == (old_trace / f'{stem}-{index}.bin').read_bytes()
        assert sha(image) == config['sourceSha256']
        frames = [(trace / f'publication-{index}.bin').read_bytes() for index in range(len(plan['publications']))]
        for row, frame in zip(plan['publications'], frames):
            assert len(frame) == row['bytes'] == FRAME_BYTES
        stages = stage_values()
        projected_homes = {row['physical']: frames[index] for index, row in enumerate(plan['publications'])
                           if row['stage'] == stages['METADATA_HOME']}
        assert set(projected_homes) == {row['physical'] for row in plan['regions']}
        cases, coverage = cut_states(plan, config['mftInitializedBytes'])
        if 'nativeCases' in config:
            selected = {tuple(value) for value in config['nativeCases']}
            assert len(selected) == len(config['nativeCases']) and len(selected) <= NATIVE_CASE_LIMIT
            assert selected.issubset({(row['complete'], row['prefixBytes']) for row in cases})
            for row in cases:
                row['native'] = (row['complete'], row['prefixBytes']) in selected
        native_count = sum(row['native'] for row in cases)
        (output / 'coverage-plan.json').write_text(json.dumps(dict(cases=cases, coverage=coverage,
            nativeRepresentatives=native_count, selectionDependsOnVerdicts=False,
            sectorSize=SECTOR_BYTES, frameBytes=FRAME_BYTES, hardwarePowerCuts=False), indent=2) + '\n')
        expected = {True: expected_inventory(config['winnerObjects'], config['inventoryPrefix']),
                    False: expected_inventory(config['loserObjects'], config['inventoryPrefix'])}
        if previous is not None:
            predecessor_inventory = (plan_directory / 'predecessor-inventory.stdout').read_bytes()
        else:
            predecessor_inventory = command(plan_directory, 'predecessor-inventory', [tools['inventory'], source, config['parentReference']])
        verify_inventory(predecessor_inventory, expected[False], config['parentReference'])
        for case in cases:
            directory = output / case['case']
            directory.mkdir()
            crash = directory / 'crash.ntfs'
            clone(directory, 'clone-crash', source, crash)
            complete, prefix = case['complete'], case['prefixBytes']
            changes = [(row['physical'], frames[index]) for index, row in enumerate(plan['publications'][:complete])]
            if prefix:
                changes.append((plan['publications'][complete]['physical'], frames[complete][:prefix]))
            apply(crash, changes)
            crash.chmod(0o444)
            recovered = directory / 'recovered.ntfs'
            clone(directory, 'clone-recovery', crash, recovered)
            recovery_trace = directory / 'recovery-trace'
            recovery_trace.mkdir()
            recovery = json.loads(command(directory, 'fresh-recover', [tools['writer'], 'recover', recovered,
                recovery_trace, '--fault', 0, 0, 0, RECOVERY_TRACE_EVENT_CAPACITY]))
            assert recovery['result'] == 0 and recovery['completed'] and not recovery['poisoned']
            recovery_plan = json.loads((recovery_trace / 'plan.json').read_text())
            events = json.loads((recovery_trace / 'events.json').read_text())
            assert not events['triggered'] and not events['native_failure']
            transfers = [(index, row) for index, row in enumerate(events['events']) if not row['barrier']]
            assert len(transfers) == len(recovery_plan['publications']) == recovery['writes']
            final = {}
            for ordinal, (index, row) in enumerate(transfers):
                wanted = recovery_plan['publications'][ordinal]
                frame = (recovery_trace / f'publication-{ordinal}.bin').read_bytes()
                assert row['physical'] == wanted['physical'] and row['bytes'] == row['completed'] == FRAME_BYTES
                assert row['result'] == row['native_result'] == 0 and row['native_attempted'] and not row['injected']
                assert frame == (recovery_trace / f'event-{index}.bin').read_bytes()
                final[row['physical']] = frame
            for first, value in final.items():
                assert at(recovered, first, len(value)) == value
            for index, region in enumerate(plan['regions']):
                if not case['winner'] and metadata_class(region, config['mftInitializedBytes']) in ('new-index', 'new-file-records'):
                    continue  # Reclaimed unowned storage has no predecessor metadata contract.
                wanted = projected_homes[region['physical']] if case['winner'] else at(source, region['physical'], region['bytes'])
                actual = at(recovered, region['physical'], region['bytes'])
                assert logical_protected(actual, region) == logical_protected(wanted, region), (case['case'], index)
            validation = json.loads(command(directory, 'complete-validation', [tools['validate'], recovered]))
            assert validation['complete'] and validation['result'] == 'success'
            verify_inventory(command(directory, 'namespace-data-identity-security', [tools['inventory'], recovered,
                config['parentReference']]), expected[case['winner']], config['parentReference'])
            reopen_trace = directory / 'reopen-trace'
            reopen_trace.mkdir()
            reopen = json.loads(command(directory, 'fresh-idempotent-recover', [tools['writer'], 'recover', recovered,
                reopen_trace, '--fault', 0, 0, 0, RECOVERY_TRACE_EVENT_CAPACITY]))
            assert reopen['result'] == 0 and reopen['completed'] and reopen['writes'] == 0 and reopen['barriers'] == 1
            recovered.chmod(0o444)
            verdicts.append(dict(case, recovery=recovery, finalValidation=True, completeNamespaceDataIdentitySecurity=True,
                idempotentReopen=True, crash=str(crash), recovered=str(recovered), recoveryTrace=str(recovery_trace)))
            save()
            if len(verdicts) % 8 == 0:
                print('PASS native-source growth recovery states', len(verdicts), '/', len(cases), flush=True)
        assert sha(source) == config['sourceSha256'] and all(sha(tools[name]) == value for name, value in binaries.items())
        result = dict(success=True, complete=True, states=len(cases), cases=verdicts, coverage=coverage,
                      sourceUnchanged=True, currentPlanExactlyMatchesAcceptedNativeGrowth=True,
                      nativeRepresentatives=native_count, nativeWindowsPending=True, fatalASanUBSan=True,
                      actualFreshCRecovery=True, currentCoreSemanticsChanged=False, nativeCaseReexecutions=0,
                      vmCommands=0, automaticRetry=False, hardwarePowerCuts=False, tools=binaries)
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print('PASS complete native-source growth fault matrix', len(cases), 'states; native representatives pending', flush=True)
        return result
    except BaseException as error:
        (output / 'failure.json').write_text(json.dumps(dict(success=False, error=repr(error), completed=len(verdicts),
                                                           automaticRetry=False, vmCommands=0), indent=2) + '\n')
        raise


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    run_matrix(json.loads(arguments.input.read_text()), arguments.output)
