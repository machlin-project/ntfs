#!/usr/bin/env python3
"""Compare actual image failure transfers with independently authored full bytes."""
from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile

import fixtures as f
import filename_storage as storage
import logfile_fixtures as w
import validation_fixtures as v
import write_journal_fixtures as oracle
from write_metadata_fixtures import FILE, STANDARD

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import sanitizer_environment

NTFS_OK, NTFS_IO = 0, 4
REPORT_BYTES = 16 * 1024
TOOL_SECONDS = 30


def invoke(tool, arguments, status):
    done = subprocess.run([str(tool), *map(str, arguments)], cwd=ROOT,
                          env=sanitizer_environment(), stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=TOOL_SECONDS)
    assert done.returncode == status, (arguments, done.returncode, done.stderr)
    assert len(done.stdout) <= REPORT_BYTES and done.stderr == b'', done.stderr
    return json.loads(done.stdout)


def expected_transfers(directory):
    source = (directory / 'source.img').read_bytes()
    manifest = json.loads((directory / 'manifest.json').read_text())
    record_first = f.MFT_LCN * f.CLUSTER + v.FRAGMENTED_RECORD * f.RECORD
    log_record_first = f.MFT_LCN * f.CLUSTER + v.LOGFILE_RECORD * f.RECORD
    log_attrs = storage.record_parts(source[log_record_first:log_record_first + f.RECORD])[1]
    _, log_runs = storage.mapping(next(attr for attr in log_attrs
                                      if storage.attr_header(attr)['type'] == f.DATA))
    assert len(log_runs) == 1
    log_first = log_runs[0][1] * f.CLUSTER
    transfers = []
    image = bytearray(source)

    def publish(location, desired, layout=None, barrier=True):
        before = bytes(image[location:location + len(desired)])
        value = oracle.guarded_publication(before, desired, layout) if layout else desired
        image[location:location + len(value)] = value
        transfers.append((location, value))
        if barrier:
            transfers.append(None)

    for slot in range(w.RESTART_PAGES):
        publish(log_first + slot * w.PAGE_BYTES,
                (directory / f'dirty-{slot}.expected').read_bytes(), w.RESTART_HEADER)
    publish(log_first + w.RESTART_PAGES * w.PAGE_BYTES,
            (directory / 'prepare-copy.expected').read_bytes(), w.PAGE)
    publish(log_first + manifest['prepare_offset'],
            (directory / 'prepare.expected').read_bytes(), w.PAGE)
    data_rows = [tuple(map(int, row.split()))
                 for row in (directory / 'execute-data.rows').read_text().splitlines()]
    for index, (location, length) in enumerate(data_rows):
        value = (directory / f'execute-data-{index}.expected').read_bytes()
        assert len(value) == length
        publish(location, value, barrier=False)
    transfers.append(None)
    publish(log_first + (w.RESTART_PAGES + 1) * w.PAGE_BYTES,
            (directory / 'commit-copy.expected').read_bytes(), w.PAGE)
    commit_copy_index = len(transfers) - 2
    publish(log_first + manifest['commit_offset'],
            (directory / 'commit.expected').read_bytes(), w.PAGE)
    file_home = record_first // f.CLUSTER * f.CLUSTER
    file_relative = record_first - file_home
    file_cluster = bytearray(image[file_home:file_home + f.CLUSTER])
    protected = (directory / 'protected.expected').read_bytes()
    guarded = oracle.guarded_publication(source[record_first:record_first + f.RECORD],
                                        protected, FILE)
    file_cluster[file_relative:file_relative + f.RECORD] = guarded
    publish(file_home, bytes(file_cluster))
    for slot in range(w.RESTART_PAGES):
        publish(log_first + slot * w.PAGE_BYTES,
                (directory / f'retained-{slot}.expected').read_bytes(), w.RESTART_HEADER)
    assert bytes(image) == (directory / 'execute-final.img').read_bytes()
    return source, manifest, transfers, data_rows, record_first, commit_copy_index


def check_trace(directory, transfers, write=0, prefix=0, barrier=0):
    trace = json.loads((directory / 'events.json').read_text())
    assert not trace['native_failure']
    assert trace['triggered'] == bool(write or barrier)
    writes = barriers = 0
    for index, transfer in enumerate(transfers):
        event = trace['events'][index]
        assert event['barrier'] == (transfer is None)
        if transfer is None:
            barriers += 1
            injected = barriers == barrier
            assert event['physical'] == event['bytes'] == event['completed'] == 0
            assert event['native_attempted']
        else:
            writes += 1
            injected = writes == write
            physical, value = transfer
            assert (event['physical'], event['bytes']) == (physical, len(value))
            assert (directory / f'event-{index}.bin').read_bytes() == value
            completed = prefix if injected else len(value)
            assert event['completed'] == completed
            assert event['native_attempted'] == bool(completed)
        assert event['injected'] == injected
        assert event['native_result'] == NTFS_OK
        assert event['result'] == (NTFS_IO if injected else NTFS_OK)
        if injected:
            assert len(trace['events']) == index + 1, 'Callbacks continued after uncertainty.'
            break
    else:
        assert len(trace['events']) == len(transfers)
    assert (trace['writes'], trace['barriers']) == (writes, barriers)
    return len(trace['events']) - 1


def metadata_times(image, first):
    _, attrs = storage.record_parts(image[first:first + f.RECORD])
    attr = next(attr for attr in attrs if storage.attr_header(attr)['type'] == f.SI)
    resident = dict(zip(storage.RESIDENT_FIELDS,
                        f.RESIDENT_HEADER.unpack_from(attr, f.ATTR_HEADER.size)))
    fields = oracle.fields(STANDARD, attr, resident['offset'])
    return fields['modified'], fields['changed'], fields['attributes']


def main():
    tool, validator, directory = (Path(argument).resolve() for argument in sys.argv[1:])
    source, manifest, transfers, data_rows, first, commit_copy = expected_transfers(directory)
    old_times = metadata_times(source, first)
    final_times = metadata_times((directory / 'execute-final.img').read_bytes(), first)
    cases = [('complete', 0, 0, 0)]
    writes = barriers = 0
    for transfer in transfers:
        if transfer is None:
            barriers += 1
            cases.append((f'barrier-{barriers}', 0, 0, barriers))
        else:
            writes += 1
            for prefix in range(0, len(transfer[1]) + f.SECTOR, f.SECTOR):
                cases.append((f'write-{writes}-prefix-{prefix}', writes, prefix, 0))
    with tempfile.TemporaryDirectory(prefix='machlin-ntfs-image-fault-') as temporary:
        root = Path(temporary)
        for label, write, prefix, barrier in cases:
            case = root / label
            case.mkdir()
            image = case / 'working.img'
            shutil.copyfile(directory / 'source.img', image)
            interrupted = bool(write or barrier)
            report = invoke(tool, ['--interrupt-image', image, f"{manifest['reference']:x}",
                                  oracle.EXECUTE_OFFSET, directory / 'execute-payload.input',
                                  manifest['filetime'], write, prefix, barrier, case],
                            int(interrupted))
            assert report['result'] == (NTFS_IO if interrupted else NTFS_OK)
            assert report['initially_quiet'] and report['initial_persistence']
            assert report['poisoned'] == interrupted
            assert report['completed'] != interrupted
            assert report['completed_bytes'] == (0 if interrupted else oracle.EXECUTE_BYTES)
            last = check_trace(case, transfers, write, prefix, barrier)
            expected = bytearray(source)
            for index, transfer in enumerate(transfers[:last + 1]):
                if transfer is not None:
                    physical, value = transfer
                    if index == last and write:
                        value = value[:prefix]
                    expected[physical:physical + len(value)] = value
            assert image.read_bytes() == expected, label
            recovered = invoke(tool, ['--recover', image], 0)
            assert recovered['result'] == NTFS_OK and recovered['completed']
            settled = image.read_bytes()
            # DATA is not rolled back. Metadata is redo/undo according to the
            # complete commit copy, including an uncertain fully written copy.
            winner = last > commit_copy or (last == commit_copy and prefix == w.PAGE_BYTES)
            assert metadata_times(settled, first) == (final_times if winner else old_times), label
            for physical, length in data_rows:
                assert settled[physical:physical + length] == expected[physical:physical + length]
            validation = invoke(validator, [image], 0)
            assert validation['result'] == 'success' and validation['complete'], validation
            repeated = case / 'repeated'
            repeated.mkdir()
            reopen = invoke(tool, ['--interrupt-recover', image, 0, 0, 0, repeated], 0)
            assert reopen['completed'] and reopen['writes'] == 0 and reopen['barriers'] == 1
            quiet = json.loads((repeated / 'events.json').read_text())
            assert not quiet['triggered'] and not quiet['native_failure']
            assert quiet['writes'] == 0 and quiet['barriers'] == 1
            assert len(quiet['events']) == 1 and quiet['events'][0]['barrier']
            assert image.read_bytes() == settled, 'Idempotent admission changed image bytes.'
            shutil.rmtree(case)
    assert (directory / 'source.img').read_bytes() == source
    print(f'PASS: {len(cases)} actual image profiles, full transfer/image oracles and repeated recovery')


if __name__ == '__main__':
    main()
