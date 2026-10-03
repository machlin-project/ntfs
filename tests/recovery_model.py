"""Explore abstract transaction failures against independently authored NTFS bytes."""
from dataclasses import replace
from pathlib import Path
import argparse
import hashlib
import json
import sys
import tempfile

import fixtures as f
import recovery_fixtures as native
import transaction_model as m

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from bounded_tool import bounded_read, run_tool
from validation_cli import invoke as validate_image

MAX_EXPLORED_STATES = 100000
MAX_NATIVE_REPORT_BYTES = 16 * 1024
MAX_INSTRUMENTED_TOOL_BYTES = 32 * 1024 * 1024
FAULT_PREFIXES = (0, 1, f.SECTOR // 2, f.SECTOR - 1, f.SECTOR)


def refuse(call, exception=m.Refused):
    try:
        call()
    except exception:
        return
    raise AssertionError('Forbidden transition was admitted')


def cells_from_image(image, ranges):
    return {('home', address + offset): image[address + offset:address + offset + f.SECTOR]
            for address, length in ranges for offset in range(0, length, f.SECTOR)}


def prepared(endpoints):
    updates = tuple(m.Page(m.ObjectKind[kind], address,
                           endpoints.before[address:address + length],
                           endpoints.after[address:address + length])
                    for kind, address, length in endpoints.metadata)
    initialized = tuple(m.Page(m.ObjectKind.DATA, address,
                               endpoints.before[address:address + length],
                               endpoints.after[address:address + length])
                        for address, length in endpoints.initialized)
    ranges = (*[(address, length) for _, address, length in endpoints.metadata],
              *endpoints.initialized)
    return m.Plan(updates, initialized), cells_from_image(endpoints.before, ranges)


def endpoint(cells, before, after, initialized, *, acknowledged=False):
    # Independent byte oracle: complete native metadata must equal one authored
    # endpoint. Unreferenced initialized/free data need not revert on an abort.
    if all(cells.get(key) == value for key, value in after.items()):
        assert all(cells.get(key) == value for key, value in initialized.items()), 'uninitialized publication'
        return 'after'
    assert not acknowledged, 'acknowledged commit was lost'
    assert all(cells.get(key) == value for key, value in before.items()), 'mixed metadata endpoint'
    return 'before'


def persistence_masks(snapshot, exhaustive_cells):
    indices = [index for index, (key, value) in enumerate(snapshot.pending.items())
               if value != snapshot.durable.get(key)]
    count = len(indices)
    home_control = any(key[0] == 'home' or isinstance(value, m.Fragment) and
                       value.record.kind != m.RecordKind.UPDATE
                       for key, value in snapshot.pending.items())
    # Persisting a cell already equal to stable storage produces the same crash
    # state. Enumerate effective changes while retaining original cache bit IDs.
    def original_mask(value):
        return sum(1 << index for bit, index in enumerate(indices) if value & (1 << bit))
    if count <= exhaustive_cells and (home_control or count == 0):
        return (original_mask(value) for value in range(1 << count)), 'powerset'
    # Large log bodies have no published home changes. Exercise every individual
    # fragment and every prefix/suffix instead of claiming their full powerset.
    full = (1 << count) - 1
    masks = {0, full}
    for index in range(count):
        masks.add(1 << index)
        masks.add(full ^ (1 << index))
        masks.add((1 << index) - 1)
        masks.add(full ^ ((1 << index) - 1))
    return [original_mask(value) for value in sorted(masks)], 'fragment-prefix-suffix'


class Check:
    def __init__(self, endpoints):
        ranges = [(address, length) for _, address, length in endpoints.metadata]
        self.before = cells_from_image(endpoints.before, ranges)
        self.after = cells_from_image(endpoints.after, ranges)
        self.data = cells_from_image(endpoints.after, endpoints.initialized)
        self.states = 0

    def run(self, cells, acknowledged=False):
        self.states += 1
        assert self.states <= MAX_EXPLORED_STATES, 'model exploration ceiling exceeded'
        device = m.Device(f.SECTOR, cells)
        m.recover(device)
        value = endpoint(device.durable, self.before, self.after, self.data,
                         acknowledged=acknowledged)
        assert not device.pending and not device.requires_recovery
        # Replay after successful retirement must be idempotent.
        original = dict(device.durable)
        m.recover(device)
        assert device.durable == original
        return value, device.durable


def protocol(plan, initial, commit, steal, *, fault=None, trace=True):
    device = m.Device(f.SECTOR, initial, fault=fault, trace=trace)
    owner = m.Owner(device)
    transaction = owner.prepare(plan)
    try:
        transaction.run(commit=commit, steal=steal)
    except m.UncertainIO:
        assert owner.poisoned
        operations = device.operations
        refuse(owner.read_view)
        refuse(lambda: owner.prepare(plan))
        refuse(transaction.run)
        assert device.operations == operations
    else:
        assert owner.live_bytes == 0 and not owner.reservations and owner.active is None
    finally:
        owner.close()
    assert owner.live_bytes == 0 and not owner.reservations and not device.claimed
    return device


def ownership(plan, initial, check):
    checks = 0
    private = sum(len(page.before) + len(page.after) for page in (*plan.initialized, *plan.updates))
    records = tuple(m.Record(1, m.RecordKind.UPDATE, index, page)
                    for index, page in enumerate(sorted(plan.updates, key=lambda p: (p.kind, p.address))))
    ids = tuple(range(len(records)))
    required_log = sum(record.parts(f.SECTOR) for record in (*records,
        m.Record(1, m.RecordKind.COMMIT, update_ids=ids),
        m.Record(1, m.RecordKind.CHECKPOINT, update_ids=ids)))
    for limits in (m.Limits(private_bytes=private - 1),
                   m.Limits(log_fragments=required_log - 1),
                   m.Limits(pages=len(plan.updates) + len(plan.initialized) - 1)):
        device = m.Device(f.SECTOR, initial)
        owner = m.Owner(device, limits)
        refuse(lambda: owner.prepare(plan))
        assert owner.allocations == 0 and owner.live_bytes == 0 and not owner.reservations
        assert device.operations == 0 and device.durable == initial and not device.pending
        owner.close()
        checks += 1
    for failed in range(1, len(plan.updates) + len(plan.initialized) + 1):
        device = m.Device(f.SECTOR, initial)
        owner = m.Owner(device, fail_allocation=failed)
        refuse(lambda: owner.prepare(plan))
        assert owner.allocations == failed and owner.live_bytes == 0 and not owner.reservations
        assert not owner.poisoned and device.operations == 0
        transaction = owner.prepare(plan)
        assert list(owner.reservations) == sorted(owner.reservations)
        refuse(lambda: m.Owner(device))
        refuse(lambda: owner.prepare(plan))
        refuse(lambda: m.recover(device))
        assert device.operations == 0
        transaction.run()
        assert owner.read_view().items() >= check.after.items()
        check.run(device.durable, True)
        owner.close()
        checks += 1
    device = m.Device(f.SECTOR, initial)
    owner = m.Owner(device, m.Limits(private, required_log, len(plan.updates) + len(plan.initialized)))
    malformed = (m.Plan((plan.updates[0], plan.updates[0])),
                 replace(plan, updates=(replace(plan.updates[0], address=plan.updates[0].address + 1),)),
                 replace(plan, updates=(replace(plan.updates[0], before=bytes(len(plan.updates[0].before))),)),
                 replace(plan, updates=(replace(plan.updates[0], after=bytearray(plan.updates[0].after)),)),
                 replace(plan, initialized=(replace(plan.initialized[0], kind=m.ObjectKind.INDEX),)),
                 replace(plan, updates=list(plan.updates)),
                 replace(plan, initialized=list(plan.initialized)),
                 replace(plan, updates=(object(),)),
                 replace(plan, updates=(replace(plan.updates[0], address=float(plan.updates[0].address)),)))
    for bad in malformed:
        refuse(lambda bad=bad: owner.prepare(bad))
        assert device.operations == 0 and owner.allocations == 0
        checks += 1
    refuse(lambda: owner.prepare(plan, transaction=True))
    assert device.operations == 0 and owner.allocations == 0
    checks += 1
    owner.prepare(plan).run()
    assert owner.peak_bytes == private and owner.live_bytes == 0
    owner.close()
    refuse(owner.read_view)
    checks += 1
    record = records[0]
    dirty = m.Device(f.SECTOR, {**initial, **m.record_cells(record, f.SECTOR)})
    refuse(lambda: m.Owner(dirty))
    assert not dirty.claimed and dirty.operations == 0
    checks += 1
    dirty = m.Device(f.SECTOR, initial)
    key, data = next(iter(initial.items()))
    dirty.write(key, data, 'unqualified-volatile-write')
    operations = dirty.operations
    refuse(lambda: m.Owner(dirty))
    refuse(lambda: m.recover(dirty))
    assert not dirty.claimed and dirty.operations == operations
    checks += 1
    # Closing a fully reserved but unstarted transaction needs no device I/O.
    device = m.Device(f.SECTOR, initial)
    owner = m.Owner(device)
    abandoned = owner.prepare(plan)
    owner.close()
    refuse(abandoned.run)
    assert device.operations == 0 and not device.claimed and not owner.reservations
    checks += 1
    # A live owner can reuse its credits after complete retirement. An abort of
    # a following transaction preserves the preceding committed native endpoint.
    owner = m.Owner(device)
    owner.prepare(plan).run()
    inverse = m.Plan(tuple(replace(page, before=page.after, after=page.before)
                           for page in plan.updates))
    reverse = owner.prepare(inverse, transaction=2)
    assert not device.acknowledged and owner.read_view().items() >= check.after.items()
    reverse.run(commit=False, steal=True)
    assert not device.acknowledged and owner.read_view().items() >= check.after.items()
    check.run(device.durable, True)
    owner.prepare(inverse, transaction=3).run()
    assert device.acknowledged and owner.read_view().items() >= check.before.items()
    value, _ = check.run(device.durable)
    assert value == 'before' and owner.live_bytes == 0 and not owner.reservations
    owner.close()
    checks += 1
    return checks


def history_negatives(plan, initial):
    device = protocol(plan, initial, True, False)
    point = next(s for s in device.trace if s.label == 'commit-durable')
    cells = dict(point.durable)
    records = m.qualified_records(m.Device(f.SECTOR, cells))
    update = next(record for record in records.values() if record.kind == m.RecordKind.UPDATE)
    for key in m.record_cells(update, f.SECTOR):
        cells.pop(key)
    failed = m.Device(f.SECTOR, cells)
    refuse(lambda: m.recover(failed))
    assert failed.operations == 0 and failed.durable == cells
    # A second complete transaction or malformed control membership must refuse
    # before any recovery write, even beside valid first-transaction updates.
    bad_records = (m.Record(2, m.RecordKind.COMMIT, update_ids=()),
                   m.Record(1, m.RecordKind.COMMIT, update_ids=(0, 0)),
                   m.Record(1, m.RecordKind.COMMIT, update_ids=(0, len(plan.updates))),
                   m.Record(1, m.RecordKind.UPDATE, len(plan.updates), plan.updates[0]),
                   m.Record(True, m.RecordKind.COMMIT),
                   m.Record(1, 'unknown'),
                   m.Record(1, m.RecordKind.UPDATE, page=replace(plan.updates[0],
                       address=float(plan.updates[0].address))),
                   m.Record(1, m.RecordKind.UPDATE, page=replace(plan.updates[0],
                       after=bytearray(plan.updates[0].after))),
                   m.Record(1, m.RecordKind.COMMIT, update_ids=(False,)))
    for record in bad_records:
        cells = dict(point.durable)
        cells.update(m.record_cells(record, f.SECTOR))
        failed = m.Device(f.SECTOR, cells)
        refuse(lambda: m.recover(failed))
        assert failed.operations == 0 and failed.durable == cells
    malformed = (m.Fragment(update, update.parts(f.SECTOR)), m.Fragment(update, True),
                 m.Fragment(update, 0, intact=1), m.Fragment(None, 0))
    for fragment in malformed:
        cells = dict(point.durable)
        key = ('log', *update.identity, fragment.part)
        cells[key] = fragment
        failed = m.Device(f.SECTOR, cells)
        refuse(lambda: m.recover(failed))
        assert failed.operations == 0 and failed.durable == cells
    return 1 + len(bad_records) + len(malformed)


def native_check(directory, label, cells, expected, endpoints, reader, validator):
    image = bytearray(endpoints.before)
    for key, value in cells.items():
        if key[0] == 'home':
            address = key[1]
            image[address:address + len(value)] = value
    path = directory / (label + '.img')
    path.write_bytes(image)
    original = hashlib.sha256(image).hexdigest()
    report = json.loads(run_tool([str(validator), str(path)], output_limit=MAX_NATIVE_REPORT_BYTES))
    path.with_suffix('.json').write_text(json.dumps(report, indent=2) + '\n')
    assert report['complete'] and report['result'] == 'success', (label, report)
    name, data = ((native.NEW_NAME, native.NEW_DATA) if expected == 'after'
                  else (native.OLD_NAME, native.OLD_DATA))
    content = run_tool([str(reader), str(path), 'cat', '/' + name], output_limit=len(data))
    assert content == data
    assert hashlib.sha256(path.read_bytes()).hexdigest() == original
    return {'image': str(path), 'sha256': original, 'endpoint': expected,
            'complete_metadata_diagnostic': True, 'original_content': True}


def explore(directory, reader, validator, report):
    endpoints = native.author()
    plan, initial = prepared(endpoints)
    check = Check(endpoints)
    report['input_sha256'] = {name: hashlib.sha256(data).hexdigest()
                             for name, data in (('before', endpoints.before), ('after', endpoints.after))}
    report['private_bytes'] = sum(len(p.before) + len(p.after) for p in (*plan.updates, *plan.initialized))
    report['ownership_contracts'] = ownership(plan, initial, check)
    report['history_refusals'] = history_negatives(plan, initial)
    report['native_checks'] = [native_check(directory, 'authored-before', initial, 'before',
                                          endpoints, reader, validator)]
    all_after = {**initial, **check.after, **check.data}
    report['native_checks'].append(native_check(directory, 'authored-after', all_after, 'after',
                                                endpoints, reader, validator))
    metadata_sectors = len(check.before)
    membership = tuple(range(len(plan.updates)))
    control_cells = max(m.Record(1, kind, update_ids=membership).parts(f.SECTOR)
                        for kind in (m.RecordKind.COMMIT, m.RecordKind.CHECKPOINT))
    exhaustive = metadata_sectors + control_cells
    retained = {}
    report['profiles'] = []
    for commit, steal in ((True, False), (True, True), (False, True)):
        name = ('commit' if commit else 'abort') + ('-steal' if steal else '-deferred')
        device = protocol(plan, initial, commit, steal)
        endpoint(device.durable, check.before, check.after, check.data, acknowledged=commit)
        profile = {'name': name, 'boundaries': len(device.trace), 'operations': device.operations,
                   'powerset_states': 0, 'fragment_prefix_suffix_states': 0, 'failed_io_states': 0}
        report['profiles'].append(profile)
        for snapshot in device.trace:
            masks, scope = persistence_masks(snapshot, exhaustive)
            for mask in masks:
                value, recovered = check.run(m.crash(snapshot, mask), snapshot.acknowledged)
                profile[('powerset_states' if scope == 'powerset' else
                         'fragment_prefix_suffix_states')] += 1
                # Keep one actual state per phase/endpoint for native byte checks.
                retained.setdefault((name, snapshot.label, value), recovered)
        for operation in range(1, device.operations + 1):
            for prefix in FAULT_PREFIXES:
                failed = protocol(plan, initial, commit, steal,
                                  fault=m.Fault(operation, prefix), trace=False)
                assert failed.requires_recovery
                refuse(lambda: m.Owner(failed))
                snapshot = m.Snapshot('failed', failed.durable, failed.pending, failed.acknowledged)
                # No/all outstanding cells and every individual home cell cover
                # uncertain partial/full writes plus reorder across dirty metadata.
                masks = {0, (1 << len(snapshot.pending)) - 1}
                masks.update(1 << index for index, key in enumerate(snapshot.pending)
                             if key[0] == 'home')
                for mask in masks:
                    check.run(m.crash(snapshot, mask), snapshot.acknowledged)
                    profile['failed_io_states'] += 1
        report['states'] = check.states

    # Interrupt recovery itself, including retirement of an already durable
    # checkpoint. A subsequent successful replay must reach the same endpoint.
    report['recovery_interruption_states'] = 0
    for snapshot in (next(s for s in protocol(plan, initial, True, False).trace if s.label == 'publish'),
                     next(s for s in protocol(plan, initial, False, True).trace if s.label == 'uncommitted-home'),
                     next(s for s in protocol(plan, initial, True, False).trace if s.label == 'trim')):
        cells = m.crash(snapshot, (1 << len(snapshot.pending)) - 1)
        successful = m.Device(f.SECTOR, cells, trace=True)
        m.recover(successful)
        expected = endpoint(successful.durable, check.before, check.after, check.data,
                            acknowledged=snapshot.acknowledged)
        for operation in range(1, successful.operations + 1):
            for prefix in FAULT_PREFIXES:
                failed = m.Device(f.SECTOR, cells, fault=m.Fault(operation, prefix))
                refuse(lambda: m.recover(failed), m.UncertainIO)
                point = m.Snapshot('recovery-failed', failed.durable, failed.pending,
                                   snapshot.acknowledged)
                for mask in {0, (1 << len(point.pending)) - 1}:
                    value, _ = check.run(m.crash(point, mask), snapshot.acknowledged)
                    assert value == expected
                    report['recovery_interruption_states'] += 1

    # Negative protocol witnesses show the oracle detects broken ordering.
    report['unsafe_witnesses'] = []
    unsafe = dict(initial)
    first_sector = next(iter(check.after))
    unsafe[first_sector] = check.after[first_sector]
    recovered = m.Device(f.SECTOR, unsafe)
    m.recover(recovered)
    refuse(lambda: endpoint(recovered.durable, check.before, check.after, check.data), AssertionError)
    report['unsafe_witnesses'].append('home-before-durable-log')
    refuse(lambda: endpoint(initial, check.before, check.after, check.data, acknowledged=True), AssertionError)
    report['unsafe_witnesses'].append('acknowledge-without-persistence-barrier')
    uninitialized = {**initial, **check.after}
    refuse(lambda: endpoint(uninitialized, check.before, check.after, check.data, acknowledged=True), AssertionError)
    report['unsafe_witnesses'].append('publish-before-data-initialization')
    marker = m.Record(1, m.RecordKind.CHECKPOINT, update_ids=tuple(range(len(plan.updates))))
    prematurely_retired = {**unsafe, **m.record_cells(marker, f.SECTOR)}
    recovered = m.Device(f.SECTOR, prematurely_retired)
    m.recover(recovered)
    refuse(lambda: endpoint(recovered.durable, check.before, check.after, check.data), AssertionError)
    report['unsafe_witnesses'].append('checkpoint-before-durable-home')
    unsafe_image = bytearray(endpoints.before)
    for key, value in unsafe.items():
        unsafe_image[key[1]:key[1] + len(value)] = value
    path = directory / 'unsafe-home-before-log.img'
    path.write_bytes(unsafe_image)
    verdict = validate_image(validator, [path], 1)
    assert not verdict['complete']
    report['unsafe_native_diagnostic'] = verdict['result']

    # Native execution is representative, while every explored state has the
    # independent complete metadata/data oracle above. Retain one per profile,
    # phase and endpoint, so earlier failures remain inspectable.
    for index, ((profile, phase, value), cells) in enumerate(retained.items()):
        report['native_checks'].append(native_check(directory, f'{index:03}-{profile}-{phase}-{value}',
                                                    cells, value, endpoints, reader, validator))
    report['states'] = check.states
    report['maximum_exhaustive_pending_cells'] = exhaustive
    report['fault_prefix_bytes'] = list(FAULT_PREFIXES)
    report['status'] = 'pass'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reader', type=Path)
    parser.add_argument('validator', type=Path)
    parser.add_argument('--output', type=Path, help='New retained artifact directory')
    args = parser.parse_args()
    report = {'status': 'running', 'scope': 'serialized in-memory transaction/durability model',
              'native_recovery_qualified': False, 'writes_enabled': False,
              'crash_persistence': 'all subsets for bounded home/control pending sets; '
                                   'individual fragments and prefixes/suffixes for larger log bodies'}
    temporary = tempfile.TemporaryDirectory(prefix='ntfs-recovery-model-') if args.output is None else None
    directory = Path(temporary.name) if temporary is not None else args.output.resolve()
    if temporary is None:
        directory.mkdir(parents=True, exist_ok=False)
    try:
        tools = {'reader': args.reader.resolve(strict=True),
                 'validator': args.validator.resolve(strict=True)}
        report['tools'] = {name: {'path': str(path), 'sha256': hashlib.sha256(
            bounded_read(path, MAX_INSTRUMENTED_TOOL_BYTES)).hexdigest()}
            for name, path in tools.items()}
        explore(directory, tools['reader'], tools['validator'], report)
        assert all(hashlib.sha256(bounded_read(path, MAX_INSTRUMENTED_TOOL_BYTES)).hexdigest() ==
                   report['tools'][name]['sha256'] for name, path in tools.items())
    except BaseException as error:
        report['status'], report['error'] = 'failed', f'{type(error).__name__}: {error}'
        raise
    finally:
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        if temporary is not None:
            temporary.cleanup()
    print(f'PASS: {report["states"]} crash/fault states, {len(report["native_checks"])} '
          f'independent native-byte endpoints, {len(report["unsafe_witnesses"])} unsafe-order witnesses; '
          'abstract model only, native recovery unqualified')


if __name__ == '__main__':
    main()
