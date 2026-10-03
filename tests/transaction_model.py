"""Bounded executable write-ownership model, operating only on in-memory cells.

Log fragments carry typed immutable observations, not serialized journal bytes.
Their intact/torn status models a future qualified integrity decoder. This module
does not implement an NTFS log format, native replay, a device writer or FSKit API.
"""
from dataclasses import dataclass
from enum import Enum, IntEnum

WORD_BYTES = 8
BYTE_BITS = 8
IDENTITY_WORDS = 3
MAX_IDENTIFIER = (1 << (WORD_BYTES * BYTE_BITS)) - 1
MAX_PRIVATE_BYTES = 4 * 1024 * 1024
MAX_LOG_FRAGMENTS = 4096
MAX_PAGES = 256


class Refused(Exception):
    """Admission or history qualification failed before unsafe publication."""


class UncertainIO(Exception):
    """An attempted write/barrier may have changed persistent storage."""


class ObjectKind(IntEnum):
    # Reservation order is independent of physical placement.
    DATA = 0
    MFT = 1
    BITMAP = 2
    INDEX = 3
    SECURE = 4


class RecordKind(Enum):
    UPDATE = 'update'
    COMMIT = 'commit'
    CHECKPOINT = 'checkpoint'


@dataclass(frozen=True)
class Page:
    kind: ObjectKind
    address: int
    before: bytes
    after: bytes

    def cells(self, sector_bytes, after):
        data = self.after if after else self.before
        return {('home', self.address + offset): data[offset:offset + sector_bytes]
                for offset in range(0, len(data), sector_bytes)}


@dataclass(frozen=True)
class Plan:
    updates: tuple[Page, ...]
    initialized: tuple[Page, ...] = ()


@dataclass(frozen=True)
class Record:
    transaction: int
    kind: RecordKind
    ordinal: int = 0
    page: Page | None = None
    update_ids: tuple[int, ...] = ()

    def parts(self, sector_bytes):
        # Charge typed identities and complete snapshots in abstract fragments.
        # These sizes define model credits, not an NTFS record layout.
        count = (IDENTITY_WORDS + len(self.update_ids)) * WORD_BYTES
        if self.page is not None:
            count += WORD_BYTES + len(self.page.before) + len(self.page.after)
        return (count + sector_bytes - 1) // sector_bytes

    @property
    def identity(self):
        return self.transaction, self.kind, self.ordinal


@dataclass(frozen=True)
class Fragment:
    record: Record
    part: int
    intact: bool = True


@dataclass(frozen=True)
class Snapshot:
    label: str
    durable: dict
    pending: dict
    acknowledged: bool
    operation: int = 0


@dataclass(frozen=True)
class Fault:
    operation: int
    prefix_bytes: int = 0
    # A failing write/barrier can persist any subset of its outstanding cells.
    persist_mask: int = 0


def apply_cells(target, cells):
    for key, value in cells.items():
        if value is None:
            target.pop(key, None)
        else:
            target[key] = value


def crash(snapshot, mask):
    keys = tuple(snapshot.pending)
    if not 0 <= mask < (1 << len(keys)):
        raise Refused('Crash persistence mask is outside the pending set')
    result = dict(snapshot.durable)
    apply_cells(result, {key: snapshot.pending[key] for index, key in enumerate(keys)
                         if mask & (1 << index)})
    return result


class Device:
    """An idealized persistent-cell device with arbitrary volatile eviction."""

    def __init__(self, sector_bytes, cells, *, fault=None, trace=False):
        if sector_bytes <= 0 or sector_bytes & (sector_bytes - 1):
            raise Refused('Sector geometry must be a positive power of two')
        self.sector_bytes = sector_bytes
        self.durable, self.pending = dict(cells), {}
        self.fault, self.operations = fault, 0
        self.trace_enabled, self.trace = trace, []
        self.acknowledged = False
        self.claimed = False
        self.requires_recovery = False
        self.observe('initial')

    def observe(self, label):
        if self.trace_enabled:
            self.trace.append(Snapshot(label, dict(self.durable), dict(self.pending),
                                       self.acknowledged, self.operations))

    def _attempt(self, label, key=None, value=None):
        self.operations += 1
        if self.fault is None or self.operations != self.fault.operation:
            return
        prefix = self.fault.prefix_bytes
        if not 0 <= prefix <= self.sector_bytes:
            raise Refused('Partial transfer exceeds one sector')
        if key is not None and prefix:
            if value is None:
                previous = self.pending.get(key, self.durable.get(key))
                if prefix == self.sector_bytes:
                    self.pending[key] = None
                elif isinstance(previous, Fragment):
                    self.pending[key] = Fragment(previous.record, previous.part, False)
            elif isinstance(value, bytes):
                old = self.pending.get(key, self.durable.get(key, bytes(self.sector_bytes)))
                self.pending[key] = value[:prefix] + old[prefix:]
            else:
                self.pending[key] = Fragment(value.record, value.part,
                                             prefix == self.sector_bytes)
        snapshot = Snapshot(label, self.durable, self.pending, self.acknowledged)
        self.durable = crash(snapshot, self.fault.persist_mask)
        self.requires_recovery = True
        self.observe('failed:' + label)
        raise UncertainIO(label)

    def write(self, key, value, label):
        self._attempt(label, key, value)
        if isinstance(value, bytes) and len(value) != self.sector_bytes:
            raise Refused('Home writes must provide one complete private sector')
        self.pending[key] = value
        self.requires_recovery = True
        self.observe(label)

    def flush(self, label):
        self._attempt(label)
        apply_cells(self.durable, self.pending)
        self.pending.clear()
        self.observe(label)

    def trim(self, key):
        self._attempt('trim', key)
        self.pending[key] = None
        self.observe('trim')


def record_cells(record, sector_bytes):
    return {('log', *record.identity, part): Fragment(record, part)
            for part in range(record.parts(sector_bytes))}


def write_record(device, record):
    for key, value in record_cells(record, device.sector_bytes).items():
        device.write(key, value, record.kind.value)


def write_page(device, page, after, label):
    for key, value in page.cells(device.sector_bytes, after).items():
        device.write(key, value, label)


def retire(device, marker, *, already_durable=False):
    if not already_durable:
        write_record(device, marker)
        device.flush('checkpoint-durable')
    # Retain the durable checkpoint until every other record has been retired.
    keys = [key for key in (*device.durable, *device.pending)
            if key[0] == 'log' and key[1] == marker.transaction and
            key[2] != RecordKind.CHECKPOINT]
    for key in dict.fromkeys(keys):
        device.trim(key)
    device.flush('log-retired')
    for key in record_cells(marker, device.sector_bytes):
        device.trim(key)
    device.flush('checkpoint-retired')


def checkpoint(device, transaction, update_ids):
    retire(device, Record(transaction, RecordKind.CHECKPOINT, update_ids=update_ids))


@dataclass(frozen=True)
class Limits:
    # Small executable-model policies; native/core limits remain separate.
    private_bytes: int = MAX_PRIVATE_BYTES
    log_fragments: int = MAX_LOG_FRAGMENTS
    pages: int = MAX_PAGES


class Owner:
    """Serialized exclusive owner with preallocation credits and sticky failure."""

    def __init__(self, device, limits=Limits(), *, fail_allocation=None):
        if (device.claimed or device.requires_recovery or device.pending or
                any(key[0] == 'log' for key in device.durable)):
            raise Refused('Owner requires exclusive, qualified clean storage')
        if any(type(value) is not int or not 0 < value <= maximum for value, maximum in (
                (limits.private_bytes, MAX_PRIVATE_BYTES),
                (limits.log_fragments, MAX_LOG_FRAGMENTS), (limits.pages, MAX_PAGES))):
            raise Refused('Model credits must be positive and within hard ceilings')
        device.claimed = True
        self.device, self.limits = device, limits
        self.fail_allocation = fail_allocation
        self.allocations, self.live_bytes, self.peak_bytes = 0, 0, 0
        self.reservations, self.active = (), None
        self.poisoned, self.closed = False, False
        self.visible = {key: value for key, value in device.durable.items() if key[0] == 'home'}

    def prepare(self, plan, transaction=1):
        if self.closed or self.poisoned or self.active is not None:
            raise Refused('Owner does not admit another transaction')
        if (type(transaction) is not int or not 0 < transaction <= MAX_IDENTIFIER or
                not isinstance(plan, Plan) or not isinstance(plan.updates, tuple) or
                not isinstance(plan.initialized, tuple) or not plan.updates):
            raise Refused('Transaction identity and update set must be nonempty')
        pages = (*plan.initialized, *plan.updates)
        if len(pages) > self.limits.pages:
            raise Refused('Page reservation ceiling exceeded')
        sector = self.device.sector_bytes
        addresses = set()
        private = 0
        for page in pages:
            if (not isinstance(page, Page) or not isinstance(page.kind, ObjectKind) or
                    type(page.address) is not int or page.address < 0 or
                    page.address % sector or not isinstance(page.before, bytes) or
                    not isinstance(page.after, bytes) or not page.before or
                    len(page.before) != len(page.after) or len(page.before) % sector):
                raise Refused('Private page geometry is invalid')
            private += len(page.before) + len(page.after)
            if private > self.limits.private_bytes:
                raise Refused('Complete private credits must fit before allocation')
        for page in pages:
            for key, before in page.cells(sector, False).items():
                if key in addresses or self.visible.get(key) != before:
                    raise Refused('Overlapping reservation or stale private snapshot')
                addresses.add(key)
        if (any(page.kind != ObjectKind.DATA for page in plan.initialized) or
                any(page.kind == ObjectKind.DATA for page in plan.updates)):
            raise Refused('Initialized user data and logged metadata have separate ownership')
        selected = tuple(sorted(plan.updates, key=lambda page: (page.kind, page.address)))
        records = tuple(Record(transaction, RecordKind.UPDATE, index, page)
                        for index, page in enumerate(selected))
        ids = tuple(range(len(records)))
        controls = (Record(transaction, RecordKind.COMMIT, update_ids=ids),
                    Record(transaction, RecordKind.CHECKPOINT, update_ids=ids))
        log_parts = sum(record.parts(sector) for record in (*records, *controls))
        if log_parts > self.limits.log_fragments:
            raise Refused('Complete private/log credits must fit before allocation')
        # Canonical reservations are established before private allocation.
        self.reservations = tuple(sorted((page.kind, page.address) for page in pages))
        try:
            for page in pages:
                self.allocations += 1
                if self.allocations == self.fail_allocation:
                    raise Refused('Injected private allocation failure')
                self.live_bytes += len(page.before) + len(page.after)
                self.peak_bytes = max(self.peak_bytes, self.live_bytes)
            self.active = Transaction(self, Plan(selected, plan.initialized), records)
            self.device.acknowledged = False
            return self.active
        except Refused:
            self.live_bytes, self.reservations = 0, ()
            raise

    def release(self):
        self.active, self.reservations, self.live_bytes = None, (), 0

    def read_view(self):
        if self.closed or self.poisoned:
            raise Refused('Closed or uncertain ownership cannot publish a live view')
        return dict(self.visible)

    def close(self):
        if not self.closed:
            self.release()
            self.device.claimed = False
            self.closed = True


class Transaction:
    def __init__(self, owner, plan, records):
        self.owner, self.plan, self.records = owner, plan, records
        self.finished = False

    def run(self, *, commit=True, steal=False):
        owner, device = self.owner, self.owner.device
        if owner.closed or owner.poisoned or owner.active is not self or self.finished:
            raise Refused('Transaction is no longer admitted')
        try:
            for page in self.plan.initialized:
                write_page(device, page, True, 'initialize-data')
            if self.plan.initialized:
                device.flush('data-durable')
            for record in self.records:
                write_record(device, record)
                device.flush('update-durable')
            if steal:
                for page in self.plan.updates:
                    write_page(device, page, True, 'uncommitted-home')
            transaction = self.records[0].transaction
            ids = tuple(record.ordinal for record in self.records)
            if commit:
                write_record(device, Record(transaction, RecordKind.COMMIT, update_ids=ids))
                device.flush('commit-durable')
                # Live readers use one committed snapshot, never the dirty home cells.
                for page in (*self.plan.initialized, *self.plan.updates):
                    owner.visible.update(page.cells(device.sector_bytes, True))
                device.acknowledged = True
                device.observe('publish')
                if not steal:
                    for page in self.plan.updates:
                        write_page(device, page, True, 'committed-home')
            elif steal:
                for page in reversed(self.plan.updates):
                    write_page(device, page, False, 'abort-home')
            device.flush('home-durable')
            checkpoint(device, transaction, ids)
            device.requires_recovery = False
            self.finished = True
            owner.release()
        except UncertainIO:
            owner.poisoned = True
            raise


def validate_record(record, sector_bytes):
    if (not isinstance(record, Record) or not isinstance(record.kind, RecordKind) or
            type(record.transaction) is not int or not 0 < record.transaction <= MAX_IDENTIFIER or
            type(record.ordinal) is not int or not 0 <= record.ordinal < MAX_PAGES or
            not isinstance(record.update_ids, tuple)):
        raise Refused('History identity is invalid')
    if record.kind == RecordKind.UPDATE:
        page = record.page
        if (not isinstance(page, Page) or not isinstance(page.kind, ObjectKind) or
                page.kind == ObjectKind.DATA or not isinstance(page.before, bytes) or
                not isinstance(page.after, bytes) or not page.before or
                len(page.before) != len(page.after) or len(page.before) % sector_bytes or
                type(page.address) is not int or page.address < 0 or
                page.address % sector_bytes or record.update_ids or
                len(page.before) + len(page.after) > MAX_PRIVATE_BYTES):
            raise Refused('History update lacks a complete bounded metadata snapshot')
    elif (record.page is not None or record.ordinal != 0 or
          len(record.update_ids) > MAX_PAGES or
          any(type(ordinal) is not int for ordinal in record.update_ids) or
          record.update_ids != tuple(range(len(record.update_ids)))):
        raise Refused('History control record has invalid update membership')
    if record.parts(sector_bytes) > MAX_LOG_FRAGMENTS:
        raise Refused('History record exceeds the fragment ceiling')


def qualified_records(device):
    """Classify intact abstract fragments before issuing any recovery write."""
    grouped, observed = {}, 0
    for key, fragment in device.durable.items():
        if key[0] != 'log':
            continue
        observed += 1
        if observed > MAX_LOG_FRAGMENTS or not isinstance(fragment, Fragment):
            raise Refused('History exceeds its fragment ceiling or has an invalid fragment')
        validate_record(fragment.record, device.sector_bytes)
        if (type(fragment.part) is not int or not 0 <= fragment.part <
                fragment.record.parts(device.sector_bytes) or type(fragment.intact) is not bool or
                key != ('log', *fragment.record.identity, fragment.part)):
            raise Refused('Log fragment identity is inconsistent')
        grouped.setdefault(fragment.record.identity, []).append(fragment)
    complete = {}
    for identity, fragments in grouped.items():
        record = fragments[0].record
        if any(fragment.record != record for fragment in fragments):
            raise Refused('Fragments disagree on their immutable record')
        if (all(fragment.intact for fragment in fragments) and
                {fragment.part for fragment in fragments} ==
                set(range(record.parts(device.sector_bytes)))):
            complete[identity] = record
    if len(complete) > MAX_PAGES + len(RecordKind) - 1:
        raise Refused('History exceeds the model record ceiling')
    private = sum(len(record.page.before) + len(record.page.after)
                  for record in complete.values() if record.page is not None)
    if private > MAX_PRIVATE_BYTES:
        raise Refused('History exceeds its aggregate private snapshot credits')
    return complete


def recover(device):
    """Redo a committed serialized transaction or undo its uncommitted snapshots.

    The caller supplies authoritative abstract history. Native LFS copy routing,
    written history, opcode/target qualification and CLR semantics are not inferred.
    """
    if device.claimed or device.pending:
        raise Refused('Recovery requires an exclusive cold device without volatile cells')
    records = qualified_records(device)
    transactions = sorted({identity[0] for identity in records})
    # This model serializes and checkpoints before admitting another transaction.
    if len(transactions) > 1:
        raise Refused('Interleaved native history needs a separate owning contract')
    actions = []
    for transaction in transactions:
        if (transaction, RecordKind.CHECKPOINT, 0) in records:
            continue
        updates = {record.ordinal: record for record in records.values()
                   if record.transaction == transaction and record.kind == RecordKind.UPDATE}
        if set(updates) != set(range(len(updates))):
            raise Refused('Serialized update history is not a complete durable prefix')
        addresses = set()
        for record in updates.values():
            cells = record.page.cells(device.sector_bytes, False)
            if addresses.intersection(cells):
                raise Refused('History contains overlapping metadata updates')
            addresses.update(cells)
        commit = records.get((transaction, RecordKind.COMMIT, 0))
        if commit is not None:
            if set(updates) != set(commit.update_ids) or len(set(commit.update_ids)) != len(commit.update_ids):
                raise Refused('Durable commit lacks its complete update set')
            actions.extend((updates[index].page, True) for index in sorted(updates))
        else:
            actions.extend((updates[index].page, False) for index in sorted(updates, reverse=True))
    for page, after in actions:
        write_page(device, page, after, 'recover-home')
    device.flush('recovery-home-durable')
    for transaction in transactions:
        marker = records.get((transaction, RecordKind.CHECKPOINT, 0))
        if marker is not None:
            # Partial retirement may have removed update records. Keep the exact
            # durable marker; replacing it could erase recovery's skip evidence.
            retire(device, marker, already_durable=True)
        else:
            ids = tuple(sorted(record.ordinal for record in records.values()
                               if record.transaction == transaction and record.kind == RecordKind.UPDATE))
            checkpoint(device, transaction, ids)
    device.requires_recovery = False
