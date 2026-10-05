#!/usr/bin/env python3
"""Author independent small inputs for each parser fuzz target."""
from pathlib import Path
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import fixtures as wire
import access_transport as access_wire
from stat_fixtures import change_flags, UNKNOWN_COMPRESSION_FORMAT
from wof_fixtures import generate as generate_wof
from lzx_fixtures import author as generate_lzx
from logfile_fixtures import author as generate_logfile
import logfile_fixtures as logfile_wire
from logfile_source_fixtures import author as generate_logfile_sources
from logfile_volume_fixtures import author as generate_logfile_volumes
from logfile_record_fixtures import author as generate_logfile_records
from logfile_legacy_fixtures import author as generate_logfile_legacy
from logfile_fast_fixtures import author as generate_logfile_fast
from logfile_inventory_fixtures import author as generate_logfile_inventory
from logfile_index_fixtures import author as generate_logfile_index
from logfile_history_fixtures import author as generate_logfile_history
from logfile_client_fixtures import author as generate_logfile_clients
from logfile_checkpoint_fixtures import author as generate_logfile_checkpoints
from logfile_restart_record_fixtures import author as generate_logfile_restart_records
from logfile_tables_fixtures import author as generate_logfile_tables
from logfile_names_fixtures import author as generate_logfile_names
from checkpoint_fixtures import author as generate_checkpoint_bindings
from checkpoint_snapshot_fixtures import author as generate_checkpoint_snapshots
from checkpoint_capture_fixtures import author as generate_checkpoint_captures
from logfile_transaction_fixtures import author as generate_transaction_chains
from checkpoint_transaction_fixtures import author as generate_checkpoint_transactions
from recovery_history_fixtures import author as generate_recovery_histories
from record_protect_fixtures import author as generate_record_protection
from logfile_encode_fixtures import author as generate_logfile_encoding, RECORD_KIND as LOGFILE_ENCODE_RECORD
from logfile_page_encode_fixtures import author as generate_logfile_page_encoding

LOGFILE_FUZZ_HEADER = struct.Struct('<BQI')
LOGFILE_FUZZ_KINDS = {'restart': 0, 'page': 1, 'record': 2, 'update': 3, 'client': 4}
LOGFILE_SOURCE_KIND = 5
LOGFILE_CIRCULAR_RECORD_KIND = 6
LOGFILE_CLIENT_RESTART_KIND = 7
LOGFILE_CLIENT_RESTART_RECORD_KIND = 8
LOGFILE_TABLE_KINDS = {0: 9, 1: 10, 2: 11, 3: 12}
LOGFILE_PROTECTED_RECORD_KIND = 13
LOGFILE_LEGACY_RECORD_KIND = 14
LOGFILE_INVENTORY_KIND = 23
LOGFILE_INDEX_KIND = 24
LOGFILE_HISTORY_KIND = 25
LOGFILE_CAPTURE_KIND = 26
LOGFILE_TRANSACTION_CHAIN_KIND = 27
LOGFILE_CHECKPOINT_TRANSACTIONS_KIND = 28
LOGFILE_RECOVERY_INPUTS_KIND = 29
LOGFILE_TRANSACTION_HEADER = struct.Struct('<HHI')
LOGFILE_INVENTORY_READ_CALL_BUDGET = 4096
LOGFILE_NAME_KINDS = {0: 16, 1: 15}
LOGFILE_CHECKPOINT_TABLE_KIND = 17
LOGFILE_CHECKPOINT_HEADER = struct.Struct('<IB')
LOGFILE_CHECKPOINT_SNAPSHOT_KIND = 18
LOGFILE_RECORD_ENCODE_KIND = 19
LOGFILE_UPDATE_ENCODE_KIND = 20
LOGFILE_PAGE_ENCODE_KIND = 21
LOGFILE_FAST_RECORD_KIND = 22
LOGFILE_SNAPSHOT_KINDS = 4
LOGFILE_SNAPSHOT_HEADER = struct.Struct('<' + 'I' * (LOGFILE_SNAPSHOT_KINDS + 1))
BITS_PER_BYTE = 8
LOGFILE_CAPTURE_SHORT_WORKSPACE = 1 << (BITS_PER_BYTE + 5)
LOGFILE_CAPTURE_SHORT_NAMES = 1 << (BITS_PER_BYTE + 6)
LOGFILE_CAPTURE_IDENTITY_SHIFT = struct.calcsize('<H') * BITS_PER_BYTE
LOGFILE_CLIENT_VERSION_SHIFT = struct.calcsize('<I') * BITS_PER_BYTE
LOGFILE_FUZZ_INPUT_BYTES = 2 * 1024 * 1024
LOGFILE_ALLOCATION_FAULT = 1 << BITS_PER_BYTE
LOGFILE_RECORD_ALLOCATION_FAULT = 1 << (BITS_PER_BYTE + 1)
LOGFILE_INDEX_COMPARISON_FAULT = 1 << (BITS_PER_BYTE + 2)
LOGFILE_INDEX_SELECTED_READ_FAULT = 1 << (BITS_PER_BYTE + 3)
LOGFILE_INDEX_SHORT_MEMORY = 1 << (BITS_PER_BYTE + 4)
LOGFILE_HISTORY_SHORT_WORKSPACE = 1 << (BITS_PER_BYTE + 5)
LOGFILE_HISTORY_VISITOR_STOP = 1 << (BITS_PER_BYTE + 6)
LOGFILE_HISTORY_SHORT_RECORDS = 1 << (BITS_PER_BYTE + 7)
LOGFILE_BUDGET_SHIFT = 16
LOGFILE_TRANSACTION_SHORT_LINKS = 1 << LOGFILE_BUDGET_SHIFT
LOGFILE_TRANSACTION_BUDGET_SHIFT = LOGFILE_BUDGET_SHIFT + 1
LOGFILE_ENCODE_SHORT_SHIFT = struct.calcsize('<H') * BITS_PER_BYTE
LOGFILE_PAGE_WORKSPACE_SHORT_SHIFT = LOGFILE_ENCODE_SHORT_SHIFT + 1
LOGFILE_PAGE_MAJOR_SHIFT = struct.calcsize('<I') * BITS_PER_BYTE
LOGFILE_PAGE_MINOR_SHIFT = (struct.calcsize('<I') + struct.calcsize('<H')) * BITS_PER_BYTE
LOGFILE_NULL_WORKSPACE_SHIFT = LOGFILE_BUDGET_SHIFT + struct.calcsize('<H') * BITS_PER_BYTE
LOGFILE_READ_CALL_BUDGET = 32
LOGFILE_FAST_READ_CALL_BUDGET = 2 * logfile_wire.FAST_PAGES + 1

MAX_STRUCTURE_BYTES = 32768
LZNT1_RAW_PAYLOAD = b'Independent raw chunk\n'
SECURITY_DESCRIPTOR = struct.Struct('<BBHIIII')
SECURITY_ACL = struct.Struct('<BBHHH')
SECURITY_ACE = struct.Struct('<BBHI')
SECURITY_SELF_RELATIVE = 0x8000
SECURITY_DACL_PRESENT = 0x0004
SECURITY_OBJECT_FLAGS = 0x00000003
SECURITY_OBJECT_CALLBACK = 0x0b
SECURITY_ALLOW = 0x00
SECURITY_REVISION = 1
SECURITY_ACL_REVISION = 2
SECURITY_OBJECT_ACL_REVISION = 4
SECURITY_GUID_BYTES = 16
SECURITY_APPLICATION_DATA = bytes.fromhex('61727478')
SECURITY_AUTHORITY_BYTES = 6
SECURITY_SID_SUBAUTHORITIES_MAX = 15
SECURITY_DWORD_MAX = (1 << 32) - 1
SECURITY_NT_AUTHORITY = 5
SECURITY_BUILTIN_DOMAIN = 32
SECURITY_BUILTIN_ADMINISTRATORS = 544
SECURITY_FILE_READ_DATA = 0x00000001
ACCESS_HEADER = struct.Struct('<IIBIIII')
ACCESS_COMPARISON_BUDGET = 262144
ACCESS_ENABLED = 0x00000004
ACCESS_DENY_ONLY = 0x00000010
ACCESS_RESTRICTED = 0x01
ACCESS_USER_DENY_ONLY = 0x02
ACCESS_UNRELATED_RID = 1001


def journal_volume_images(output, image_bytes):
    sources = output / 'logfile-sources'
    volumes = output / 'logfile-volumes'
    generate_logfile_sources(sources)
    cases = generate_logfile_volumes(volumes, sources, image_bytes,
                                    name_prefix='logfile-volume-')
    return [volumes / case['path'] for case in cases]


def security_seeds():
    authorities = (SECURITY_BUILTIN_DOMAIN, SECURITY_BUILTIN_ADMINISTRATORS)
    sid = struct.pack('BB', SECURITY_REVISION, len(authorities))
    sid += SECURITY_NT_AUTHORITY.to_bytes(SECURITY_AUTHORITY_BYTES, 'big')
    sid += struct.pack(f'<{len(authorities)}I', *authorities)
    ace = SECURITY_ACE.pack(SECURITY_ALLOW, 0, SECURITY_ACE.size + len(sid), SECURITY_FILE_READ_DATA) + sid
    object_body = struct.pack('<I', SECURITY_OBJECT_FLAGS) + bytes(2 * SECURITY_GUID_BYTES)
    object_body += sid + SECURITY_APPLICATION_DATA
    object_ace = SECURITY_ACE.pack(SECURITY_OBJECT_CALLBACK, 0,
                                  SECURITY_ACE.size + len(object_body), SECURITY_FILE_READ_DATA) + object_body
    maximum_parts = (SECURITY_DWORD_MAX,) * SECURITY_SID_SUBAUTHORITIES_MAX
    maximum_sid = struct.pack('BB', SECURITY_REVISION, len(maximum_parts))
    maximum_sid += bytes([0xff]) * SECURITY_AUTHORITY_BYTES
    maximum_sid += struct.pack(f'<{len(maximum_parts)}I', *maximum_parts)
    output = {'allow-ace': ace, 'object-ace': object_ace, 'sid-builtin': sid,
              'sid-maximum': maximum_sid,
              'sid-empty': struct.pack('BB', SECURITY_REVISION, 0) + bytes(SECURITY_AUTHORITY_BYTES)}
    for name, body, count, revision, present in (
            ('absent', b'', 0, SECURITY_ACL_REVISION, False),
            ('null', b'', 0, SECURITY_ACL_REVISION, True),
            ('empty', b'', 0, SECURITY_ACL_REVISION, True),
            ('allow', ace, 1, SECURITY_ACL_REVISION, True),
            ('object-callback', object_ace, 1, SECURITY_OBJECT_ACL_REVISION, True)):
        use_acl = name not in ('absent', 'null')
        acl = SECURITY_ACL.pack(revision, 0, SECURITY_ACL.size + len(body), count, 0) + body if use_acl else b''
        sid_offset = SECURITY_DESCRIPTOR.size
        acl_offset = sid_offset + len(sid) if use_acl else 0
        control = SECURITY_SELF_RELATIVE | (SECURITY_DACL_PRESENT if present else 0)
        output[name] = SECURITY_DESCRIPTOR.pack(SECURITY_REVISION, 0, control,
                                               sid_offset, sid_offset, 0, acl_offset) + sid + acl
    return output


def generate(output):
    seeds = {
        'mapping-pairs': {
            'resident': wire.resident(wire.DATA, b'resident data'),
            'fragmented': wire.nonresident(wire.DATA, [(1, 128), (1, 130)], wire.CLUSTER * 2),
            'negative-delta': wire.nonresident(wire.DATA, [(1, 130), (1, 128)], wire.CLUSTER * 2),
            'sparse': wire.nonresident(wire.DATA, [(1, 128), (2, None), (1, 130)], wire.CLUSTER * 4, flags=wire.SPARSE),
            'compressed': wire.nonresident(wire.DATA, [(1, 128), (wire.COMPRESSION_CLUSTERS - 1, None)], wire.COMPRESSION_UNIT_BYTES, flags=wire.COMPRESSED),
            'empty': wire.nonresident(wire.DATA, [], 0),
            'encrypted': wire.nonresident(wire.DATA, [(1, 128), (1, 130)],
                                           wire.FRAGMENTED_BYTES, flags=wire.ENCRYPTED),
            'opaque-compression': change_flags(wire.nonresident(wire.DATA,
                [(1, 128), (1, 130)], wire.FRAGMENTED_BYTES, flags=wire.COMPRESSED),
                UNKNOWN_COMPRESSION_FORMAT),
        },
        'attribute-list': {
            'base-data': wire.list_entry(wire.ROOT_REF, 1, 0),
            'duplicate': wire.list_entry(wire.ROOT_REF, 1, 0) * 2,
            'extension': wire.list_entry(wire.file_reference(wire.ATTRIBUTE_EXTENSION_RECORD), 1, 0),
            'gap': wire.list_entry(wire.ROOT_REF, 1, 1),
        },
        'index-block': {
            'empty': wire.index_block(0, []),
            'entries': wire.index_block(0, [wire.entry('a.txt', wire.FILE_RECORDS['hello.txt']),
                                          wire.entry('Ω-name.txt', wire.FILE_RECORDS['fragmented.bin'])]),
            'cycle': wire.index_block(0, [], terminal_child=0),
        },
        'lznt1': {
            'repeated': wire.repeated_chunk(ord('Z')),
            'raw': struct.pack('<H', wire.LZNT1_SIGNATURE | (len(LZNT1_RAW_PAYLOAD) - 1)) + LZNT1_RAW_PAYLOAD,
            'partial-final': wire.repeated_chunk(ord('A')) + struct.pack('<H', wire.LZNT1_SIGNATURE) + b'B',
        },
        'reparse': {
            'relative': wire.reparse_value(wire.REPARSE_TAG_SYMLINK, wire.REPARSE_RELATIVE_TARGET, 'display', relative=True),
            'absolute': wire.reparse_value(wire.REPARSE_TAG_SYMLINK, wire.REPARSE_ABSOLUTE_TARGET, wire.REPARSE_PRINT_TARGET),
            'junction': wire.reparse_value(wire.REPARSE_TAG_MOUNT_POINT, wire.REPARSE_ABSOLUTE_TARGET, wire.REPARSE_PRINT_TARGET),
            'unpaired': wire.reparse_value(wire.REPARSE_TAG_SYMLINK, '\ud800\\target', '', relative=True),
            'wof': wire.REPARSE_HEADER.pack(wire.REPARSE_TAG_WOF, 0, 0),
            'cloud': wire.REPARSE_HEADER.pack(wire.REPARSE_TAG_CLOUD, 0, 0),
        },
        'index-root': {},
        'security': security_seeds(),
        'access': {},
    }
    for name, descriptor in security_seeds().items():
        if name.endswith('-ace') or name.startswith('sid-'):
            continue
        for context, flags, attributes, user in (
                ('owner', 0, ACCESS_ENABLED, SECURITY_BUILTIN_ADMINISTRATORS),
                ('group', 0, ACCESS_ENABLED, ACCESS_UNRELATED_RID),
                ('deny-only', ACCESS_USER_DENY_ONLY, ACCESS_DENY_ONLY, SECURITY_BUILTIN_ADMINISTRATORS),
                ('restricted', ACCESS_RESTRICTED, ACCESS_ENABLED, ACCESS_UNRELATED_RID)):
            # The harness interprets the comparison word as a zero-based budget.
            header = ACCESS_HEADER.pack(SECURITY_FILE_READ_DATA, ACCESS_COMPARISON_BUDGET - 1, flags,
                                        attributes, user, SECURITY_BUILTIN_ADMINISTRATORS,
                                        SECURITY_BUILTIN_ADMINISTRATORS)
            seeds['access'][f'{name}-{context}'] = header + descriptor
    access_user = access_wire.sid(SECURITY_NT_AUTHORITY, SECURITY_BUILTIN_DOMAIN,
                                SECURITY_BUILTIN_ADMINISTRATORS)
    for name, generic, mapped in (
            ('read', access_wire.GENERIC_READ, access_wire.FILE_GENERIC_READ),
            ('write', access_wire.GENERIC_WRITE, access_wire.FILE_GENERIC_WRITE),
            ('execute', access_wire.GENERIC_EXECUTE, access_wire.FILE_GENERIC_EXECUTE),
            ('all', access_wire.GENERIC_ALL, access_wire.FILE_ALL_ACCESS)):
        concrete = access_wire.ace(access_wire.ACE_ALLOW, mapped, access_user)
        for stored, entries in (
                ('concrete', [concrete]),
                ('generic', [access_wire.ace(access_wire.ACE_ALLOW, generic, access_user)]),
                ('mixed-late', [concrete, access_wire.ace(access_wire.ACE_DENY,
                                                       generic | SECURITY_FILE_READ_DATA, access_user)]),
                ('inherit-only', [concrete, access_wire.ace(access_wire.ACE_DENY, generic,
                                                         access_user, access_wire.ACE_INHERIT_ONLY)])):
            packet = access_wire.descriptor(access_wire.UNRELATED, entries)
            for context, flags in (('ordinary', 0), ('restricted', ACCESS_RESTRICTED)):
                header = ACCESS_HEADER.pack(generic, ACCESS_COMPARISON_BUDGET - 1, flags,
                                            ACCESS_ENABLED, SECURITY_BUILTIN_ADMINISTRATORS,
                                            SECURITY_BUILTIN_ADMINISTRATORS,
                                            SECURITY_BUILTIN_ADMINISTRATORS)
                seeds['access'][f'request-{name}-stored-{stored}-{context}'] = header + packet
    for name, entries in (('empty', wire.entry()),
                          ('entries', wire.entry('hello.txt', wire.FILE_RECORDS['hello.txt']) + wire.entry()),
                          ('case-collision', wire.entry('HELLO.TXT', wire.FILE_RECORDS['fragmented.bin'], namespace=wire.NAMESPACE_POSIX) +
                           wire.entry('hello.txt', wire.FILE_RECORDS['hello.txt'], namespace=wire.NAMESPACE_POSIX) + wire.entry())):
        root = wire.INDEX_ROOT_HEADER.pack(wire.FILENAME, wire.COLLATION_FILENAME, wire.CLUSTER, 1)
        root += wire.INDEX_HEADER.pack(wire.INDEX_HEADER.size, wire.INDEX_HEADER.size + len(entries),
                                       wire.INDEX_HEADER.size + len(entries), 0)
        seeds['index-root'][name] = root + entries
    for target, cases in seeds.items():
        directory = output / target
        directory.mkdir(parents=True, exist_ok=True)
        for name, data in cases.items():
            assert 0 < len(data) <= MAX_STRUCTURE_BYTES
            (directory / (name + '.seed')).write_bytes(data)
    generate_wof(output)
    generate_lzx(output)
    log_packets = output / 'logfile-packets'
    log_seeds = output / 'logfile'
    log_seeds.mkdir(parents=True, exist_ok=True)
    for case in generate_logfile(log_packets):
        configuration = (log_packets / case['config']).read_bytes() if case['kind'] == 'page' else b''
        payload = (log_packets / case['path']).read_bytes()
        envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_FUZZ_KINDS[case['kind']], case['parameter'], len(configuration))
        (log_seeds / (case['path'].replace('.', '-') + '.seed')).write_bytes(envelope + configuration + payload)
    log_sources = output / 'logfile-sources'
    for case in generate_logfile_sources(log_sources):
        payload = (log_sources / case['path']).read_bytes()
        envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_SOURCE_KIND, 0, 0)
        if len(envelope) + len(payload) <= LOGFILE_FUZZ_INPUT_BYTES:
            (log_seeds / ('source-' + case['path'].replace('.', '-') + '.seed')).write_bytes(envelope + payload)
    log_records = output / 'logfile-records'
    selection = dict(input_bytes=LOGFILE_FUZZ_INPUT_BYTES, envelope_bytes=LOGFILE_FUZZ_HEADER.size,
                     included=[], skipped=[], fault_seeds=[])
    for case in generate_logfile_records(log_records):
        payload = (log_records / case['path']).read_bytes()
        if len(payload) + LOGFILE_FUZZ_HEADER.size > LOGFILE_FUZZ_INPUT_BYTES:
            selection['skipped'].append(dict(path=case['path'], source_bytes=len(payload),
                reason='Complete source and envelope exceed input cap; retained in direct C/CLI suites'))
            continue
        selection['included'].append(case['path'])
        envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_CIRCULAR_RECORD_KIND, case['lsn'], 0)
        (log_seeds / ('circular-' + case['path'].replace('.', '-') + '.seed')).write_bytes(envelope + payload)
        controls = {}
        if case['path'] == 'three-pages.journal':
            controls = {'first-read': 1, 'continuation-read': 2, 'allocation': LOGFILE_ALLOCATION_FAULT}
        elif case['path'] == 'credits.journal':
            # Call/byte policy derives from the same control word in the test
            # envelope. Add a full call-budget period where extra bytes are needed.
            exact_calls = case['pages'] - 1
            controls = {'exact-calls': (exact_calls + LOGFILE_READ_CALL_BUDGET) << LOGFILE_BUDGET_SHIFT,
                        'short-calls': (exact_calls - 1 + LOGFILE_READ_CALL_BUDGET) << LOGFILE_BUDGET_SHIFT,
                        'short-bytes': exact_calls << LOGFILE_BUDGET_SHIFT}
        for name, control in controls.items():
            filename = 'circular-' + case['path'].replace('.', '-') + '-' + name + '.seed'
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_CIRCULAR_RECORD_KIND, case['lsn'], control)
            (log_seeds / filename).write_bytes(envelope + payload)
            selection['fault_seeds'].append(filename)
    (output / 'logfile-record-selection.json').write_text(json.dumps(selection, indent=2) + '\n')
    legacy_records = output / 'logfile-legacy'
    for case in generate_logfile_legacy(legacy_records):
        payload = (legacy_records / case['path']).read_bytes()
        controls = {'default': 0}
        if case['path'] == 'newer-second-slot.journal':
            controls.update({'first-tail-read': 1, 'second-tail-read': 2, 'circular-read': 3,
                'selected-copy-read': 4, 'comparison-allocation': LOGFILE_ALLOCATION_FAULT,
                'record-allocation': LOGFILE_RECORD_ALLOCATION_FAULT})
        elif case['pages'] > 1:
            exact_calls = case['reads'] - 1
            controls.update({'exact-calls': (exact_calls + LOGFILE_READ_CALL_BUDGET) << LOGFILE_BUDGET_SHIFT,
                'short-calls': (exact_calls - 1 + LOGFILE_READ_CALL_BUDGET) << LOGFILE_BUDGET_SHIFT,
                'short-bytes': exact_calls << LOGFILE_BUDGET_SHIFT,
                'final-copy-read': case['reads']})
        for name, control in controls.items():
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_LEGACY_RECORD_KIND, case['lsn'], control)
            assert len(envelope) + len(payload) <= LOGFILE_FUZZ_INPUT_BYTES
            filename = 'legacy-' + case['path'].replace('.', '-') + '-' + name + '.seed'
            (log_seeds / filename).write_bytes(envelope + payload)
    fast_records = output / 'logfile-fast'
    for case in generate_logfile_fast(fast_records):
        payload = (fast_records / case['path']).read_bytes()
        controls = {'default': 0}
        if case['faults']:
            controls.update({'first-copy-read': 1,
                'circular-read': logfile_wire.FAST_PAGES + 1,
                'final-copy-read': case['reads'],
                'comparison-allocation': LOGFILE_ALLOCATION_FAULT,
                'record-allocation': LOGFILE_RECORD_ALLOCATION_FAULT})
        if case['pages'] > 1 or case['reads'] == LOGFILE_FAST_READ_CALL_BUDGET:
            # Admit bytes as well as calls. Whole call periods preserve the
            # remainder while supplying sufficient byte credits for the source.
            minimum = (case['reads'] * case['page_bytes'] + logfile_wire.USA_STRIDE - 1) // logfile_wire.USA_STRIDE
            for name, calls in [('exact-calls', case['reads']), ('short-calls', case['reads'] - 1)]:
                remainder = calls - 1
                periods = (minimum - remainder + LOGFILE_FAST_READ_CALL_BUDGET - 1) // LOGFILE_FAST_READ_CALL_BUDGET
                budget = remainder + periods * LOGFILE_FAST_READ_CALL_BUDGET
                controls[name] = budget << LOGFILE_BUDGET_SHIFT
            if case['reads'] == LOGFILE_FAST_READ_CALL_BUDGET:
                controls['short-bytes'] = (minimum - 1) << LOGFILE_BUDGET_SHIFT
        for name, control in controls.items():
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_FAST_RECORD_KIND, case['lsn'], control)
            assert len(envelope) + len(payload) <= LOGFILE_FUZZ_INPUT_BYTES
            filename = 'fast-' + case['path'].replace('.', '-') + '-' + name + '.seed'
            (log_seeds / filename).write_bytes(envelope + payload)
    inventories = output / 'logfile-inventory'
    for case in generate_logfile_inventory(inventories):
        payload = (inventories / case['path']).read_bytes()
        if len(payload) + LOGFILE_FUZZ_HEADER.size > LOGFILE_FUZZ_INPUT_BYTES:
            continue
        controls = {'default': (0, 0)}
        if case['faults']:
            pages = case['inventory']['total_pages']
            byte_units = case['inventory']['read_bytes'] // logfile_wire.USA_STRIDE
            controls.update({'first-read': (0, 1), 'last-read': (0, pages),
                'visitor-first': (1, 0), 'visitor-last': (pages, 0),
                'exact-calls': (0, (pages - 1 + LOGFILE_INVENTORY_READ_CALL_BUDGET) << LOGFILE_BUDGET_SHIFT),
                'short-calls': (0, (pages - 2 + LOGFILE_INVENTORY_READ_CALL_BUDGET) << LOGFILE_BUDGET_SHIFT),
                'exact-bytes': (0, byte_units << LOGFILE_BUDGET_SHIFT),
                'short-bytes': (0, (byte_units - 1) << LOGFILE_BUDGET_SHIFT)})
        for name, (stop, control) in controls.items():
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_INVENTORY_KIND, stop, control)
            filename = 'inventory-' + case['path'].replace('.', '-') + '-' + name + '.seed'
            (log_seeds / filename).write_bytes(envelope + payload)
    indices = output / 'logfile-index'
    index_cases, index_records = generate_logfile_index(indices)
    for case in index_cases:
        payload = (indices / case['path']).read_bytes()
        if len(payload) + LOGFILE_FUZZ_HEADER.size > LOGFILE_FUZZ_INPUT_BYTES:
            continue
        controls = {'default': 0}
        if case['faults']:
            maximum_reads = case['maximum_reads']
            byte_units = maximum_reads * case['page_bytes'] // logfile_wire.USA_STRIDE
            controls.update({'first-read': 1,
                'comparison-read': LOGFILE_INDEX_COMPARISON_FAULT | 1,
                'index-allocation': LOGFILE_ALLOCATION_FAULT,
                'short-memory': LOGFILE_INDEX_SHORT_MEMORY,
                'exact-calls': (maximum_reads - 1 + LOGFILE_INVENTORY_READ_CALL_BUDGET) << LOGFILE_BUDGET_SHIFT,
                'short-calls': (maximum_reads - 2 + LOGFILE_INVENTORY_READ_CALL_BUDGET) << LOGFILE_BUDGET_SHIFT,
                'exact-bytes': byte_units << LOGFILE_BUDGET_SHIFT,
                'short-bytes': (byte_units - 1) << LOGFILE_BUDGET_SHIFT})
        for name, control in controls.items():
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_INDEX_KIND, 0, control)
            filename = 'index-' + case['path'].replace('/', '-').replace('.', '-') + '-' + name + '.seed'
            (log_seeds / filename).write_bytes(envelope + payload)
    for case in index_records:
        payload = (indices / case['path']).read_bytes()
        assert len(payload) + LOGFILE_FUZZ_HEADER.size <= LOGFILE_FUZZ_INPUT_BYTES
        controls = {'record-default': 0}
        if case['code'] == 0 and (case['pages'] > 1 or case.get('faults')):
            controls.update({'record-allocation': LOGFILE_RECORD_ALLOCATION_FAULT,
                'selected-first-read': LOGFILE_INDEX_SELECTED_READ_FAULT | 1,
                'selected-last-read': LOGFILE_INDEX_SELECTED_READ_FAULT | case['pages']})
        for name, control in controls.items():
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_INDEX_KIND, case['lsn'], control)
            filename = 'index-' + case['path'].replace('/', '-').replace('.', '-') + '-' + name + '.seed'
            (log_seeds / filename).write_bytes(envelope + payload)
    histories = output / 'logfile-history'
    for case in generate_logfile_history(histories):
        payload = (histories / case['path']).read_bytes()
        if len(payload) + LOGFILE_FUZZ_HEADER.size > LOGFILE_FUZZ_INPUT_BYTES:
            continue
        controls = {'default': 0}
        if case['code'] == 0 and ('three-page' in case['path'] or 'unfinished-copy' in case['path']):
            controls.update({'record-allocation': LOGFILE_RECORD_ALLOCATION_FAULT,
                'selected-first-read': LOGFILE_INDEX_SELECTED_READ_FAULT | 1,
                'selected-last-read': LOGFILE_INDEX_SELECTED_READ_FAULT | case['history']['read_calls'],
                'short-workspace': LOGFILE_HISTORY_SHORT_WORKSPACE,
                'visitor-stop': LOGFILE_HISTORY_VISITOR_STOP,
                'short-record-count': LOGFILE_HISTORY_SHORT_RECORDS})
        for name, control in controls.items():
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_HISTORY_KIND, case['first_lsn'], control)
            filename = 'history-' + case['path'].replace('.', '-') + '-' + name + '.seed'
            (log_seeds / filename).write_bytes(envelope + payload)
    captures = output / 'checkpoint-capture'
    for case in generate_checkpoint_captures(captures):
        payload = (captures / case['path']).read_bytes()
        if len(payload) + LOGFILE_FUZZ_HEADER.size > LOGFILE_FUZZ_INPUT_BYTES:
            continue
        controls = {'default': 0}
        if case['code'] == 0 and case['path'] in (
                'client-0-fast-0-mask-15.journal', 'checkpoint-fast-copy.journal',
                'wrapped-checkpoint.journal'):
            controls.update({'record-allocation': LOGFILE_RECORD_ALLOCATION_FAULT,
                'selected-first-read': LOGFILE_INDEX_SELECTED_READ_FAULT | 1,
                'selected-last-read': LOGFILE_INDEX_SELECTED_READ_FAULT | case['report']['read_calls'],
                'short-record-workspace': LOGFILE_CAPTURE_SHORT_WORKSPACE,
                'short-name-workspace': LOGFILE_CAPTURE_SHORT_NAMES})
            byte_units = case['report']['read_bytes'] // logfile_wire.USA_STRIDE
            remainder = case['report']['read_calls'] - 2
            periods = max(1, (byte_units - remainder + LOGFILE_INVENTORY_READ_CALL_BUDGET - 1) //
                LOGFILE_INVENTORY_READ_CALL_BUDGET)
            budget = remainder + periods * LOGFILE_INVENTORY_READ_CALL_BUDGET
            controls['short-capture-calls'] = budget << LOGFILE_BUDGET_SHIFT
        identity = case['client_index'] | (case['client_sequence'] << LOGFILE_CAPTURE_IDENTITY_SHIFT)
        for name, control in controls.items():
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_CAPTURE_KIND, identity, control)
            filename = 'capture-' + case['path'].replace('.', '-') + '-' + name + '.seed'
            (log_seeds / filename).write_bytes(envelope + payload)
    chains = output / 'logfile-transaction'
    for case in generate_transaction_chains(chains):
        payload = (chains / case['path']).read_bytes()
        if len(payload) + LOGFILE_FUZZ_HEADER.size + LOGFILE_TRANSACTION_HEADER.size > LOGFILE_FUZZ_INPUT_BYTES:
            continue
        controls = {'default': 0}
        if case['code'] == 0 and case['path'] in (
                'legacy-markers-extended-0.journal', 'fast-copy-31.journal',
                'legacy-spanning-root.journal', 'legacy-wrapped-root.journal'):
            controls.update({'record-allocation': LOGFILE_RECORD_ALLOCATION_FAULT,
                'selected-first-read': LOGFILE_INDEX_SELECTED_READ_FAULT | 1,
                'selected-last-read': LOGFILE_INDEX_SELECTED_READ_FAULT | case['report']['read_calls'],
                'short-record-workspace': LOGFILE_HISTORY_SHORT_WORKSPACE,
                'short-link-workspace': LOGFILE_TRANSACTION_SHORT_LINKS,
                'visitor-stop': LOGFILE_HISTORY_VISITOR_STOP,
                'short-record-count': LOGFILE_HISTORY_SHORT_RECORDS})
            byte_units = case['report']['read_bytes'] // logfile_wire.USA_STRIDE
            remainder = case['report']['read_calls'] - 2
            periods = max(1, (byte_units - remainder + LOGFILE_INVENTORY_READ_CALL_BUDGET - 1) //
                LOGFILE_INVENTORY_READ_CALL_BUDGET)
            budget = remainder + periods * LOGFILE_INVENTORY_READ_CALL_BUDGET
            controls['short-chain-calls'] = budget << LOGFILE_TRANSACTION_BUDGET_SHIFT
        identity = LOGFILE_TRANSACTION_HEADER.pack(case['index'], case['sequence'], case['transaction'])
        for name, control in controls.items():
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_TRANSACTION_CHAIN_KIND, case['root'], control)
            filename = 'chain-' + case['path'].replace('.', '-') + '-' + name + '.seed'
            (log_seeds / filename).write_bytes(envelope + identity + payload)
    checkpoint_transactions = output / 'checkpoint-transactions'
    for case in generate_checkpoint_transactions(checkpoint_transactions)['cases']:
        payload = (checkpoint_transactions / case['path']).read_bytes()
        assert len(payload) + LOGFILE_FUZZ_HEADER.size <= LOGFILE_FUZZ_INPUT_BYTES
        controls = {'default': 0}
        if case['path'] in ('client-1-fast-0-extended-0.journal', 'copy-fast-1-31.journal'):
            controls.update({'index-allocation': LOGFILE_ALLOCATION_FAULT,
                'record-allocation': LOGFILE_RECORD_ALLOCATION_FAULT,
                'selected-first-read': LOGFILE_INDEX_SELECTED_READ_FAULT | 1,
                'selected-last-read': LOGFILE_INDEX_SELECTED_READ_FAULT | case['report']['read_calls'],
                'short-record-workspace': LOGFILE_HISTORY_SHORT_WORKSPACE,
                'short-link-workspace': LOGFILE_TRANSACTION_SHORT_LINKS,
                'visitor-stop': LOGFILE_HISTORY_VISITOR_STOP,
                'short-record-count': LOGFILE_HISTORY_SHORT_RECORDS})
            byte_units = case['report']['read_bytes'] // logfile_wire.USA_STRIDE
            remainder = case['report']['read_calls'] - 2
            periods = max(1, (byte_units - remainder + LOGFILE_INVENTORY_READ_CALL_BUDGET - 1) //
                LOGFILE_INVENTORY_READ_CALL_BUDGET)
            controls['short-total-calls'] = (remainder + periods * LOGFILE_INVENTORY_READ_CALL_BUDGET) << LOGFILE_TRANSACTION_BUDGET_SHIFT
        identity = case['index'] | (case['sequence'] << LOGFILE_CAPTURE_IDENTITY_SHIFT)
        for name, control in controls.items():
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_CHECKPOINT_TRANSACTIONS_KIND, identity, control)
            filename = 'checkpoint-chain-' + case['path'].replace('.', '-') + '-' + name + '.seed'
            (log_seeds / filename).write_bytes(envelope + payload)
    recovery_histories = output / 'recovery-history'
    for case in generate_recovery_histories(recovery_histories):
        payload = (recovery_histories / case['path']).read_bytes()
        assert len(payload) + LOGFILE_FUZZ_HEADER.size <= LOGFILE_FUZZ_INPUT_BYTES
        controls = {'default': 0}
        if case['path'] == 'checkpoint-active-then-forget-0-0-0.journal':
            controls.update({'index-allocation': LOGFILE_ALLOCATION_FAULT,
                'owner-allocation': LOGFILE_RECORD_ALLOCATION_FAULT,
                'selected-first-read': LOGFILE_INDEX_SELECTED_READ_FAULT | 1,
                'short-record-count': LOGFILE_HISTORY_SHORT_RECORDS,
                'short-history-bytes': LOGFILE_HISTORY_SHORT_WORKSPACE})
        identity = logfile_wire.CLIENT_SEQUENCE << LOGFILE_CAPTURE_IDENTITY_SHIFT
        for name, control in controls.items():
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_RECOVERY_INPUTS_KIND, identity, control)
            filename = 'recovery-' + case['path'].replace('.', '-') + '-' + name + '.seed'
            (log_seeds / filename).write_bytes(envelope + payload)
    log_clients = output / 'logfile-clients'
    for case in generate_logfile_clients(log_clients):
        payload = (log_clients / case['path']).read_bytes()
        envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_SOURCE_KIND, 0, 0)
        assert len(envelope) + len(payload) <= LOGFILE_FUZZ_INPUT_BYTES
        (log_seeds / ('client-source-' + case['path'].replace('.', '-') + '.seed')).write_bytes(envelope + payload)
    log_checkpoints = output / 'logfile-checkpoints'
    for case in generate_logfile_checkpoints(log_checkpoints):
        payload = (log_checkpoints / case['path']).read_bytes()
        envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_CLIENT_RESTART_KIND, 0, 0)
        assert len(envelope) + len(payload) <= LOGFILE_FUZZ_INPUT_BYTES
        (log_seeds / ('checkpoint-' + case['path'].replace('.', '-') + '.seed')).write_bytes(envelope + payload)
    log_restart_records = output / 'logfile-restart-records'
    for case in generate_logfile_restart_records(log_restart_records):
        source = (log_restart_records / case['source']).read_bytes()
        packet = (log_restart_records / case['path']).read_bytes()
        envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_CLIENT_RESTART_RECORD_KIND, 0, len(source))
        assert len(envelope) + len(source) + len(packet) <= LOGFILE_FUZZ_INPUT_BYTES
        (log_seeds / ('restart-record-' + case['path'].replace('.', '-') + '.seed')).write_bytes(envelope + source + packet)
    log_tables = output / 'logfile-tables'
    generate_logfile_tables(log_tables)
    for case in json.loads((log_tables / 'manifest.json').read_text())['cases']:
        payload = (log_tables / (case['name'] + '.input')).read_bytes()
        argument = case['major'] | (case['minor'] << LOGFILE_CLIENT_VERSION_SHIFT)
        envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_TABLE_KINDS[case['kind']], argument, 0)
        assert len(envelope) + len(payload) <= LOGFILE_FUZZ_INPUT_BYTES
        (log_seeds / ('table-' + case['name'] + '.seed')).write_bytes(envelope + payload)
    protect_packets = output / 'record-protection'
    generate_record_protection(protect_packets)
    for case in json.loads((protect_packets / 'manifest.json').read_text())['cases']:
        payload = (protect_packets / (case['name'] + '.input')).read_bytes()
        envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_PROTECTED_RECORD_KIND, case['capacity'], 0)
        assert len(envelope) + len(payload) <= LOGFILE_FUZZ_INPUT_BYTES
        (log_seeds / ('protect-' + case['name'] + '.seed')).write_bytes(envelope + payload)
    name_packets = output / 'logfile-names'
    for case in generate_logfile_names(name_packets):
        payload = (name_packets / (case['name'] + '.input')).read_bytes()
        envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_NAME_KINDS[case['kind']], 0, 0)
        assert len(envelope) + len(payload) <= LOGFILE_FUZZ_INPUT_BYTES
        (log_seeds / ('name-' + case['name'] + '.seed')).write_bytes(envelope + payload)
    binding_packets = output / 'checkpoint-bindings'
    for case in generate_checkpoint_bindings(binding_packets):
        source = (binding_packets / case['source']).read_bytes()
        checkpoint = (binding_packets / (case['name'] + '.checkpoint')).read_bytes()
        table = (binding_packets / (case['name'] + '.table')).read_bytes()
        wrapper = LOGFILE_CHECKPOINT_HEADER.pack(len(checkpoint), case['kind'])
        for suffix, argument in (('', 0), ('-read-fault', 1),
                                 ('-allocation-fault', LOGFILE_ALLOCATION_FAULT)):
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_CHECKPOINT_TABLE_KIND, argument, len(source))
            payload = envelope + source + wrapper + checkpoint + table
            assert len(payload) <= LOGFILE_FUZZ_INPUT_BYTES
            (log_seeds / ('binding-' + case['name'] + suffix + '.seed')).write_bytes(payload)
    snapshot_packets = output / 'checkpoint-snapshots'
    for case in generate_checkpoint_snapshots(snapshot_packets):
        source = (snapshot_packets / case['source']).read_bytes()
        checkpoint = (snapshot_packets / (case['name'] + '.checkpoint')).read_bytes()
        dumps = [(snapshot_packets / f"{case['name']}.dump-{kind}").read_bytes()
            for kind in range(LOGFILE_SNAPSHOT_KINDS)]
        wrapper = LOGFILE_SNAPSHOT_HEADER.pack(len(checkpoint), *map(len, dumps))
        control = (case['capacity'] + 1) << LOGFILE_BUDGET_SHIFT
        if case['null_workspace']:
            control |= 1 << LOGFILE_NULL_WORKSPACE_SHIFT
        for suffix, fault in (('', 0), ('-read-fault', 1), ('-allocation-fault', LOGFILE_ALLOCATION_FAULT)):
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_CHECKPOINT_SNAPSHOT_KIND, control | fault, len(source))
            payload = envelope + source + wrapper + checkpoint + b''.join(dumps)
            assert len(payload) <= LOGFILE_FUZZ_INPUT_BYTES
            (log_seeds / ('snapshot-' + case['name'] + suffix + '.seed')).write_bytes(payload)
    encode_packets = output / 'logfile-encoding'
    for case in generate_logfile_encoding(encode_packets):
        payload = (encode_packets / (case['name'] + '.input')).read_bytes()
        kind = LOGFILE_RECORD_ENCODE_KIND if case['kind'] == LOGFILE_ENCODE_RECORD else LOGFILE_UPDATE_ENCODE_KIND
        argument = case['header_bytes'] if case['kind'] == LOGFILE_ENCODE_RECORD else 0
        for suffix, control in (('', 0), ('-short-capacity', 1 << LOGFILE_ENCODE_SHORT_SHIFT)):
            envelope = LOGFILE_FUZZ_HEADER.pack(kind, argument | control, 0)
            assert len(envelope) + len(payload) <= LOGFILE_FUZZ_INPUT_BYTES
            (log_seeds / ('encode-' + case['name'] + suffix + '.seed')).write_bytes(envelope + payload)
    page_packets = output / 'logfile-page-encoding'
    for case in generate_logfile_page_encoding(page_packets):
        payload = (page_packets / (case['name'] + '.input')).read_bytes()
        argument = (case['data_offset'] | (logfile_wire.LEGACY_MAJOR << LOGFILE_PAGE_MAJOR_SHIFT)
                    | (logfile_wire.LEGACY_MINOR << LOGFILE_PAGE_MINOR_SHIFT))
        for suffix, control in (('', 0), ('-short-capacity', 1 << LOGFILE_ENCODE_SHORT_SHIFT),
                                ('-short-workspace', 1 << LOGFILE_PAGE_WORKSPACE_SHORT_SHIFT)):
            envelope = LOGFILE_FUZZ_HEADER.pack(LOGFILE_PAGE_ENCODE_KIND, argument | control, 0)
            assert len(envelope) + len(payload) <= LOGFILE_FUZZ_INPUT_BYTES
            (log_seeds / ('page-encode-' + case['name'] + suffix + '.seed')).write_bytes(envelope + payload)
    return seeds


if __name__ == '__main__':
    generate(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).touch()
