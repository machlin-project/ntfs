#!/usr/bin/env python3
"""Offline contracts for transport, SDK buffer ownership and truthful oracle reports."""
from copy import deepcopy
import ctypes as ct
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import access_transport as wire
import collect_windows_access as collector
from bounded_tool import bounded_read, run_tool
import windows_access as verifier

TEST_USER = wire.sid(5, 21, 1001)
TEST_OTHER = wire.sid(5, 21, 1002)
TEST_ERROR = 1314  # ERROR_PRIVILEGE_NOT_HELD.
TEST_UNKNOWN_FLAG = 0x80000000
TEST_UNKNOWN_ATTRIBUTE = 0x00000080
TEST_TIMEOUT_SECONDS = 0.05
TEST_OUTPUT_BYTES = 65536
HEADER_FIELDS = ('magic', 'version', 'desired', 'flags', 'groups', 'restricting', 'descriptor')
checks = 0


def check(condition):
    global checks
    assert condition
    checks += 1


def rejected(call, errors=(ValueError, OSError, KeyError, TypeError, RuntimeError)):
    try:
        call()
    except errors:
        check(True)
    else:
        raise AssertionError('Malformed or unsupported input was accepted')


def token(*, user=TEST_USER, groups=None, restricting=None, user_deny_only=False, restricted=False):
    return {'user': deepcopy(user), 'user_deny_only': user_deny_only,
            'groups': deepcopy(groups or []), 'restricting': deepcopy(restricting or []),
            'restricted': restricted}


def rewrite_header(packet, **changes):
    fields = dict(zip(HEADER_FIELDS, wire.HEADER.unpack_from(packet)))
    fields.update(changes)
    return wire.HEADER.pack(*(fields[field] for field in HEADER_FIELDS)) + packet[wire.HEADER.size:]


def core_contract(evaluator, directory):
    request = directory / 'request.bin'

    def evaluate(context, descriptor, desired, allowed, code=wire.NTFS_OK, mapped=None):
        packet = wire.request(context, descriptor, desired)
        request.write_bytes(packet)
        result = verifier.decision(run_tool([str(evaluator), str(request)]))
        check(result['code'] == code and result['allowed'] == allowed)
        if code == wire.NTFS_OK:
            mapped = desired if mapped is None else mapped
            check(result['requested'] == mapped and result['granted'] == (mapped if allowed else 0))
        check(bounded_read(request, wire.REQUEST_BYTES_MAX) == packet)
        return result

    plain = token()
    read, write = wire.FILE_READ_DATA, wire.FILE_WRITE_DATA
    allow = wire.ace(wire.ACE_ALLOW, read, TEST_USER)
    deny = wire.ace(wire.ACE_DENY, read, TEST_USER)
    for entries, desired, allowed in (([allow], read, True), ([deny, allow], read, False),
                                     ([allow, deny], read, True), ([], read, False),
                                     ([], 0, True), ([allow], read | write, False)):
        evaluate(plain, wire.descriptor(TEST_OTHER, entries), desired, allowed)
    for state in ('null', 'absent'):
        evaluate(plain, wire.descriptor(TEST_OTHER, [], state=state), read, True)
    evaluate(plain, wire.descriptor(TEST_OTHER, [wire.ace(wire.ACE_ALLOW, wire.FILE_GENERIC_READ, TEST_USER)]),
             wire.GENERIC_READ, True, mapped=wire.FILE_GENERIC_READ)
    generic_overlap = [wire.ace(wire.ACE_DENY, wire.FILE_GENERIC_WRITE, TEST_USER),
                       wire.ace(wire.ACE_ALLOW, wire.FILE_GENERIC_READ, TEST_USER)]
    evaluate(plain, wire.descriptor(TEST_OTHER, generic_overlap), wire.GENERIC_READ, False,
             mapped=wire.FILE_GENERIC_READ)
    # Mapping applies to requests. Stored generic bits remain outside the
    # concrete-ACE policy even after a sufficient grant or a zero request.
    for generic in (wire.GENERIC_READ, wire.GENERIC_WRITE, wire.GENERIC_EXECUTE, wire.GENERIC_ALL):
        for kind in (wire.ACE_ALLOW, wire.ACE_DENY):
            raw = wire.ace(kind, generic, TEST_USER)
            evaluate(plain, wire.descriptor(TEST_OTHER, [raw]), read, False, code=wire.NTFS_UNSUPPORTED)
            evaluate(plain, wire.descriptor(TEST_OTHER, [allow, raw]), read, False, code=wire.NTFS_UNSUPPORTED)
            evaluate(plain, wire.descriptor(TEST_OTHER, [raw]), 0, False, code=wire.NTFS_UNSUPPORTED)
            mixed = wire.ace(kind, generic | read, TEST_OTHER)
            evaluate(plain, wire.descriptor(TEST_OTHER, [allow, mixed]), read, False, code=wire.NTFS_UNSUPPORTED)
            inherited = wire.ace(kind, generic, TEST_USER, wire.ACE_INHERIT_ONLY)
            evaluate(plain, wire.descriptor(TEST_OTHER, [allow, inherited]), read, True)
    for attributes, allowed in ((wire.GROUP_ENABLED, True), (0, False), (wire.GROUP_DENY_ONLY, False)):
        context = token(groups=[{'sid': wire.WORLD, 'attributes': attributes}])
        evaluate(context, wire.descriptor(TEST_OTHER, [wire.ace(wire.ACE_ALLOW, read, wire.WORLD)]), read, allowed)
        evaluate(context, wire.descriptor(TEST_OTHER, [wire.ace(wire.ACE_DENY, read, wire.WORLD), allow]),
                 read, attributes == 0)
    evaluate(token(user_deny_only=True), wire.descriptor(TEST_OTHER, [allow]), read, False)
    evaluate(token(user_deny_only=True, groups=[{'sid': wire.WORLD, 'attributes': wire.GROUP_ENABLED}]),
             wire.descriptor(TEST_OTHER, [deny, wire.ace(wire.ACE_ALLOW, read, wire.WORLD)]), read, False)
    for restrictions, restricted, allowed in (([TEST_USER], True, True), ([wire.WORLD], True, False),
                                              ([], True, False), ([], False, True)):
        evaluate(token(restricting=restrictions, restricted=restricted),
                 wire.descriptor(TEST_OTHER, [allow]), read, allowed)
    duplicate = token(restricting=[wire.WORLD, wire.WORLD], restricted=True)
    evaluate(duplicate, wire.descriptor(TEST_OTHER, [allow, wire.ace(wire.ACE_ALLOW, read, wire.WORLD)]), read, True)
    controls = wire.READ_CONTROL | wire.WRITE_DAC
    evaluate(plain, wire.descriptor(TEST_USER, []), controls, True)
    evaluate(plain, wire.descriptor(TEST_USER, []), read, False)
    evaluate(plain, wire.descriptor(TEST_USER, [wire.ace(wire.ACE_DENY, controls, wire.OWNER_RIGHTS)]), controls, False)
    evaluate(token(restricting=[TEST_USER], restricted=True), wire.descriptor(TEST_USER, []), controls,
             False, code=wire.NTFS_UNSUPPORTED)
    evaluate(plain, wire.descriptor(TEST_OTHER, [allow]), wire.MAXIMUM_ALLOWED, False, code=wire.NTFS_UNSUPPORTED)
    evaluate(token(groups=[{'sid': wire.WORLD, 'attributes': TEST_UNKNOWN_ATTRIBUTE}]),
             wire.descriptor(TEST_OTHER, [allow]), read, False, code=wire.NTFS_UNSUPPORTED)
    evaluate(plain, b'', read, False, code=wire.NTFS_CORRUPT)
    maximum = wire.sid((1 << wire.AUTHORITY_BITS) - 1, *([wire.DWORD_MAX] * wire.SID_SUBAUTHORITIES_MAX))
    evaluate(token(user=maximum), wire.descriptor(TEST_OTHER, [wire.ace(wire.ACE_ALLOW, read, maximum)]), read, True)
    full_context = token(groups=[{'sid': wire.WORLD, 'attributes': 0}] * wire.SID_COUNT_MAX,
                         restricting=[wire.WORLD] * wire.SID_COUNT_MAX, restricted=True)
    evaluate(full_context, wire.descriptor(TEST_OTHER, [], state='null'), read, True)

    valid = wire.request(plain, wire.descriptor(TEST_OTHER, [allow]), read)
    malformed = [rewrite_header(valid, magic=b'FAIL'), rewrite_header(valid, version=wire.SCHEMA_VERSION + 1),
                 rewrite_header(valid, flags=TEST_UNKNOWN_FLAG),
                 rewrite_header(valid, groups=wire.SID_COUNT_MAX + 1),
                 rewrite_header(valid, restricting=wire.DWORD_MAX),
                 rewrite_header(valid, descriptor=wire.DESCRIPTOR_BYTES_MAX + 1), valid + b'x']
    malformed.extend(valid[:prefix] for prefix in range(len(valid)))
    invalid_sid = wire.SID_HEADER.pack(wire.SID_REVISION, wire.SID_SUBAUTHORITIES_MAX + 1,
                                       bytes(wire.AUTHORITY_BYTES))
    malformed.append(valid[:wire.HEADER.size] + invalid_sid + valid[wire.HEADER.size + wire.SID_HEADER.size:])
    revision, count, authority = wire.SID_HEADER.unpack_from(valid, wire.HEADER.size)
    invalid_sid = wire.SID_HEADER.pack(revision + 1, count, authority)
    malformed.append(valid[:wire.HEADER.size] + invalid_sid + valid[wire.HEADER.size + wire.SID_HEADER.size:])
    for packet in malformed:
        request.write_bytes(packet)
        rejected(lambda: run_tool([str(evaluator), str(request)]), (RuntimeError,))
    rejected(lambda: run_tool([str(evaluator), str(directory)]), (RuntimeError,))
    fifo = directory / 'request.fifo'
    os.mkfifo(fifo)
    rejected(lambda: run_tool([str(evaluator), str(fifo)]), (RuntimeError,))
    rejected(lambda: bounded_read(fifo, wire.REQUEST_BYTES_MAX))
    request.write_bytes(bytes(wire.REQUEST_BYTES_MAX + 1))
    rejected(lambda: run_tool([str(evaluator), str(request)]), (RuntimeError,))


def sdk_contract():
    # Native pointers refer to one retained SDK buffer. Both structure offsets and
    # pointer stride come from ctypes; no assumption that DWORD follows host long.
    check(ct.sizeof(collector.DWORD) == wire.DWORD.size)
    packet = wire.sid_packet(TEST_USER)
    offset = collector.TokenGroups.groups.offset
    sid_offset = offset + ct.sizeof(collector.SidAndAttributes)
    buffer = ct.create_string_buffer(sid_offset + len(packet))
    ct.memmove(ct.addressof(buffer) + sid_offset, packet, len(packet))
    collector.DWORD.from_buffer(buffer).value = 1
    entry = collector.SidAndAttributes.from_buffer(buffer, offset)
    entry.sid, entry.attributes = ct.addressof(buffer) + sid_offset, wire.GROUP_ENABLED
    check(collector.native_groups(buffer, len(buffer)) == [{'sid': TEST_USER, 'attributes': wire.GROUP_ENABLED}])
    for pointer in (None, ct.addressof(buffer) - 1, ct.addressof(buffer) + len(buffer)):
        entry.sid = pointer
        rejected(lambda: collector.native_groups(buffer, len(buffer)))
    entry.sid = ct.addressof(buffer) + sid_offset
    rejected(lambda: collector.native_groups(buffer, len(buffer) - 1))
    collector.DWORD.from_buffer(buffer).value = wire.SID_COUNT_MAX + 1
    rejected(lambda: collector.native_groups(buffer, len(buffer)))
    collector.DWORD.from_buffer(buffer).value = 1
    invalid = wire.SID_HEADER.pack(wire.SID_REVISION, wire.SID_SUBAUTHORITIES_MAX + 1,
                                   bytes(wire.AUTHORITY_BYTES))
    ct.memmove(entry.sid, invalid, len(invalid))
    rejected(lambda: collector.native_groups(buffer, len(buffer)))
    privileges = ct.create_string_buffer(ct.sizeof(collector.TokenPrivileges))
    collector.DWORD.from_buffer(privileges).value = collector.PRIVILEGES_MAX + 1
    rejected(lambda: collector.native_privileges(privileges, len(privileges)))
    collector.DWORD.from_buffer(privileges).value = 0
    check(collector.native_privileges(privileges, len(privileges)) == [])
    user = {'sid': TEST_USER, 'attributes': 0}
    groups = [{'sid': wire.WORLD, 'attributes': wire.GROUP_ENABLED},
              {'sid': wire.HIGH_INTEGRITY, 'attributes': wire.GROUP_INTEGRITY | wire.GROUP_ENABLED}]
    projected = collector.projected_token(user, groups, [], False)
    check(projected['groups'] == [groups[0]] and len(groups) == 2)
    rejected(lambda: collector.projected_token(user, groups, [], True))
    rejected(lambda: collector.projected_token(user, groups, [groups[0]], False))
    rejected(lambda: collector.projected_token({'sid': TEST_USER, 'attributes': TEST_UNKNOWN_ATTRIBUTE}, groups, [], False))

    # Exercise the SDK-facing wrapper itself with adversarial API outputs. The
    # injected provider is never used as Windows provenance or an access oracle.
    api = collector.WindowsAPI.__new__(collector.WindowsAPI)
    state = {'error': collector.ERROR_SUCCESS, 'success': False, 'privileges': 0}
    api.get_error = lambda: state['error']
    api.set_error = lambda value: state.update(error=value)

    def native_check(sd, handle, desired, mapping, used, needed, granted, allowed):
        ct.cast(granted, ct.POINTER(collector.DWORD)).contents.value = wire.FILE_READ_DATA
        ct.cast(allowed, ct.POINTER(collector.BOOL)).contents.value = True
        ct.cast(used, ct.POINTER(collector.PrivilegeSet)).contents.count = state['privileges']
        state['error'] = TEST_ERROR
        return state['success']

    api.security = SimpleNamespace(MapGenericMask=lambda mask, mapping: None, AccessCheck=native_check)
    observed = api.check(1, wire.descriptor(TEST_OTHER, []), wire.FILE_READ_DATA)
    check(not observed['api_success'] and observed['error'] == TEST_ERROR and
          observed['allowed'] is None and observed['granted'] is None and observed['privileges_used'] is None)
    state['success'] = True
    observed = api.check(1, wire.descriptor(TEST_OTHER, []), wire.FILE_READ_DATA)
    check(observed['api_success'] and observed['allowed'] and observed['error'] == collector.ERROR_SUCCESS)
    state['privileges'] = collector.PRIVILEGES_MAX + 1
    rejected(lambda: api.check(1, wire.descriptor(TEST_OTHER, []), wire.FILE_READ_DATA))

    def information(handle, kind, output, size, returned):
        ct.cast(returned, ct.POINTER(collector.DWORD)).contents.value = state['length']
        state['error'] = collector.ERROR_INSUFFICIENT_BUFFER
        return output is not None

    api.security.GetTokenInformation = information
    state['length'] = collector.TOKEN_INFORMATION_BYTES_MAX + 1
    rejected(lambda: api.information(1, collector.TOKEN_USER_CLASS))
    state['length'] = ct.sizeof(collector.SidAndAttributes)
    returned, length = api.information(1, collector.TOKEN_USER_CLASS)
    check(length == ct.sizeof(collector.SidAndAttributes) and len(returned) == length)

    def oversized_return(handle, kind, output, size, returned):
        ct.cast(returned, ct.POINTER(collector.DWORD)).contents.value = state['length'] + (1 if output is not None else 0)
        state['error'] = collector.ERROR_INSUFFICIENT_BUFFER
        return output is not None

    api.security.GetTokenInformation = oversized_return
    rejected(lambda: api.information(1, collector.TOKEN_USER_CLASS))

    def duplicate(existing, desired, attributes, level, kind, handle):
        check(desired == (collector.TOKEN_QUERY | collector.TOKEN_DUPLICATE))
        check(attributes is None and level == collector.SECURITY_IMPERSONATION and kind == collector.TOKEN_IMPERSONATION)
        ct.cast(handle, ct.POINTER(collector.HANDLE)).contents.value = 1
        return True

    api.security.DuplicateTokenEx = duplicate
    check(api.duplicate(1).value == 1)

    def restricted(existing, flags, disable_count, disabled, delete_count, deleted,
                   restricting_count, restricting, handle):
        check(flags == collector.DISABLE_MAX_PRIVILEGE and delete_count == 0 and deleted is None)
        check(disable_count == 1 and restricting_count == 2)
        check(disabled[0].attributes == 0 and wire.decode_sid(ct.string_at(disabled[0].sid, len(packet))) == TEST_USER)
        for index in range(restricting_count):
            world = wire.sid_packet(wire.WORLD)
            check(restricting[index].attributes == 0 and ct.string_at(restricting[index].sid, len(world)) == world)
        ct.cast(handle, ct.POINTER(collector.HANDLE)).contents.value = 1
        return True

    api.security.CreateRestrictedToken = restricted
    check(api.restrict(1, disable=[TEST_USER], restricting=[wire.WORLD, wire.WORLD]).value == 1)
    if sys.platform != 'win32':
        rejected(collector.WindowsAPI)


class FakeAPI:
    """Intentionally coarse decisions test reporting; they are not Windows answers."""
    def __init__(self, fail=None):
        self.handles, self.created, self.closed = {}, [], []
        self.fail, self.calls = fail, 0

    def retain(self, native):
        handle = len(self.created) + 1
        self.created.append(handle)
        self.handles[handle] = deepcopy(native)
        return handle

    def open_process_token(self):
        native = {'user': {'sid': TEST_USER, 'attributes': 0},
                  'groups': [{'sid': wire.WORLD, 'attributes': wire.GROUP_ENABLED | wire.GROUP_OWNER},
                             {'sid': TEST_OTHER, 'attributes': 0},
                             {'sid': wire.HIGH_INTEGRITY, 'attributes': wire.GROUP_INTEGRITY | wire.GROUP_ENABLED}],
                  'restricting': [], 'privileges': [], 'is_restricted': False}
        return self.retain(native)

    def duplicate(self, handle):
        if self.fail == 'duplicate':
            raise OSError(TEST_ERROR, 'Injected duplicate failure')
        return self.retain(self.handles[handle])

    def restrict(self, handle, *, disable=(), restricting=()):
        native = deepcopy(self.handles[handle])
        for entry in [native['user'], *native['groups']]:
            if entry['sid'] in disable:
                entry['attributes'] = ((entry['attributes'] | wire.GROUP_DENY_ONLY) & ~wire.GROUP_ENABLED)
        native['restricting'] = [{'sid': sid, 'attributes': wire.GROUP_ENABLED} for sid in restricting]
        native['is_restricted'] = bool(restricting)
        return self.retain(native)

    def close(self, handle):
        check(handle not in self.closed)
        self.closed.append(handle)
        del self.handles[handle]
        if self.fail == 'close':
            raise OSError(TEST_ERROR, 'Injected close failure')

    def context(self, handle):
        native = deepcopy(self.handles[handle])
        return {'token': collector.projected_token(native['user'], native['groups'], native['restricting'],
                                                    native['is_restricted']), 'native': native}

    def check(self, handle, descriptor, desired):
        self.calls += 1
        if self.fail == 'check' and self.calls % 2 == 0:
            raise OSError(TEST_ERROR, 'Injected acquisition failure')
        mapped = wire.FILE_GENERIC_READ if desired == wire.GENERIC_READ else desired
        # No rights granted: an independent fake deliberately produces both
        # matches and mismatches, so neither result can certify native behavior.
        return {'api_success': self.fail != 'api', 'error': TEST_ERROR if self.fail == 'api' else 0,
                'mapped': mapped, 'allowed': None if self.fail == 'api' else False,
                'granted': None if self.fail == 'api' else 0,
                'privileges_used': None if self.fail == 'api' else []}


def corpus_contract(evaluator, directory):
    fake = FakeAPI()
    rejected(lambda: collector.capture(fake, directory / 'false-native'))
    check(not (directory / 'false-native').exists())
    corpus = directory / 'corpus'
    manifest = collector.capture(fake, corpus, synthetic=True)
    check(manifest['acquisition_status'] == 'complete' and len(manifest['contexts']) == len(collector.CONTEXT_IDS))
    check(len(manifest['cases']) == 24 * len(collector.CONTEXT_IDS))
    check(fake.created == sorted(fake.closed) and not fake.handles)
    check(manifest['contexts'][1]['token']['user_deny_only'] and not manifest['contexts'][1]['token']['restricted'])
    check(len(manifest['contexts'][-1]['token']['restricting']) == 2)
    path = corpus / 'manifest.json'
    original = path.read_bytes()
    report = verifier.verify(path, evaluator, directory / 'report')
    check(report['status'] == 'gaps' and not report['native_dacl_vectors_verified'] and
          not report['full_authorization_qualified'] and report['manifest_unchanged'])
    check(report['counts']['passed'] > 0 and report['counts']['failed'] > 0 and
          report['counts']['unsupported'] > 0 and report['counts']['out_of_plane'] == len(collector.CONTEXT_IDS))
    check(sum(report['counts'].values()) == len(manifest['cases']) and path.read_bytes() == original)
    rejected(lambda: verifier.verify(path, evaluator, directory / 'report'), (OSError,))

    def altered(change):
        candidate = deepcopy(manifest)
        change(candidate)
        path.write_text(json.dumps(candidate), encoding='utf-8')
        rejected(lambda: verifier.validate_manifest(path))
        path.write_bytes(original)

    altered(lambda value: value['cases'].pop())
    altered(lambda value: value['contexts'].pop())
    altered(lambda value: value['cases'].append(deepcopy(value['cases'][0])))
    altered(lambda value: value['cases'][0].update(descriptor_sha256='0' * 64))
    altered(lambda value: value['cases'][0].update(descriptor_base64='!'))
    altered(lambda value: value['cases'][0].update(desired=True))
    altered(lambda value: value['cases'][0].update(scope='probe'))
    altered(lambda value: value.update(probe_owner_group=None))
    altered(lambda value: value['contexts'][0]['token'].update(groups=[]))
    altered(lambda value: value['contexts'][0]['construction'].update(flags=0))
    altered(lambda value: value['cases'][0]['native'].update(api_success=False))
    altered(lambda value: value['cases'][0]['native'].update(allowed=False, granted=wire.FILE_READ_DATA))
    altered(lambda value: value.update(provenance=collector.NATIVE_PROVENANCE))
    path.write_text('{"schema_version":1,"schema_version":1}', encoding='utf-8')
    rejected(lambda: verifier.validate_manifest(path))
    path.write_bytes(original)
    for failure in ('duplicate', 'check', 'close', 'api'):
        api = FakeAPI(failure)
        collected = collector.capture(api, directory / failure, synthetic=True)
        check(sorted(api.created) == sorted(api.closed) and not api.handles)
        check(collected['acquisition_status'] == ('complete' if failure == 'api' else 'partial'))
        observed = verifier.verify(directory / failure / 'manifest.json', evaluator, directory / (failure + '-report'))
        check(observed['status'] == 'gaps' and not observed['native_dacl_vectors_verified'])
        if failure == 'api':
            check(observed['counts']['oracle_errors'] == len(collected['cases']) and
                  observed['counts']['passed'] == observed['counts']['failed'] == 0)
        else:
            check(bool(observed['acquisition_errors']))


def subprocess_contract():
    rejected(lambda: run_tool([sys.executable, '-c', 'import time; time.sleep(1)'], timeout=TEST_TIMEOUT_SECONDS), (TimeoutError,))
    for target in ('stdout', 'stderr'):
        rejected(lambda: run_tool([sys.executable, '-c', f'import sys; sys.{target}.write("x" * {TEST_OUTPUT_BYTES})']))
    check(run_tool([sys.executable, '-c', 'print("ok")']) == b'ok\n')


def main():
    evaluator = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='ntfs-access-contract-') as temporary:
        directory = Path(temporary)
        core_contract(evaluator, directory)
        sdk_contract()
        corpus_contract(evaluator, directory)
        subprocess_contract()
    print(f'PASS: {checks} access transport, SDK span, token acquisition, cleanup and reporting contracts; '
          'synthetic oracle only, no Windows qualification')


if __name__ == '__main__':
    main()
