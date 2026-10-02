#!/usr/bin/env python3
"""Capture independent AccessCheck observations using disposable token copies.

Only in-memory authored descriptors are checked. No file ACL, process/thread
identity, privilege setting, volume or device is changed. Run with Windows CPython.
This collector is separate from the driver and never calls its decision code.
"""
import argparse
import base64
from contextlib import ExitStack
import ctypes as ct
import hashlib
import json
from pathlib import Path
import platform
import sys

import access_transport as wire

DWORD = ct.c_uint32
LONG = ct.c_int32
BOOL = ct.c_int32
HANDLE = ct.c_void_p
TOKEN_QUERY = 0x0008
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATION = 2
SECURITY_IMPERSONATION = 2
DISABLE_MAX_PRIVILEGE = 0x00000001
TOKEN_USER_CLASS = 1
TOKEN_GROUPS_CLASS = 2
TOKEN_PRIVILEGES_CLASS = 3
TOKEN_RESTRICTED_SIDS_CLASS = 11
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_SUCCESS = 0
TOKEN_INFORMATION_BYTES_MAX = 1024 * 1024
PRIVILEGES_MAX = 64
NATIVE_PROVENANCE = 'Windows AccessCheck with queried disposable impersonation tokens'
SYNTHETIC_PROVENANCE = 'Synthetic AccessCheck collector contract test; no Windows qualification'
VECTOR_SET = 'ntfs-file-dacl-v1'
CONTEXT_IDS = ('base', 'deny-user', 'deny-group', 'restrict-user', 'restrict-world',
               'restrict-duplicates')


class SidAndAttributes(ct.Structure):
    _fields_ = [('sid', ct.c_void_p), ('attributes', DWORD)]


class TokenGroups(ct.Structure):
    _fields_ = [('count', DWORD), ('groups', SidAndAttributes * 1)]


class Luid(ct.Structure):
    _fields_ = [('low', DWORD), ('high', LONG)]


class LuidAndAttributes(ct.Structure):
    _fields_ = [('luid', Luid), ('attributes', DWORD)]


class TokenPrivileges(ct.Structure):
    _fields_ = [('count', DWORD), ('privileges', LuidAndAttributes * 1)]


class PrivilegeSet(ct.Structure):
    _fields_ = [('count', DWORD), ('control', DWORD),
                ('privileges', LuidAndAttributes * PRIVILEGES_MAX)]


class GenericMapping(ct.Structure):
    _fields_ = [('read', DWORD), ('write', DWORD), ('execute', DWORD), ('all', DWORD)]


def mapping():
    return GenericMapping(wire.FILE_GENERIC_READ, wire.FILE_GENERIC_WRITE,
                          wire.FILE_GENERIC_EXECUTE, wire.FILE_ALL_ACCESS)


def checked_span(buffer, length, pointer, size):
    start = ct.addressof(buffer)
    if (not pointer or length < 0 or length > ct.sizeof(buffer) or size < 0 or
            pointer < start or pointer - start > length or size > length - (pointer - start)):
        raise ValueError('Native token pointer lies outside its returned buffer')
    return pointer - start


def native_sid(buffer, length, pointer):
    checked_span(buffer, length, pointer, wire.SID_HEADER.size)
    header = ct.string_at(pointer, wire.SID_HEADER.size)
    _, count, _ = wire.SID_HEADER.unpack(header)
    if count > wire.SID_SUBAUTHORITIES_MAX:
        raise ValueError('Native SID exceeds its subauthority limit')
    size = wire.SID_HEADER.size + count * wire.DWORD.size
    checked_span(buffer, length, pointer, size)
    return wire.decode_sid(ct.string_at(pointer, size))


def native_groups(buffer, length):
    if length < ct.sizeof(DWORD) or length > ct.sizeof(buffer):
        raise ValueError('Truncated native token group count')
    count = DWORD.from_buffer_copy(buffer).value
    offset = TokenGroups.groups.offset
    if count > wire.SID_COUNT_MAX or offset + count * ct.sizeof(SidAndAttributes) > length:
        raise ValueError('Native token group vector exceeds its returned span or budget')
    result = []
    for index in range(count):
        entry = SidAndAttributes.from_buffer_copy(buffer, offset + index * ct.sizeof(SidAndAttributes))
        result.append({'sid': native_sid(buffer, length, entry.sid),
                       'attributes': entry.attributes})
    return result


def native_privileges(buffer, length):
    if length < ct.sizeof(DWORD) or length > ct.sizeof(buffer):
        raise ValueError('Truncated native token privilege count')
    count = DWORD.from_buffer_copy(buffer).value
    offset = TokenPrivileges.privileges.offset
    if count > PRIVILEGES_MAX or offset + count * ct.sizeof(LuidAndAttributes) > length:
        raise ValueError('Native privileges exceed their returned span or budget')
    return [privilege(LuidAndAttributes.from_buffer_copy(
        buffer, offset + index * ct.sizeof(LuidAndAttributes))) for index in range(count)]


def privilege(entry):
    return {'luid_low': entry.luid.low, 'luid_high': entry.luid.high,
            'attributes': entry.attributes}


def projected_token(user, groups, restricting, restricted):
    """Retain the mandatory-plane groups separately; do not alter native attributes."""
    if type(restricted) is not bool or restricted != bool(restricting):
        raise ValueError('IsTokenRestricted disagrees with the queried restricting SID list')
    if user['attributes'] & ~wire.GROUP_DENY_ONLY:
        raise ValueError('Unmodeled native user SID attributes')
    return {'user': user['sid'], 'user_deny_only': bool(user['attributes'] & wire.GROUP_DENY_ONLY),
            'groups': [entry for entry in groups if not entry['attributes'] & wire.INTEGRITY_ATTRIBUTES],
            'restricting': [entry['sid'] for entry in restricting], 'restricted': restricted}


class WindowsAPI:
    def __init__(self):
        if sys.platform != 'win32':
            raise RuntimeError('AccessCheck acquisition requires Windows CPython')
        self.kernel = ct.WinDLL('kernel32', use_last_error=True)
        self.security = ct.WinDLL('advapi32', use_last_error=True)
        self.get_error, self.set_error = ct.get_last_error, ct.set_last_error
        self._declare(self.kernel.GetCurrentProcess, HANDLE, [])
        self._declare(self.kernel.CloseHandle, BOOL, [HANDLE])
        self._declare(self.security.OpenProcessToken, BOOL, [HANDLE, DWORD, ct.POINTER(HANDLE)])
        self._declare(self.security.DuplicateTokenEx, BOOL,
                      [HANDLE, DWORD, ct.c_void_p, ct.c_int, ct.c_int, ct.POINTER(HANDLE)])
        self._declare(self.security.CreateRestrictedToken, BOOL,
                      [HANDLE, DWORD, DWORD, ct.POINTER(SidAndAttributes), DWORD,
                       ct.POINTER(LuidAndAttributes), DWORD, ct.POINTER(SidAndAttributes),
                       ct.POINTER(HANDLE)])
        self._declare(self.security.GetTokenInformation, BOOL,
                      [HANDLE, ct.c_int, ct.c_void_p, DWORD, ct.POINTER(DWORD)])
        self._declare(self.security.IsTokenRestricted, BOOL, [HANDLE])
        self._declare(self.security.MapGenericMask, None, [ct.POINTER(DWORD), ct.POINTER(GenericMapping)])
        self._declare(self.security.AccessCheck, BOOL,
                      [ct.c_void_p, HANDLE, DWORD, ct.POINTER(GenericMapping),
                       ct.c_void_p, ct.POINTER(DWORD), ct.POINTER(DWORD), ct.POINTER(BOOL)])

    @staticmethod
    def _declare(function, result, arguments):
        function.restype, function.argtypes = result, arguments

    def error(self):
        return OSError(self.get_error(), 'Windows security API failed')

    def open_process_token(self):
        handle = HANDLE()
        if not self.security.OpenProcessToken(self.kernel.GetCurrentProcess(),
                                               TOKEN_QUERY | TOKEN_DUPLICATE, ct.byref(handle)):
            raise self.error()
        return handle

    def duplicate(self, existing):
        handle = HANDLE()
        if not self.security.DuplicateTokenEx(existing, TOKEN_QUERY | TOKEN_DUPLICATE, None,
                                              SECURITY_IMPERSONATION, TOKEN_IMPERSONATION,
                                              ct.byref(handle)):
            raise self.error()
        return handle

    def restrict(self, existing, *, disable=(), restricting=()):
        # The backing buffers stay alive through the SDK call. SDK Attributes must
        # be zero for restricting entries and are ignored for disable entries.
        def vector(sids):
            if len(sids) > wire.SID_COUNT_MAX:
                raise ValueError('Requested SID vector exceeds the token budget')
            buffers = [ct.create_string_buffer(wire.sid_packet(sid)) for sid in sids]
            entries = (SidAndAttributes * len(buffers))(
                *(SidAndAttributes(ct.addressof(buffer), 0) for buffer in buffers))
            return buffers, entries if buffers else None

        disable_buffers, disabled = vector(disable)
        restrict_buffers, restricted = vector(restricting)
        handle = HANDLE()
        if not self.security.CreateRestrictedToken(existing, DISABLE_MAX_PRIVILEGE,
                                                   len(disable_buffers), disabled, 0, None,
                                                   len(restrict_buffers), restricted, ct.byref(handle)):
            raise self.error()
        return handle

    def close(self, handle):
        if not self.kernel.CloseHandle(handle):
            raise self.error()

    def information(self, handle, kind):
        needed = DWORD()
        self.set_error(ERROR_SUCCESS)
        success = self.security.GetTokenInformation(handle, kind, None, 0, ct.byref(needed))
        if success or self.get_error() != ERROR_INSUFFICIENT_BUFFER:
            raise self.error()
        if not 0 < needed.value <= TOKEN_INFORMATION_BYTES_MAX:
            raise ValueError('Native token information exceeds the byte budget')
        buffer = ct.create_string_buffer(needed.value)
        returned = DWORD()
        if not self.security.GetTokenInformation(handle, kind, buffer, len(buffer), ct.byref(returned)):
            raise self.error()
        if not 0 < returned.value <= len(buffer):
            raise ValueError('Invalid native token information return length')
        return buffer, returned.value

    def context(self, handle):
        buffer, length = self.information(handle, TOKEN_USER_CLASS)
        if length < ct.sizeof(SidAndAttributes):
            raise ValueError('Truncated native token user')
        entry = SidAndAttributes.from_buffer_copy(buffer)
        user = {'sid': native_sid(buffer, length, entry.sid), 'attributes': entry.attributes}
        groups = native_groups(*self.information(handle, TOKEN_GROUPS_CLASS))
        restricting = native_groups(*self.information(handle, TOKEN_RESTRICTED_SIDS_CLASS))
        privileges = native_privileges(*self.information(handle, TOKEN_PRIVILEGES_CLASS))
        self.set_error(ERROR_SUCCESS)
        restricted = bool(self.security.IsTokenRestricted(handle))
        if not restricted and self.get_error() != ERROR_SUCCESS:
            raise self.error()
        token = projected_token(user, groups, restricting, restricted)
        wire.validate_token(token)
        return {'token': token, 'native': {'user': user, 'groups': groups,
                'restricting': restricting, 'privileges': privileges, 'is_restricted': restricted}}

    def check(self, handle, descriptor, desired):
        packet = ct.create_string_buffer(descriptor)
        rights, generic = DWORD(wire.unsigned(desired)), mapping()
        self.security.MapGenericMask(ct.byref(rights), ct.byref(generic))
        used = PrivilegeSet()
        needed, granted, allowed = DWORD(ct.sizeof(used)), DWORD(), BOOL()
        self.set_error(ERROR_SUCCESS)
        success = bool(self.security.AccessCheck(packet, handle, rights, ct.byref(generic),
                       ct.byref(used), ct.byref(needed), ct.byref(granted), ct.byref(allowed)))
        error = ERROR_SUCCESS if success else self.get_error()
        if success and (needed.value > ct.sizeof(used) or used.count > PRIVILEGES_MAX or
                        PrivilegeSet.privileges.offset + used.count * ct.sizeof(LuidAndAttributes) > needed.value):
            raise ValueError('AccessCheck returned an invalid privilege span')
        return {'api_success': success, 'error': error, 'mapped': rights.value,
                'allowed': bool(allowed.value) if success else None,
                'granted': granted.value if success else None,
                'privileges_used': [privilege(used.privileges[index]) for index in range(used.count)]
                                  if success else None}


def vectors(token, group_sid=None, owner_group=None):
    user = token['user']
    # An unrelated owner avoids implicit owner rights in ordinary membership cases.
    memberships = [user, *(entry['sid'] for entry in token['groups']), *token['restricting']]
    if wire.UNRELATED in memberships:
        raise ValueError('The reserved fixture owner unexpectedly matches a native SID')
    read, write = wire.FILE_READ_DATA, wire.FILE_WRITE_DATA
    controls = wire.READ_CONTROL | wire.WRITE_DAC
    result = []

    def add(name, entries, desired=read, *, owner=wire.UNRELATED, state='present', scope='dacl', sacl=None):
        result.append({'name': name, 'desired': desired, 'scope': scope,
                       'descriptor': wire.descriptor(owner, entries, state=state, sacl_entries=sacl)})

    add('allow-user', [wire.ace(wire.ACE_ALLOW, read, user)])
    add('deny-user', [wire.ace(wire.ACE_DENY, read, user), wire.ace(wire.ACE_ALLOW, read, wire.WORLD)])
    add('allow-before-deny', [wire.ace(wire.ACE_ALLOW, read, user), wire.ace(wire.ACE_DENY, read, user)])
    add('deny-before-allow', [wire.ace(wire.ACE_DENY, read, user), wire.ace(wire.ACE_ALLOW, read, user)])
    add('split-allow', [wire.ace(wire.ACE_ALLOW, read, user), wire.ace(wire.ACE_ALLOW, write, user)], read | write)
    add('allow-user-and-world', [wire.ace(wire.ACE_ALLOW, read, user), wire.ace(wire.ACE_ALLOW, read, wire.WORLD)])
    add('allow-world', [wire.ace(wire.ACE_ALLOW, read, wire.WORLD)])
    add('inherit-only', [wire.ace(wire.ACE_ALLOW, read, user, wire.ACE_INHERIT_ONLY)])
    add('generic-read', [wire.ace(wire.ACE_ALLOW, wire.FILE_GENERIC_READ, user)], wire.GENERIC_READ)
    add('generic-write-denies-read', [wire.ace(wire.ACE_DENY, wire.FILE_GENERIC_WRITE, wire.WORLD),
                                    wire.ace(wire.ACE_ALLOW, wire.FILE_GENERIC_READ, wire.WORLD)], wire.GENERIC_READ)
    add('empty', [])
    add('null', [], state='null')
    add('absent', [], state='absent')
    add('zero-request', [], 0)
    add('owner-empty-control', [], controls, owner=user,
        scope='probe' if token['restricted'] else 'dacl')
    add('owner-empty-data', [], owner=user)
    owner_scope = 'probe' if token['restricted'] else 'dacl'
    add('owner-rights-deny', [wire.ace(wire.ACE_DENY, controls, wire.OWNER_RIGHTS),
                            wire.ace(wire.ACE_ALLOW, controls, user)], controls, owner=user, scope=owner_scope)
    add('owner-rights-allow', [wire.ace(wire.ACE_ALLOW, read, wire.OWNER_RIGHTS)], owner=user, scope=owner_scope)
    add('owner-rights-inherit-only', [wire.ace(wire.ACE_DENY, controls, wire.OWNER_RIGHTS,
                                            wire.ACE_INHERIT_ONLY)], controls, owner=user, scope=owner_scope)
    add('maximum-allowed', [wire.ace(wire.ACE_ALLOW, read | write, user)], wire.MAXIMUM_ALLOWED, scope='probe')
    add('mandatory-label-boundary', [wire.ace(wire.ACE_ALLOW, read, user)], scope='boundary',
        sacl=[wire.ace(wire.ACE_MANDATORY_LABEL, wire.LABEL_NO_READ_UP, wire.HIGH_INTEGRITY)])
    if group_sid is not None:
        add('group-allow', [wire.ace(wire.ACE_ALLOW, read, group_sid)])
        add('group-deny', [wire.ace(wire.ACE_DENY, read, group_sid), wire.ace(wire.ACE_ALLOW, read, user)])
    if owner_group is not None:
        add('group-owner-empty', [], controls, owner=owner_group,
            scope='probe' if token['restricted'] else 'dacl')
    return result


def capture(api, directory, *, synthetic=False):
    """Checkpoint partial acquisition, including native API errors and missing contexts."""
    if not synthetic and (sys.platform != 'win32' or not isinstance(api, WindowsAPI)):
        raise ValueError('A substitute provider cannot claim Windows acquisition provenance')
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    manifest = {'schema_version': wire.SCHEMA_VERSION, 'vector_set': VECTOR_SET,
                'acquisition_status': 'partial',
                'provenance': SYNTHETIC_PROVENANCE if synthetic else NATIVE_PROVENANCE,
                'platform': {'system': platform.system(), 'version': platform.version(),
                             'machine': platform.machine(), 'pointer_bytes': ct.sizeof(ct.c_void_p)},
                'context_plan': list(CONTEXT_IDS), 'probe_group': None, 'probe_owner_group': None,
                'contexts': [], 'cases': [], 'errors': []}
    path = directory / 'manifest.json'

    def checkpoint():
        path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')

    checkpoint()
    try:
        with ExitStack() as owned:
            def retain(handle):
                owned.callback(api.close, handle)
                return handle

            process = retain(api.open_process_token())
            duplicate = retain(api.duplicate(process))
            base = retain(api.restrict(duplicate))
            base_context = api.context(base)
            enabled = [entry for entry in base_context['token']['groups']
                       if entry['attributes'] & wire.GROUP_ENABLED and
                       not entry['attributes'] & wire.GROUP_DENY_ONLY]
            group_sid = enabled[0]['sid'] if enabled else None
            owner_group = next((entry['sid'] for entry in enabled if entry['attributes'] & wire.GROUP_OWNER), None)
            manifest['probe_group'], manifest['probe_owner_group'] = group_sid, owner_group
            variants = [('base', {}, base),
                        ('deny-user', {'disable': [base_context['token']['user']]}, None),
                        ('deny-group', {'disable': [group_sid]} if group_sid else None, None),
                        ('restrict-user', {'restricting': [base_context['token']['user']]}, None),
                        ('restrict-world', {'restricting': [wire.WORLD]}, None),
                        ('restrict-duplicates', {'restricting': [wire.WORLD, wire.WORLD]}, None)]
            for identity, options, existing in variants:
                if options is None:
                    manifest['errors'].append({'context': identity, 'error': 'No enabled DACL group is available'})
                    checkpoint()
                    continue
                try:
                    handle = existing if existing is not None else retain(api.restrict(base, **options))
                    context = base_context if identity == 'base' else api.context(handle)
                    context['id'] = identity
                    context['construction'] = {'source': 'caller-copy' if identity == 'base' else 'base',
                        'flags': DISABLE_MAX_PRIVILEGE, 'disable': options.get('disable', []),
                        'restricting': options.get('restricting', [])}
                    manifest['contexts'].append(context)
                    for vector in vectors(context['token'], group_sid, owner_group):
                        descriptor = vector['descriptor']
                        case = {'id': identity + '/' + vector['name'], 'context': identity,
                                'scope': vector['scope'], 'desired': vector['desired'],
                                'descriptor_base64': base64.b64encode(descriptor).decode('ascii'),
                                'descriptor_sha256': hashlib.sha256(descriptor).hexdigest()}
                        case['native'] = api.check(handle, descriptor, vector['desired'])
                        manifest['cases'].append(case)
                    checkpoint()
                except (OSError, ValueError, RuntimeError) as error:
                    manifest['errors'].append({'context': identity, 'error': str(error)})
                    checkpoint()
        if not manifest['errors']:
            manifest['acquisition_status'] = 'complete'
    except (OSError, ValueError, RuntimeError) as error:
        manifest['errors'].append({'context': 'acquisition', 'error': str(error)})
    checkpoint()
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='New acquisition directory')
    args = parser.parse_args()
    try:
        api = WindowsAPI()
        manifest = capture(api, args.output)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, f'AccessCheck acquisition rejected: {error}\n')
    print(json.dumps({'acquisition_status': manifest['acquisition_status'],
                      'contexts': len(manifest['contexts']), 'cases': len(manifest['cases']),
                      'errors': len(manifest['errors'])}))
    return 0 if manifest['acquisition_status'] == 'complete' else 1


if __name__ == '__main__':
    raise SystemExit(main())
