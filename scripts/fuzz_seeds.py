#!/usr/bin/env python3
"""Author independent small inputs for each parser fuzz target."""
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import fixtures as wire
from stat_fixtures import change_flags, UNKNOWN_COMPRESSION_FORMAT
from wof_fixtures import generate as generate_wof

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
    return seeds


if __name__ == '__main__':
    generate(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).touch()
