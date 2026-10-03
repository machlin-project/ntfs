"""Original diagnostic transport and independent MS-DTYP fixture authors.

This is test tooling, not an identity mapper or production authorization API.
Native observations retain original descriptor bytes and attributed token SIDs.
"""
import struct

SCHEMA_VERSION = 1
MAGIC = b'NTAC'
HEADER = struct.Struct('<4s6I')
DWORD = struct.Struct('<I')
SID_HEADER = struct.Struct('BB6s')
SD_HEADER = struct.Struct('<BBH4I')
ACL_HEADER = struct.Struct('<BBHHH')
ACE_HEADER = struct.Struct('<BBH')
SID_REVISION = 1
SD_REVISION = 1
ACL_REVISION = 2
BITS_PER_BYTE = 8
AUTHORITY_BYTES = 6
AUTHORITY_BITS = AUTHORITY_BYTES * BITS_PER_BYTE
SID_SUBAUTHORITIES_MAX = 15
SID_COUNT_MAX = 1024
DESCRIPTOR_BYTES_MAX = 1024 * 1024
REQUEST_BYTES_MAX = 2 * 1024 * 1024
DWORD_MAX = (1 << 32) - 1
WORD_MAX = (1 << 16) - 1
USER_DENY_ONLY = 1
RESTRICTED = 2
SD_SELF_RELATIVE = 0x8000
SD_DACL_PRESENT = 0x0004
SD_SACL_PRESENT = 0x0010
ACE_ALLOW = 0x00
ACE_DENY = 0x01
ACE_INHERIT_ONLY = 0x08
ACE_MANDATORY_LABEL = 0x11
LABEL_NO_READ_UP = 0x00000002
GROUP_ENABLED = 0x00000004
GROUP_OWNER = 0x00000008
GROUP_DENY_ONLY = 0x00000010
GROUP_INTEGRITY = 0x00000020
GROUP_INTEGRITY_ENABLED = 0x00000040
INTEGRITY_ATTRIBUTES = GROUP_INTEGRITY | GROUP_INTEGRITY_ENABLED
FILE_READ_DATA = 0x00000001
FILE_WRITE_DATA = 0x00000002
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
MAXIMUM_ALLOWED = 0x02000000
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000
# Independent published SDK values, not calculated with the core's macros.
FILE_GENERIC_READ = 0x00120089
FILE_GENERIC_WRITE = 0x00120116
FILE_GENERIC_EXECUTE = 0x001200a0
FILE_ALL_ACCESS = 0x001f01ff
NTFS_OK = 0
NTFS_CORRUPT = 2
NTFS_UNSUPPORTED = 3


def unsigned(value, maximum=DWORD_MAX):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('Invalid unsigned wire value')
    return value


def boolean(value):
    if type(value) is not bool:
        raise ValueError('Invalid boolean context')
    return value


def sid(authority, *subauthorities):
    value = {'authority': authority, 'subauthorities': list(subauthorities)}
    sid_packet(value)
    return value


# Published well-known SID components. The unrelated fixture uses arbitrary
# domain tags ("NTFS", "ACCS"), checked against native membership before use.
FIXTURE_DOMAIN_NTFS = int.from_bytes(b'NTFS', 'big')
FIXTURE_DOMAIN_ACCESS = int.from_bytes(b'ACCS', 'big')
WORLD = {'authority': 1, 'subauthorities': [0]}
OWNER_RIGHTS = {'authority': 3, 'subauthorities': [4]}
UNRELATED = {'authority': 5, 'subauthorities': [21, FIXTURE_DOMAIN_NTFS, FIXTURE_DOMAIN_ACCESS, DWORD_MAX]}
HIGH_INTEGRITY = {'authority': 16, 'subauthorities': [12288]}


def sid_packet(value):
    if not isinstance(value, dict) or set(value) != {'authority', 'subauthorities'}:
        raise ValueError('Invalid SID object')
    authority = unsigned(value['authority'], (1 << AUTHORITY_BITS) - 1)
    parts = value['subauthorities']
    if not isinstance(parts, list) or len(parts) > SID_SUBAUTHORITIES_MAX:
        raise ValueError('Invalid SID subauthority count')
    return (SID_HEADER.pack(SID_REVISION, len(parts), authority.to_bytes(AUTHORITY_BYTES, 'big')) +
            b''.join(DWORD.pack(unsigned(part)) for part in parts))


def decode_sid(packet):
    if len(packet) < SID_HEADER.size:
        raise ValueError('Truncated SID')
    revision, count, authority = SID_HEADER.unpack_from(packet)
    if (revision != SID_REVISION or count > SID_SUBAUTHORITIES_MAX or
            len(packet) != SID_HEADER.size + count * DWORD.size):
        raise ValueError('Invalid exact SID packet')
    return {'authority': int.from_bytes(authority, 'big'),
            'subauthorities': list(struct.unpack_from(f'<{count}I', packet, SID_HEADER.size))}


def group(value):
    if not isinstance(value, dict) or set(value) != {'sid', 'attributes'}:
        raise ValueError('Invalid attributed SID')
    return DWORD.pack(unsigned(value['attributes'])) + sid_packet(value['sid'])


def validate_token(token):
    if (not isinstance(token, dict) or set(token) !=
            {'user', 'user_deny_only', 'groups', 'restricting', 'restricted'}):
        raise ValueError('Invalid token context')
    sid_packet(token['user'])
    boolean(token['user_deny_only'])
    boolean(token['restricted'])
    for name in ('groups', 'restricting'):
        if not isinstance(token[name], list) or len(token[name]) > SID_COUNT_MAX:
            raise ValueError('Token vector exceeds the SID budget')
    for entry in token['groups']:
        group(entry)
    for entry in token['restricting']:
        sid_packet(entry)


def request(token, descriptor, desired):
    validate_token(token)
    if not isinstance(descriptor, bytes) or len(descriptor) > DESCRIPTOR_BYTES_MAX:
        raise ValueError('Descriptor exceeds the byte budget')
    flags = ((USER_DENY_ONLY if token['user_deny_only'] else 0) |
             (RESTRICTED if token['restricted'] else 0))
    result = (HEADER.pack(MAGIC, SCHEMA_VERSION, unsigned(desired), flags,
                          len(token['groups']), len(token['restricting']), len(descriptor)) +
              sid_packet(token['user']) + b''.join(group(entry) for entry in token['groups']) +
              b''.join(sid_packet(entry) for entry in token['restricting']) + descriptor)
    if len(result) > REQUEST_BYTES_MAX:
        raise ValueError('Request exceeds the byte budget')
    return result


def ace(kind, rights, trustee, flags=0):
    body = DWORD.pack(unsigned(rights)) + sid_packet(trustee)
    size = ACE_HEADER.size + len(body)
    return ACE_HEADER.pack(unsigned(kind, 0xff), unsigned(flags, 0xff),
                           unsigned(size, WORD_MAX)) + body


def acl(entries):
    body = b''.join(entries)
    return ACL_HEADER.pack(ACL_REVISION, 0, unsigned(ACL_HEADER.size + len(body), WORD_MAX),
                           unsigned(len(entries), WORD_MAX), 0) + body


def descriptor(owner, entries, *, state='present', sacl_entries=None):
    """Author a self-relative descriptor without canonicalizing the ACE order."""
    if state not in ('present', 'null', 'absent'):
        raise ValueError('Invalid DACL state')
    owner_bytes, group_bytes = sid_packet(owner), sid_packet(WORLD)
    owner_offset = SD_HEADER.size
    group_offset = owner_offset + len(owner_bytes)
    control, sacl_offset, dacl_offset = SD_SELF_RELATIVE, 0, 0
    body = owner_bytes + group_bytes
    if sacl_entries is not None:
        control |= SD_SACL_PRESENT
        sacl_offset = SD_HEADER.size + len(body)
        body += acl(sacl_entries)
    if state != 'absent':
        control |= SD_DACL_PRESENT
    if state == 'present':
        dacl_offset = SD_HEADER.size + len(body)
        body += acl(entries)
    return SD_HEADER.pack(SD_REVISION, 0, control, owner_offset, group_offset,
                           sacl_offset, dacl_offset) + body
