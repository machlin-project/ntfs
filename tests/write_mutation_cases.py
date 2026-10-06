#!/usr/bin/env python3
"""Author independent byte expectations for one ordinary mutation test batch."""
from pathlib import Path
import argparse
import hashlib
import json
import struct

PAYLOAD_BYTES = 65537
WRITE_OFFSET = 257
GROW_BYTES = 299999
SHRINK_BYTES = 19
REGROW_BYTES = WRITE_OFFSET + PAYLOAD_BYTES
REPLACEMENT_BYTES = 23
PATTERN_MULTIPLIER = 37
PATTERN_BIAS = 11
REPLACEMENT_MULTIPLIER = 13
REPLACEMENT_BIAS = 5
CHILDREN = 96
NAME_UNITS = 200
REUSE_OPERATIONS = 512
SD_SELF_RELATIVE = 0x8000
SD_DACL_PRESENT = 0x0004
SD_DACL_AUTO_INHERITED = 0x0400
ACE_INHERITED = 0x10
OBJECT_INHERIT = 0x01
CONTAINER_INHERIT = 0x02
INHERIT_ONLY = 0x08
NO_PROPAGATE = 0x04
ALLOW, DENY = 0, 1
FULL_ACCESS = 0x001f01ff
READ_ACCESS = 0x001200a9
LIST_ACCESS = 0x001200a9
WRITE_ACCESS = 0x00000002
DESCRIPTOR = struct.Struct('<BBHIIII')
ACL = struct.Struct('<BBHHH')
ACE = struct.Struct('<BBHI')
SID = struct.Struct('<BB6s')
DWORD = struct.Struct('<I')
SECURITY_DESCRIPTOR_TYPE = 0x50


def sid(authority, *subauthorities):
    return (SID.pack(1, len(subauthorities), authority.to_bytes(6, 'big')) +
            b''.join(DWORD.pack(value) for value in subauthorities))


def descriptor(rows, inherited=False):
    owner, group = sid(5, 32, 544), sid(5, 18)
    entries = b''.join(ACE.pack(kind, flags, ACE.size + len(trustee), mask) + trustee
                       for kind, flags, mask, trustee in rows)
    body = ACL.pack(2, 0, ACL.size + len(entries), len(rows), 0) + entries
    owner_offset = DESCRIPTOR.size + len(body)
    group_offset = owner_offset + len(owner)
    control = SD_SELF_RELATIVE | SD_DACL_PRESENT
    if inherited:
        control |= SD_DACL_AUTO_INHERITED
    return (DESCRIPTOR.pack(1, 0, control, owner_offset, group_offset, 0,
                            DESCRIPTOR.size) + body + owner + group)


def security_cases():
    system, users, authenticated = sid(5, 18), sid(5, 32, 545), sid(5, 11)
    administrator = sid(5, 32, 544)
    creator_owner = sid(3, 0)
    propagation = OBJECT_INHERIT | CONTAINER_INHERIT
    parent = [(DENY, 0, WRITE_ACCESS, users),
              (ALLOW, propagation, FULL_ACCESS, system),
              (ALLOW, OBJECT_INHERIT, READ_ACCESS, authenticated),
              (ALLOW, CONTAINER_INHERIT, LIST_ACCESS, users),
              (ALLOW, propagation | NO_PROPAGATE, FULL_ACCESS, administrator),
              (ALLOW, propagation, FULL_ACCESS, creator_owner)]
    # These literal child ACE rows are independent expected outcomes, including
    # creator substitution and its separate propagation-only container entry.
    directory = [(ALLOW, propagation | ACE_INHERITED, FULL_ACCESS, system),
                 (ALLOW, OBJECT_INHERIT | INHERIT_ONLY | ACE_INHERITED,
                  READ_ACCESS, authenticated),
                 (ALLOW, CONTAINER_INHERIT | ACE_INHERITED, LIST_ACCESS, users),
                 (ALLOW, ACE_INHERITED, FULL_ACCESS, administrator),
                 (ALLOW, ACE_INHERITED, FULL_ACCESS, administrator),
                 (ALLOW, propagation | INHERIT_ONLY | ACE_INHERITED,
                  FULL_ACCESS, creator_owner)]
    child_file = [(ALLOW, ACE_INHERITED, FULL_ACCESS, system),
                  (ALLOW, ACE_INHERITED, READ_ACCESS, authenticated),
                  (ALLOW, ACE_INHERITED, FULL_ACCESS, administrator)]
    direct_file = child_file[:-1] + [
        (ALLOW, ACE_INHERITED, FULL_ACCESS, administrator),
        (ALLOW, ACE_INHERITED, FULL_ACCESS, administrator)]
    return {'parent-security.bin': descriptor(parent),
            'directory-security.bin': descriptor(directory, True),
            'file-security.bin': descriptor(direct_file, True),
            'child-file-security.bin': descriptor(child_file, True)}

def author(directory, source=None):
    directory.mkdir(parents=True, exist_ok=True)
    payload = bytes((position * PATTERN_MULTIPLIER + PATTERN_BIAS) & 0xff
                    for position in range(PAYLOAD_BYTES))
    grown = bytes(WRITE_OFFSET) + payload
    resized = grown + bytes(GROW_BYTES - len(grown))
    shrunk = resized[:SHRINK_BYTES]
    regrown = shrunk + bytes(REGROW_BYTES - len(shrunk))
    replacement = bytes((position * REPLACEMENT_MULTIPLIER + REPLACEMENT_BIAS) & 0xff
                        for position in range(REPLACEMENT_BYTES))
    bodies = {'payload.bin': payload, 'written.bin': grown, 'grown.bin': resized,
              'shrunk.bin': shrunk, 'regrown.bin': regrown,
              'replacement.bin': replacement, 'empty.bin': b''}
    bodies.update(security_cases())
    names = [f'child-{index:04d}-' + 'n' * (NAME_UNITS - len(f'child-{index:04d}-'))
             for index in range(CHILDREN)]
    assert len(set(names)) == CHILDREN and all(len(name) == NAME_UNITS for name in names)
    for name, data in bodies.items():
        (directory / name).write_bytes(data)
    (directory / 'children.rows').write_text('\n'.join(names) + '\n')
    if source is not None:
        import fixtures as f
        import filename_storage as storage
        image = bytearray(source.read_bytes())
        first = f.MFT_LCN * f.CLUSTER + f.ROOT_RECORD * f.RECORD
        header, attributes = storage.record_parts(image[first:first + f.RECORD])
        index = next(index for index, attribute in enumerate(attributes)
                     if storage.attr_header(attribute)['type'] == SECURITY_DESCRIPTOR_TYPE)
        instance = storage.attr_header(attributes[index])['instance']
        attributes[index] = f.resident(SECURITY_DESCRIPTOR_TYPE,
                                      bodies['parent-security.bin'], instance)
        f.put_record(image, f.ROOT_RECORD,
                     storage.encoded_record(f.ROOT_RECORD, attributes, header))
        (directory / 'source.img').write_bytes(image)
    manifest = dict(writeOffset=WRITE_OFFSET, payloadBytes=PAYLOAD_BYTES,
                    growBytes=GROW_BYTES, shrinkBytes=SHRINK_BYTES,
                    regrowBytes=REGROW_BYTES, children=CHILDREN,
                    childNameUnits=NAME_UNITS, reuseOperations=REUSE_OPERATIONS,
                    bytes={name: dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                           for name, data in bodies.items()},
                    requiredScenarios=['resident-growth-and-storage-conversion',
                        'fragmented-allocation-and-zero-gap', 'shrink-and-zero-regrowth',
                        'cross-directory-move-and-replacement', 'file-and-directory-removal',
                        'MFT-generation-reuse', 'directory-index-split-and-MFT-growth',
                        'full-space-and-preparation-unchanged', 'writer-and-recovery-interruptions',
                        'sustained-journal-reuse-and-wrap'],
                    creationOwnerAndGroup='parent',
                    testsQualified=False, implementedMutationsQualified=False)
    (directory / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('stamp', nargs='?', type=Path)
    parser.add_argument('--source', type=Path)
    args = parser.parse_args()
    author(args.output, args.source)
    if args.stamp is not None:
        args.stamp.write_text('independent ordinary mutation expectations\n')
