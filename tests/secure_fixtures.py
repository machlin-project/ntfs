#!/usr/bin/env python3
"""Original $Secure vectors authored from named wire fields, without driver code."""
import struct
from fixtures import (CLUSTER, RECORD, SECTOR, U16_BYTES, U64_BYTES, BYTE_BITS,
                      FILE_RECORDS, ATTRIBUTE_EXTENSION_RECORD, SI, ATTR_LIST,
                      DATA, INDEX_ROOT, INDEX_ALLOC, BITMAP, END, CHILD,
                      INDEX_LARGE, INDEX_HEADER, INDEX_ROOT_HEADER, FILE_HEADER,
                      WIRE_ALIGNMENT, FIXUP_SEQUENCE, FILE_ATTRIBUTE_REPARSE,
                      FILE_ATTRIBUTE_ENCRYPTED, ENCRYPTED, STANDARD_INFO,
                      SYSTEM_SEQUENCE, FILE_SEQUENCE, FILE_IN_USE, align, resident,
                      nonresident, file_record, standard, file_reference,
                      list_entry, protect, put_record, put_data, REPARSE_POINT,
                      reparse_value, REPARSE_TAG_SYMLINK)

SECURE_RECORD = 9
SECURITY_DESCRIPTOR_ATTRIBUTE = 0x50
INLINE_INSTANCE = 2
INLINE_LIST_INSTANCE = 3
INLINE_FIRST_LCN, INLINE_SECOND_LCN = 150, 158
INLINE_DESCRIPTOR_BUDGET = 1024 * 1024
STANDARD_LEGACY_BYTES = struct.calcsize('<QQQQIIII')
SDS_BLOCK_BYTES = 256 * 1024
SDS_PAIR_BYTES = 2 * SDS_BLOCK_BYTES
SDS_ALIGNMENT = 16
SDS_LCN = 160
SDS_SECOND_LCN = 193
SDS_PREFIX_CLUSTERS = 32
SII_LCN, SDH_LCN = 232, 234
DEEP_INDEX_LCN = 240
SECURITY_ID = 256
COLLATION_ULONG, COLLATION_SECURITY_HASH = 16, 18
SDS_INSTANCE, SII_INSTANCE, SDH_INSTANCE = 1, 2, 3
INDEX_ALLOCATION_INSTANCE, INDEX_BITMAP_INSTANCE = 4, 5
SDH_ALLOCATION_INSTANCE, SDH_BITMAP_INSTANCE = 6, 7
SDS_LIST_INSTANCE = 8
SD_SELF_RELATIVE, SD_DACL_PRESENT = 0x8000, 4
SID_REVISION, NT_AUTHORITY = 1, 5
LOCAL_SYSTEM_RID, BUILTIN_DOMAIN_RID, USERS_RID = 18, 32, 545
ACL_REVISION, ACE_ALLOW = 2, 0
READ_ACCESS_MASK = 0x00120089
DWORD_BITS, DWORD_BYTES = 32, struct.calcsize('<I')
DWORD_MAX = (1 << DWORD_BITS) - 1
UNKNOWN_RECORD_FLAG = 16
UNKNOWN_INDEX_FLAG = 16
HASH_ROTATION = 3
LARGE_DESCRIPTOR_BYTES = 9001
INDEX_BLOCK_HEADER = struct.Struct('<4sHHQQ')
VIEW_ENTRY = struct.Struct('<HHIHHHH')
LOCATOR = struct.Struct('<IIQI')
DESCRIPTOR = struct.Struct('<BBHIIII')
DESCRIPTOR_FIELDS = ('revision', 'resource_manager', 'control', 'owner', 'group', 'sacl', 'dacl')
SID_HEADER = struct.Struct('<BB6s')
FILE_HEADER_FIELDS = ('magic', 'usa_offset', 'usa_count', 'lsn', 'sequence', 'links',
                      'attrs_offset', 'flags', 'used', 'allocated', 'base', 'next_instance',
                      'reserved', 'number')
ATTR_HEADER_FIELDS = ('type', 'length', 'nonresident', 'name_length', 'name_offset', 'flags', 'instance')
ACL = struct.Struct('<BBHHH')
ACE = struct.Struct('<BBHI')
SII_KEY, SDH_KEY = struct.Struct('<I'), struct.Struct('<II')


def sd(state='present'):
    if state in ('absent', 'null'):
        control = SD_SELF_RELATIVE | (SD_DACL_PRESENT if state == 'null' else 0)
        return DESCRIPTOR.pack(1, 0, control, 0, 0, 0, 0)
    if state == 'empty':
        return (DESCRIPTOR.pack(1, 0, SD_SELF_RELATIVE | SD_DACL_PRESENT,
                                0, 0, 0, DESCRIPTOR.size) +
                ACL.pack(ACL_REVISION, 0, ACL.size, 0, 0))
    owner = struct.pack('<BB6sI', SID_REVISION, 1,
                        NT_AUTHORITY.to_bytes(6, 'big'), LOCAL_SYSTEM_RID)
    group = struct.pack('<BB6sII', SID_REVISION, 2,
                        NT_AUTHORITY.to_bytes(6, 'big'), BUILTIN_DOMAIN_RID, USERS_RID)
    ace = ACE.pack(ACE_ALLOW, 0, ACE.size + len(owner), READ_ACCESS_MASK) + owner
    acl = ACL.pack(ACL_REVISION, 0, ACL.size + len(ace), 1, 0) + ace
    owner_offset = DESCRIPTOR.size + len(acl)
    group_offset = owner_offset + len(owner)
    return (DESCRIPTOR.pack(1, 0, SD_SELF_RELATIVE | SD_DACL_PRESENT,
                            owner_offset, group_offset, 0, DESCRIPTOR.size) +
            acl + owner + group)


def checksum(payload):
    value = 0
    for (word,) in struct.iter_unpack('<I', payload[:len(payload) // DWORD_BYTES * DWORD_BYTES]):
        value = (((value << HASH_ROTATION) | (value >> (DWORD_BITS - HASH_ROTATION))) + word) & DWORD_MAX
    return value


def locator_bytes(value):
    return LOCATOR.pack(value['hash'], value['id'], value['offset'], value['length'])


def view_entry(value=None, by_hash=False, child=None, **changes):
    key = b'' if value is None else (SDH_KEY.pack(value['hash'], value['id']) if by_hash else SII_KEY.pack(value['id']))
    payload = b'' if value is None else locator_bytes(value)
    data_offset = VIEW_ENTRY.size + len(key) if payload else 0
    flags = (END if value is None else 0) | (CHILD if child is not None else 0)
    length = align(VIEW_ENTRY.size + len(key) + len(payload)) + (U64_BYTES if child is not None else 0)
    fields = dict(data_offset=data_offset, data_length=len(payload), reserved1=0,
                  length=length, key_length=len(key), flags=flags, reserved2=0)
    fields.update(changes)
    out = bytearray(length)
    VIEW_ENTRY.pack_into(out, 0, *(fields[field] for field in
                                ('data_offset', 'data_length', 'reserved1', 'length', 'key_length', 'flags', 'reserved2')))
    out[VIEW_ENTRY.size:VIEW_ENTRY.size + len(key)] = key
    out[data_offset:data_offset + len(payload)] = payload
    if child is not None:
        struct.pack_into('<Q', out, length - U64_BYTES, child)
    return bytes(out)


def view_root(content, by_hash=False, large=False, **changes):
    fields = dict(type=0, collation=COLLATION_SECURITY_HASH if by_hash else COLLATION_ULONG,
                  block_size=CLUSTER, clusters=1)
    fields.update(changes)
    return (INDEX_ROOT_HEADER.pack(*(fields[f] for f in ('type', 'collation', 'block_size', 'clusters'))) +
            INDEX_HEADER.pack(INDEX_HEADER.size, INDEX_HEADER.size + len(content),
                              INDEX_HEADER.size + len(content), INDEX_LARGE if large else 0) + content)


def view_block(vcn, content, large=False):
    out = bytearray(CLUSTER)
    usa_offset = INDEX_BLOCK_HEADER.size + INDEX_HEADER.size
    first = align(usa_offset + (CLUSTER // SECTOR + 1) * U16_BYTES)
    INDEX_BLOCK_HEADER.pack_into(out, 0, b'INDX', usa_offset, CLUSTER // SECTOR + 1, 0, vcn)
    INDEX_HEADER.pack_into(out, INDEX_BLOCK_HEADER.size, first - INDEX_BLOCK_HEADER.size,
                           first + len(content) - INDEX_BLOCK_HEADER.size,
                           CLUSTER - INDEX_BLOCK_HEADER.size, INDEX_LARGE if large else 0)
    out[first:first + len(content)] = content
    protect(out, usa_offset)
    return out


def author(output, image, contents):
    descriptors = {SECURITY_ID + i: sd(state) for i, state in enumerate(('present', 'absent', 'null', 'empty'))}
    expected = output / 'secure-expected'
    expected.mkdir(exist_ok=True)
    for security_id, payload in descriptors.items():
        (expected / f'{security_id}.bin').write_bytes(payload)

    def save(label, bodies=None, locator_changes=None, sii=None, sdh=None,
             store_changes=None, copies=None, file_id=SECURITY_ID, node_attrs=None,
             tree=None, deep=None, listed=None, record_flags=None, bitmaps=None,
             start_offset=0, legacy=False, node_extension=None, node_data=None):
        bodies = bodies or descriptors
        locators, offset = {}, start_offset
        store = bytearray(start_offset + SDS_BLOCK_BYTES)
        for security_id, payload in sorted(bodies.items()):
            value = dict(hash=checksum(payload), id=security_id, offset=offset,
                         length=LOCATOR.size + len(payload))
            locators[security_id] = value
            record = locator_bytes(value) + payload
            store[offset:offset + len(record)] = record
            offset = (offset + len(record) + SDS_ALIGNMENT - 1) // SDS_ALIGNMENT * SDS_ALIGNMENT
        last_id = max(bodies)
        used = locators[last_id]['offset'] + locators[last_id]['length']
        store += store[start_offset:used]
        if SDS_LCN * CLUSTER + len(store) > len(image):
            return
        for where, replacement in copies or ():
            store[where:where + len(replacement)] = replacement
        for security_id, fields in (locator_changes or {}).items():
            locators[security_id].update(fields)
        ordered = list(locators.values())
        hashed = sorted(ordered, key=lambda value: (value['hash'], value['id']))
        sii_root = view_root(b''.join(view_entry(value) for value in ordered) + view_entry())
        sdh_root = view_root(b''.join(view_entry(value, True) for value in hashed) + view_entry(), True)
        if sii is not None:
            sii_root = sii(locators)
        if sdh is not None:
            sdh_root = sdh(locators)
        changed = bytearray(image)
        clusters = (len(store) + CLUSTER - 1) // CLUSTER
        store_options = dict(initialized=len(store))
        store_options.update(store_changes or {})
        attrs = [standard(), nonresident(DATA, [(clusters, SDS_LCN)], len(store), SDS_INSTANCE, '$SDS', **store_options),
                 resident(INDEX_ROOT, sii_root, SII_INSTANCE, '$SII'), resident(INDEX_ROOT, sdh_root, SDH_INSTANCE, '$SDH')]
        put_data(changed, SDS_LCN, store)
        if tree:
            for by_hash, plan in tree.items():
                index_name = '$SDH' if by_hash else '$SII'
                index_lcn = SDH_LCN if by_hash else SII_LCN
                blocks = plan(locators)
                for block_index, block in enumerate(blocks):
                    put_data(changed, index_lcn + block_index, block)
                allocation_instance = SDH_ALLOCATION_INSTANCE if by_hash else INDEX_ALLOCATION_INSTANCE
                bitmap_instance = SDH_BITMAP_INSTANCE if by_hash else INDEX_BITMAP_INSTANCE
                attrs += [nonresident(INDEX_ALLOC, [(len(blocks), index_lcn)], len(blocks) * CLUSTER,
                                      allocation_instance, index_name),
                          resident(BITMAP, (bitmaps or {}).get(by_hash, bytes([(1 << len(blocks)) - 1])), bitmap_instance, index_name)]
        if deep:
            count, cycle = deep
            if (DEEP_INDEX_LCN + count) * CLUSTER > len(image):
                return
            # Base attribute order is SI, SDS, SII, SDH, independent of instances.
            attrs[2] = resident(INDEX_ROOT, view_root(view_entry(child=0), large=True), SII_INSTANCE, '$SII')
            attrs[3] = resident(INDEX_ROOT, sdh_root, SDH_INSTANCE, '$SDH')
            for block_index in range(count):
                last = block_index == count - 1
                content = (view_entry(locators[SECURITY_ID]) + view_entry()) if last and not cycle else view_entry(child=0 if last else block_index + 1)
                put_data(changed, DEEP_INDEX_LCN + block_index, view_block(block_index, content, not last or cycle))
            attrs += [nonresident(INDEX_ALLOC, [(count, DEEP_INDEX_LCN)], count * CLUSTER, INDEX_ALLOCATION_INSTANCE, '$SII'),
                      resident(BITMAP, ((1 << count) - 1).to_bytes((count + BYTE_BITS - 1) // BYTE_BITS, 'little'), INDEX_BITMAP_INSTANCE, '$SII')]
        if listed:
            entries = list_entry(file_reference(SECURE_RECORD), 0, 0, SI)
            entries += list_entry(file_reference(SECURE_RECORD), SDS_INSTANCE, 0, DATA, '$SDS')
            entries += list_entry(file_reference(SECURE_RECORD), SII_INSTANCE, 0, INDEX_ROOT, '$SII')
            entries += list_entry(file_reference(SECURE_RECORD), SDH_INSTANCE, 0, INDEX_ROOT, '$SDH')
            ext_sequence = FILE_SEQUENCE + 1 if listed == 'stale' else FILE_SEQUENCE
            entries += list_entry(file_reference(ATTRIBUTE_EXTENSION_RECORD, ext_sequence), SDS_INSTANCE, SDS_PREFIX_CLUSTERS, DATA, '$SDS')
            attrs[1] = nonresident(DATA, [(SDS_PREFIX_CLUSTERS, SDS_LCN)], len(store), SDS_INSTANCE, '$SDS', allocated=clusters * CLUSTER, **store_options)
            attrs.insert(1, resident(ATTR_LIST, entries, SDS_LIST_INSTANCE))
            base = file_reference(FILE_RECORDS['hello.txt']) if listed == 'base' else file_reference(SECURE_RECORD)
            put_record(changed, ATTRIBUTE_EXTENSION_RECORD, file_record(ATTRIBUTE_EXTENSION_RECORD,
                        [nonresident(DATA, [(clusters - SDS_PREFIX_CLUSTERS, SDS_SECOND_LCN)], 0, SDS_INSTANCE, '$SDS', lowest=SDS_PREFIX_CLUSTERS)], base=base))
            put_data(changed, SDS_SECOND_LCN, store[SDS_PREFIX_CLUSTERS * CLUSTER:])
        secure_record = file_record(SECURE_RECORD, attrs, view=True)
        if record_flags is not None:
            wire = dict(zip(FILE_HEADER_FIELDS, FILE_HEADER.unpack_from(secure_record)))
            wire['flags'] = record_flags
            altered = bytearray(secure_record)
            FILE_HEADER.pack_into(altered, 0, *(wire[field] for field in FILE_HEADER_FIELDS))
            secure_record = bytes(altered)
        put_record(changed, SECURE_RECORD, secure_record)
        hello = FILE_RECORDS['hello.txt']
        information = standard(security_id=file_id)
        if legacy:
            value = STANDARD_INFO.pack(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            information = resident(SI, value[:STANDARD_LEGACY_BYTES])
        if node_extension is not None:
            put_record(changed, ATTRIBUTE_EXTENSION_RECORD, node_extension)
        put_record(changed, hello, file_record(hello, [information, *(node_attrs if node_attrs is not None else [resident(DATA, contents['hello.txt'], 1)])]))
        for lcn, payload in node_data or ():
            put_data(changed, lcn, payload)
        (output / f'secure-{label}.img').write_bytes(changed)

    save('resident')
    save('listed', listed='valid')
    save('stale', listed='stale')
    save('wrong-base', listed='base')
    save('maximum-id', bodies={DWORD_MAX: sd()}, file_id=DWORD_MAX)
    large_payload = sd() + bytes(LARGE_DESCRIPTOR_BYTES - len(sd()) - 1) + b'\x5a'
    save('large', bodies={SECURITY_ID: large_payload})
    (expected / 'large.bin').write_bytes(large_payload)
    maximum_payload = sd() + bytes(SDS_BLOCK_BYTES - LOCATOR.size - len(sd()))
    save('maximum-descriptor', bodies={SECURITY_ID: maximum_payload})
    (expected / 'maximum.bin').write_bytes(maximum_payload)
    save('second-pair', bodies={SECURITY_ID: sd()}, start_offset=SDS_PAIR_BYTES)
    collision_first = sd() + bytes(2 * DWORD_BYTES)
    changed_owner = bytearray(sd())
    descriptor_fields = dict(zip(DESCRIPTOR_FIELDS, DESCRIPTOR.unpack_from(changed_owner)))
    struct.pack_into('<I', changed_owner, descriptor_fields['owner'] + SID_HEADER.size, LOCAL_SYSTEM_RID + 1)
    prefix = bytes(changed_owner) + struct.pack('<I', 1)
    prefix_hash = checksum(prefix)
    rotated = ((prefix_hash << HASH_ROTATION) | (prefix_hash >> (DWORD_BITS - HASH_ROTATION))) & DWORD_MAX
    correction = (checksum(collision_first) - rotated) & DWORD_MAX
    collision_second = prefix + struct.pack('<I', correction)
    assert collision_first != collision_second and checksum(collision_first) == checksum(collision_second)
    save('same-hash', bodies={SECURITY_ID: collision_first, SECURITY_ID + 1: collision_second})
    (expected / f'same-hash-{SECURITY_ID}.bin').write_bytes(collision_first)
    (expected / f'same-hash-{SECURITY_ID + 1}.bin').write_bytes(collision_second)
    save('zero-id', file_id=0)
    inline = resident(SECURITY_DESCRIPTOR_ATTRIBUTE, sd(), INLINE_INSTANCE)
    plain_data = resident(DATA, contents['hello.txt'], 1)
    save('inline', file_id=0, node_attrs=[inline, plain_data])
    save('inline-legacy', legacy=True, node_attrs=[inline, plain_data])
    save('inline-null', file_id=0, node_attrs=[resident(SECURITY_DESCRIPTOR_ATTRIBUTE, sd('null'), INLINE_INSTANCE), plain_data])
    save('inline-empty', file_id=0, node_attrs=[resident(SECURITY_DESCRIPTOR_ATTRIBUTE, sd('empty'), INLINE_INSTANCE), plain_data])
    save('inline-missing', legacy=True)
    save('inline-zero', file_id=0, node_attrs=[resident(SECURITY_DESCRIPTOR_ATTRIBUTE, b'', INLINE_INSTANCE), plain_data])
    save('inline-short', file_id=0, node_attrs=[resident(SECURITY_DESCRIPTOR_ATTRIBUTE, sd()[:DESCRIPTOR.size - 1], INLINE_INSTANCE), plain_data])
    save('inline-duplicate', file_id=0, node_attrs=[inline, resident(SECURITY_DESCRIPTOR_ATTRIBUTE, sd(), INLINE_INSTANCE + 1), plain_data])
    save('inline-nonresident', file_id=0, node_attrs=[nonresident(SECURITY_DESCRIPTOR_ATTRIBUTE, [(1, INLINE_FIRST_LCN)], len(sd()), INLINE_INSTANCE), plain_data], node_data=[(INLINE_FIRST_LCN, sd())])
    save('inline-uninitialized', file_id=0, node_attrs=[nonresident(SECURITY_DESCRIPTOR_ATTRIBUTE, [(1, INLINE_FIRST_LCN)], len(sd()), INLINE_INSTANCE, initialized=len(sd()) - 1), plain_data])
    save('inline-oversized', file_id=0, node_attrs=[nonresident(SECURITY_DESCRIPTOR_ATTRIBUTE, [(INLINE_DESCRIPTOR_BUDGET // CLUSTER + 1, SDS_LCN)], INLINE_DESCRIPTOR_BUDGET + 1, INLINE_INSTANCE), plain_data])
    save('id-no-fallback', file_id=SECURITY_ID - 1, node_attrs=[inline, plain_data])
    hello = FILE_RECORDS['hello.txt']
    node_list = list_entry(file_reference(hello), 0, 0, SI)
    node_list += list_entry(file_reference(hello), 1, 0, DATA)
    node_list += list_entry(file_reference(ATTRIBUTE_EXTENSION_RECORD), INLINE_INSTANCE, 0, SECURITY_DESCRIPTOR_ATTRIBUTE)
    node_extension = file_record(ATTRIBUTE_EXTENSION_RECORD, [inline], base=file_reference(hello))
    save('inline-listed', file_id=0, node_attrs=[resident(ATTR_LIST, node_list, INLINE_LIST_INSTANCE), plain_data], node_extension=node_extension)
    fragmented_list = list_entry(file_reference(hello), 0, 0, SI)
    fragmented_list += list_entry(file_reference(hello), INLINE_INSTANCE, 0, SECURITY_DESCRIPTOR_ATTRIBUTE)
    fragmented_list += list_entry(file_reference(ATTRIBUTE_EXTENSION_RECORD), INLINE_INSTANCE, 1, SECURITY_DESCRIPTOR_ATTRIBUTE)
    fragmented_list += list_entry(file_reference(hello), 1, 0, DATA)
    inline_clusters = (len(large_payload) + CLUSTER - 1) // CLUSTER
    fragmented_extension = file_record(ATTRIBUTE_EXTENSION_RECORD,
        [nonresident(SECURITY_DESCRIPTOR_ATTRIBUTE, [(inline_clusters - 1, INLINE_SECOND_LCN)], 0, INLINE_INSTANCE, lowest=1)], base=file_reference(hello))
    save('inline-fragmented', file_id=0,
         node_attrs=[resident(ATTR_LIST, fragmented_list, INLINE_LIST_INSTANCE),
                     nonresident(SECURITY_DESCRIPTOR_ATTRIBUTE, [(1, INLINE_FIRST_LCN)], len(large_payload), INLINE_INSTANCE, allocated=inline_clusters * CLUSTER), plain_data],
         node_extension=fragmented_extension,
         node_data=[(INLINE_FIRST_LCN, large_payload[:CLUSTER]), (INLINE_SECOND_LCN, large_payload[CLUSTER:])])
    save('missing-id', file_id=SECURITY_ID - 1)
    save('unknown-record-flag', record_flags=FILE_IN_USE | UNKNOWN_RECORD_FLAG)
    encrypted = bytearray(resident(DATA, contents['hello.txt'], 1))
    # Attribute flags are named through the independently specified header.
    from fixtures import ATTR_HEADER
    fields = dict(zip(ATTR_HEADER_FIELDS, ATTR_HEADER.unpack_from(encrypted)))
    fields['flags'] = ENCRYPTED
    ATTR_HEADER.pack_into(encrypted, 0, *(fields[field] for field in ATTR_HEADER_FIELDS))
    save('encrypted-file', node_attrs=[bytes(encrypted)])
    save('reparse-file', node_attrs=[resident(REPARSE_POINT, reparse_value(REPARSE_TAG_SYMLINK, '..\\target', relative=True), 1)])
    # Replace only SI flags while retaining the descriptor ID and no file data.
    rp = output / 'secure-reparse-file.img'
    changed = bytearray(rp.read_bytes())
    hello = FILE_RECORDS['hello.txt']
    put_record(changed, hello, file_record(hello, [standard(FILE_ATTRIBUTE_REPARSE), resident(REPARSE_POINT, reparse_value(REPARSE_TAG_SYMLINK, '..\\target', relative=True), 1)]))
    rp.write_bytes(changed)
    save('uninitialized', store_changes={'initialized': SDS_BLOCK_BYTES})
    original = sd()
    save('hash', copies=[(LOCATOR.size + len(original) - 1, b'\xff')])
    save('duplicate-header', copies=[(SDS_BLOCK_BYTES, b'\xff')])
    save('duplicate-body', copies=[(SDS_BLOCK_BYTES + LOCATOR.size + len(original) - 1, b'\xff')])
    invalid = bytearray(original)
    values = dict(zip(DESCRIPTOR_FIELDS, DESCRIPTOR.unpack_from(invalid)))
    values['owner'] = len(invalid) + DWORD_BYTES
    DESCRIPTOR.pack_into(invalid, 0, *(values[field] for field in DESCRIPTOR_FIELDS))
    save('descriptor', bodies={SECURITY_ID: bytes(invalid)})
    for label, fields in [('alignment', {'offset': 1}), ('secondary-offset', {'offset': SDS_BLOCK_BYTES}),
                          ('overflow', {'offset': (1 << (U64_BYTES * BYTE_BITS)) - SDS_ALIGNMENT}),
                          ('cross-block', {'offset': SDS_BLOCK_BYTES - SDS_ALIGNMENT}),
                          ('short-length', {'length': LOCATOR.size}), ('large-length', {'length': SDS_BLOCK_BYTES + 1}),
                          ('header-id', {'id': SECURITY_ID + 1}), ('header-hash', {'hash': 0})]:
        save(label, locator_changes={SECURITY_ID: fields})
    save('sdh-missing', sdh=lambda loc: view_root(view_entry(), True))
    save('sdh-mismatch', sdh=lambda loc: view_root(view_entry(dict(loc[SECURITY_ID], length=loc[SECURITY_ID]['length'] + DWORD_BYTES), True) + view_entry(), True))
    save('sii-order', sii=lambda loc: view_root(view_entry(loc[SECURITY_ID + 1]) + view_entry(loc[SECURITY_ID]) + view_entry()))
    save('sii-duplicate', sii=lambda loc: view_root(view_entry(loc[SECURITY_ID]) * 2 + view_entry()))
    save('sii-data-overlap', sii=lambda loc: view_root(view_entry(loc[SECURITY_ID], data_offset=VIEW_ENTRY.size) + view_entry()))
    save('sii-key-size', sii=lambda loc: view_root(view_entry(loc[SECURITY_ID], key_length=0) + view_entry()))
    save('sii-flags', sii=lambda loc: view_root(view_entry(loc[SECURITY_ID], flags=UNKNOWN_INDEX_FLAG) + view_entry()))
    save('sii-no-terminal', sii=lambda loc: view_root(view_entry(loc[SECURITY_ID])))
    save('sii-terminal-data', sii=lambda loc: view_root(view_entry(loc[SECURITY_ID]) + view_entry(data_length=LOCATOR.size)))
    save('sii-missing-allocation', sii=lambda loc: view_root(view_entry(child=0), large=True))
    save('sii-collation', sii=lambda loc: view_root(view_entry(loc[SECURITY_ID]) + view_entry(), collation=COLLATION_SECURITY_HASH))
    save('sii-block-size', sii=lambda loc: view_root(view_entry(loc[SECURITY_ID]) + view_entry(), block_size=CLUSTER + SECTOR))

    def tree_root(loc, by_hash=False, child=0):
        ordered = sorted(loc.values(), key=lambda value: (value['hash'], value['id']) if by_hash else value['id'])
        return view_root(view_entry(ordered[2], by_hash, child) + view_entry(child=1), by_hash, True)

    def tree_blocks(loc, by_hash=False, mode=None):
        ordered = sorted(loc.values(), key=lambda value: (value['hash'], value['id']) if by_hash else value['id'])
        left = ordered[:2] if mode != 'bounds' else [ordered[2]]
        a = view_block(0, b''.join(view_entry(value, by_hash) for value in left) + view_entry())
        b = view_block(1, view_entry(ordered[1] if mode == 'lower' else ordered[3], by_hash) + view_entry())
        if mode == 'torn':
            a[SECTOR - U16_BYTES] ^= 1
        if mode == 'vcn':
            fields = list(INDEX_BLOCK_HEADER.unpack_from(a))
            fields[-1] = 1
            INDEX_BLOCK_HEADER.pack_into(a, 0, *fields)
        if mode == 'usa':
            fields = list(INDEX_HEADER.unpack_from(a, INDEX_BLOCK_HEADER.size))
            fields[0] = INDEX_HEADER.size
            INDEX_HEADER.pack_into(a, INDEX_BLOCK_HEADER.size, *fields)
        return [a, b]

    save('tree', sii=lambda loc: tree_root(loc), sdh=lambda loc: tree_root(loc, True),
         tree={False: lambda loc: tree_blocks(loc), True: lambda loc: tree_blocks(loc, True)})
    for mode in ('bounds', 'torn', 'vcn', 'lower', 'usa'):
        save('tree-' + mode, sii=lambda loc: tree_root(loc),
             tree={False: lambda loc, mode=mode: tree_blocks(loc, mode=mode)})
    for label, bits in [('free', bytes([0])), ('short-bitmap', b'')]:
        save('tree-' + label, sii=lambda loc: tree_root(loc),
             tree={False: lambda loc: tree_blocks(loc)}, bitmaps={False: bits})
    save('tree-overflow', sii=lambda loc: tree_root(loc, child=(1 << (U64_BYTES * BYTE_BITS)) - 1),
         tree={False: lambda loc: tree_blocks(loc)})
    save('depth-limit', deep=(32, False))
    save('depth-valid', deep=(31, False))
    save('cycle', deep=(2, True))
