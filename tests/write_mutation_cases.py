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
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000
FILE_GENERIC_READ = 0x00120089
FILE_GENERIC_WRITE = 0x00120116
FILE_GENERIC_EXECUTE = 0x001200a0
DESCRIPTOR = struct.Struct('<BBHIIII')
ACL = struct.Struct('<BBHHH')
ACE = struct.Struct('<BBHI')
SID = struct.Struct('<BB6s')
DWORD = struct.Struct('<I')
SECURITY_DESCRIPTOR_TYPE = 0x50
MST_HEADER = struct.Struct('<4sHH')
INDEX_BLOCK_PREFIX = struct.Struct('<4sHHQQ')
INDEX_BLOCK_FIELDS = ('magic', 'usa_offset', 'usa_count', 'lsn', 'vcn')
UNUSED_STORAGE_PROFILES = ('file-stale', 'file-torn', 'index-stale', 'index-torn',
                           'index-unused-slot', 'mft-tail-stale', 'mft-tail-torn')
EXPANDED_JOURNAL_BYTES = 1024 * 1024
HISTORY_JOURNAL_BYTES = 4 * 1024 * 1024
FIRST_USER_RECORD = 16
FIRST_ALLOCATABLE_RECORD = 24
RESERVED_STORAGE_PATTERN = 0x5c
MAX_FILE_SEQUENCE = (1 << 16) - 1
BITMAP_ALLOCATION_CLUSTERS = 2
BITMAP_UNUSED_PATTERN = 0xa6
BITMAP_STORAGE_PROFILES = ('mft', 'volume', 'both')
ANCESTOR_PROFILES = ('win32-dos', 'dos-win32', 'posix', 'win32', 'win32-dos-combined')
ANCESTOR_BAD_PROFILES = ('different-parent', 'zero-sequence', 'dos-only',
                         'duplicate-primary', 'unknown-namespace', 'self-parent',
                         'length-mismatch', 'physical-count', 'attribute-flags',
                         'named-attribute', 'missing-filename')


def directory_ancestor_images(directory, original, descriptor):
    """Author a complete directory graph with paired and single ancestor names."""
    import fixtures as f
    import filename_storage as storage
    import secure_fixtures as s

    first = f.MFT_LCN * f.CLUSTER + f.MFT_RECORD * f.RECORD
    _, mft_attributes = storage.record_parts(original[first:first + f.RECORD])
    original_bitmap = storage.resident_value(next(a for a in mft_attributes
        if storage.attr_header(a)['type'] == f.BITMAP))
    stream, _ = storage.mapping(next(a for a in mft_attributes
        if storage.attr_header(a)['type'] == f.DATA))
    graph_records = 6
    ancestor_number = next(number for number in range(FIRST_ALLOCATABLE_RECORD,
        min(stream['initialized'] // f.RECORD, len(original_bitmap) * f.BYTE_BITS) - graph_records + 1)
        if all(not original_bitmap[slot // f.BYTE_BITS] & (1 << (slot % f.BYTE_BITS))
               for slot in range(number, number + graph_records)))
    numbers = dict(ancestor=ancestor_number, left=ancestor_number + 1,
                   right=ancestor_number + 2, nested=ancestor_number + 3,
                   deep=ancestor_number + 4, file=ancestor_number + 5)
    long_name, short_name = 'AncestorDirectory', 'ANCEST~1'
    ancestor_ref = f.file_reference(numbers['ancestor'])

    def parts(image, number):
        first = f.MFT_LCN * f.CLUSTER + number * f.RECORD
        return storage.record_parts(image[first:first + f.RECORD])

    def filename(name, parent, namespace, instance):
        return f.resident(f.FILENAME, f.key(name, parent=parent,
            namespace=namespace, attributes=f.FILE_ATTRIBUTE_DIRECTORY), instance)

    for profile in ANCESTOR_PROFILES:
        image = bytearray(original)
        if profile == 'win32-dos':
            names = ((long_name, f.NAMESPACE_WIN32), (short_name, f.NAMESPACE_DOS))
        elif profile == 'dos-win32':
            names = ((short_name, f.NAMESPACE_DOS), (long_name, f.NAMESPACE_WIN32))
        else:
            namespace = {'posix': f.NAMESPACE_POSIX, 'win32': f.NAMESPACE_WIN32,
                         'win32-dos-combined': f.NAMESPACE_WIN32_DOS}[profile]
            names = ((long_name, namespace),)
        for kind, number in numbers.items():
            directory_type = kind != 'file'
            parent = {'ancestor': f.ROOT_REF, 'left': ancestor_ref, 'right': ancestor_ref,
                      'nested': f.file_reference(numbers['left']),
                      'deep': f.file_reference(numbers['nested']),
                      'file': f.file_reference(numbers['deep'])}[kind]
            children = {'ancestor': (('left', 'left'), ('right', 'right')),
                        'left': (('nested', 'nested'),), 'right': (),
                        'nested': (('deep', 'deep'),), 'deep': (('data.bin', 'file'),),
                        'file': ()}[kind]
            attributes = [f.standard(f.FILE_ATTRIBUTE_DIRECTORY if directory_type else 0,
                                     security_id=0),
                          f.resident(SECURITY_DESCRIPTOR_TYPE, descriptor, 1)]
            own_names = names if kind == 'ancestor' else ((
                'data.bin' if kind == 'file' else kind, f.NAMESPACE_POSIX),)
            for index, (name, namespace) in enumerate(own_names):
                value = f.key(name, size=0 if directory_type else len(b'child witness'),
                              parent=parent, namespace=namespace,
                              attributes=f.FILE_ATTRIBUTE_DIRECTORY if directory_type else 0)
                attributes.append(f.resident(f.FILENAME, value, index + 2))
            if directory_type:
                entries = b''.join(f.entry(name, numbers[child],
                    size=len(b'child witness') if child == 'file' else 0,
                    parent=f.file_reference(number), namespace=f.NAMESPACE_POSIX,
                    attributes=0 if child == 'file' else f.FILE_ATTRIBUTE_DIRECTORY)
                    for name, child in children) + f.entry()
                value = (f.INDEX_ROOT_HEADER.pack(f.FILENAME, f.COLLATION_FILENAME, f.CLUSTER, 1) +
                    f.INDEX_HEADER.pack(f.INDEX_HEADER.size,
                        f.INDEX_HEADER.size + len(entries), f.INDEX_HEADER.size + len(entries), 0) + entries)
                attributes.append(f.resident(f.INDEX_ROOT, value, len(attributes), '$I30'))
            else:
                attributes.append(f.resident(f.DATA, b'child witness', len(attributes)))
            attributes.sort(key=lambda a: (storage.attr_header(a)['type'],
                            storage.attr_name(a), storage.attr_header(a)['instance']))
            f.put_record(image, number, f.file_record(number, attributes,
                directory=directory_type, links=len(own_names)))
        # The original one-block root retains every existing authored entry.
        root_header, root_attributes = parts(image, f.ROOT_RECORD)
        allocation = next(a for a in root_attributes if storage.attr_header(a)['type'] == f.INDEX_ALLOC)
        _, runs = storage.mapping(allocation)
        assert runs == [(1, f.INDEX_LCN)]
        block = image[f.INDEX_LCN * f.CLUSTER:(f.INDEX_LCN + 1) * f.CLUSTER]
        header_offset = INDEX_BLOCK_PREFIX.size
        entries_offset, used, _, flags = f.INDEX_HEADER.unpack_from(block, header_offset)
        assert flags == 0
        entries, position = [], header_offset + entries_offset
        while position < header_offset + used:
            _, length, key_bytes, flags = f.INDEX_ENTRY.unpack_from(block, position)
            if flags & f.END:
                assert flags == f.END and key_bytes == 0
                break
            entries.append(bytes(block[position:position + length]))
            position += length
        entries.extend(f.entry(name, numbers['ancestor'], namespace=namespace,
                              attributes=f.FILE_ATTRIBUTE_DIRECTORY) for name, namespace in names)
        def collation(entry):
            key_bytes = f.INDEX_ENTRY.unpack_from(entry)[2]
            value = entry[f.INDEX_ENTRY.size:f.INDEX_ENTRY.size + key_bytes]
            raw = value[f.FILENAME_HEADER.size:]
            units = struct.unpack('<' + 'H' * (len(raw) // f.U16_BYTES), raw)
            return tuple(unit - ord('a') + ord('A') if ord('a') <= unit <= ord('z') else unit
                         for unit in units), units
        entries.sort(key=collation)
        f.put_data(image, f.INDEX_LCN, f.index_block(0, entries))
        header, attributes = parts(image, f.MFT_RECORD)
        slot = next(index for index, a in enumerate(attributes) if storage.attr_header(a)['type'] == f.BITMAP)
        bitmap = bytearray(storage.resident_value(attributes[slot]))
        for number in numbers.values():
            assert not bitmap[number // f.BYTE_BITS] & (1 << (number % f.BYTE_BITS))
            bitmap[number // f.BYTE_BITS] |= 1 << (number % f.BYTE_BITS)
        attributes[slot] = f.resident(f.BITMAP, bitmap, storage.attr_header(attributes[slot])['instance'])
        mft = storage.encoded_record(f.MFT_RECORD, attributes, header)
        f.put_record(image, f.MFT_RECORD, mft)
        f.put_data(image, f.MIRROR_LCN, mft)
        (directory / ('ancestor-' + profile + '.img')).write_bytes(image)
        if profile != 'win32-dos':
            continue
        header, attributes = parts(image, numbers['ancestor'])
        base = [a for a in attributes if storage.attr_header(a)['type'] != f.FILENAME]
        for bad in ANCESTOR_BAD_PROFILES:
            primary = filename(long_name, f.ROOT_REF, f.NAMESPACE_WIN32, 2)
            alias_parent = (f.file_reference(numbers['left']) if bad == 'different-parent'
                            else f.ROOT_RECORD if bad == 'zero-sequence' else f.ROOT_REF)
            alias = filename(short_name, alias_parent, f.NAMESPACE_DOS, 3)
            names = [primary, alias]
            if bad == 'dos-only':
                names = [alias]
            elif bad == 'duplicate-primary':
                names = [primary, filename(short_name, f.ROOT_REF, f.NAMESPACE_POSIX, 3)]
            elif bad == 'unknown-namespace':
                names[1] = filename(short_name, f.ROOT_REF, f.NAMESPACE_WIN32_DOS + 1, 3)
            elif bad == 'self-parent':
                names = [filename(long_name, ancestor_ref, f.NAMESPACE_WIN32, 2),
                         filename(short_name, ancestor_ref, f.NAMESPACE_DOS, 3)]
            elif bad == 'length-mismatch':
                value = bytearray(f.key(short_name, parent=f.ROOT_REF, namespace=f.NAMESPACE_DOS))
                fields = dict(zip(storage.FILENAME_FIELDS, f.FILENAME_HEADER.unpack_from(value)))
                fields['length'] += 1
                f.FILENAME_HEADER.pack_into(value, 0, *(fields[field] for field in storage.FILENAME_FIELDS))
                names[1] = f.resident(f.FILENAME, value, 3)
            elif bad == 'attribute-flags':
                value = bytearray(alias)
                fields = storage.attr_header(value)
                fields['flags'] = f.COMPRESSED
                f.ATTR_HEADER.pack_into(value, 0, *(fields[field] for field in s.ATTR_HEADER_FIELDS))
                names[1] = bytes(value)
            elif bad == 'named-attribute':
                names[1] = f.resident(f.FILENAME, storage.resident_value(alias), 3, 'invalid')
            elif bad == 'missing-filename':
                names = []
            values = sorted([*base, *names], key=lambda a: (
                storage.attr_header(a)['type'], storage.attr_name(a), storage.attr_header(a)['instance']))
            encoded = storage.encoded_record(numbers['ancestor'], values, header,
                links=1 if bad == 'physical-count' else max(1, len(names)))
            (directory / ('ancestor-invalid-' + bad + '.record')).write_bytes(encoded)
    (directory / 'ancestor-child.bin').write_bytes(b'child witness')
    (directory / 'ancestor-manifest.json').write_text(json.dumps(dict(
        validProfiles=list(ANCESTOR_PROFILES), refusedProfiles=list(ANCESTOR_BAD_PROFILES),
        numbers=numbers, longName=long_name, shortName=short_name), indent=2) + '\n')


def allocation_reservation_image(directory, original):
    """Keep eight free extension slots opaque while ordinary allocation grows."""
    import fixtures as f
    import filename_storage as storage
    import secure_fixtures as security

    image = bytearray(original)
    first = f.MFT_LCN * f.CLUSTER + f.MFT_RECORD * f.RECORD
    _, attributes = storage.record_parts(image[first:first + f.RECORD])
    bitmap = storage.resident_value(next(attribute for attribute in attributes
        if storage.attr_header(attribute)['type'] == f.BITMAP))
    for number in range(FIRST_USER_RECORD, FIRST_ALLOCATABLE_RECORD):
        assert not bitmap[number // f.BYTE_BITS] & (1 << (number % f.BYTE_BITS))
        value = bytearray([RESERVED_STORAGE_PATTERN + number - FIRST_USER_RECORD]) * f.RECORD
        # The free inventory does not interpret these bytes. Include a FILE
        # signature with invalid protection but a clear in-use flag.
        if number % 2:
            MST_HEADER.pack_into(value, 0, b'FILE', 0, 0)
            header = dict(zip(security.FILE_HEADER_FIELDS, f.FILE_HEADER.unpack_from(value)))
            header['flags'] = 0
            f.FILE_HEADER.pack_into(value, 0, *(header[name] for name in security.FILE_HEADER_FIELDS))
        else:
            value[:MST_HEADER.size] = bytes(MST_HEADER.size)
        f.put_record(image, number, value)
    first = f.MFT_LCN * f.CLUSTER + FIRST_USER_RECORD * f.RECORD
    end = f.MFT_LCN * f.CLUSTER + FIRST_ALLOCATABLE_RECORD * f.RECORD
    (directory / 'allocation-reservation.img').write_bytes(image)
    (directory / 'allocation-reservation.bin').write_bytes(image[first:end])


def wrapped_free_file_image(original):
    """A quiet, initialized free FILE whose next retirement wraps to generation 1."""
    import fixtures as f
    import filename_storage as storage
    import validation_fixtures as v

    image = bytearray(original)
    first = f.MFT_LCN * f.CLUSTER + f.MFT_RECORD * f.RECORD
    _, attributes = storage.record_parts(image[first:first + f.RECORD])
    bitmap = storage.resident_value(next(attribute for attribute in attributes
        if storage.attr_header(attribute)['type'] == f.BITMAP))
    number = next(number for number in range(FIRST_ALLOCATABLE_RECORD, f.MFT_COUNT)
                  if not bitmap[number // f.BYTE_BITS] & (1 << (number % f.BYTE_BITS)))
    first = f.MFT_LCN * f.CLUSTER + v.FRAGMENTED_RECORD * f.RECORD
    header, attributes = storage.record_parts(image[first:first + f.RECORD])
    header['sequence'] = MAX_FILE_SEQUENCE
    header['flags'] = 0
    f.put_record(image, number, storage.encoded_record(number, attributes, header))
    return image


def expanded_journal_image(original, journal_bytes=EXPANDED_JOURNAL_BYTES, *,
                           minimum_sequence=0, historical_state=None):
    """Independently resize the authored quiet journal, preserving its two roots.

    Changing file size changes LSN offset width. Rebind each meaningful stored
    LSN, keep opaque Noop words intact, and protect the complete authored pages.
    The new synthetic profile receives an independently chosen historical word.
    This is a test predecessor, not a driver checkpoint/reuse operation.
    """
    import fixtures as f
    import filename_storage as storage
    import logfile_fixtures as w
    import validation_fixtures as v
    from secure_store_fixtures import resident_value
    from write_journal_fixtures import restore_page, protect_page, QUIET_EXTENSION, QUIET_PROFILE_SCALAR
    from logfile_checkpoint_fixtures import CLIENT_RESTART

    image = bytearray(original)
    first = f.MFT_LCN * f.CLUSTER + v.LOGFILE_RECORD * f.RECORD
    header, attributes = storage.record_parts(image[first:first + f.RECORD])
    slot = next(index for index, attribute in enumerate(attributes)
                if storage.attr_header(attribute)['type'] == f.DATA)
    attribute = attributes[slot]
    stream, runs = storage.mapping(attribute)
    assert len(runs) == 1 and stream['initialized'] == stream['size']
    assert journal_bytes >= (w.RESTART_PAGES + w.MIN_RECORD_PAGES) * w.PAGE_BYTES
    clusters, lcn = runs[0]
    log_first = lcn * f.CLUSTER
    old = bytes(image[log_first:log_first + stream['size']])
    restart, rh, _ = restore_page(old[:w.PAGE_BYTES], w.RESTART_HEADER)
    area = {name: struct.unpack_from('<' + form, restart,
            rh['area_offset'] + w.RESTART_AREA.offsets[name])[0]
            for name, form in w.RESTART_AREA.fields}
    client_first = rh['area_offset'] + area['clients_offset']
    roots = {name: struct.unpack_from('<Q', restart,
            client_first + w.CLIENT.offsets[name])[0]
            for name in ('oldest_lsn', 'restart_lsn')}
    old_offset_bits = w.LSN_BITS - area['sequence_bits']
    new_sequence_bits = w.LSN_BITS + w.OFFSET_SHIFT - journal_bytes.bit_length()
    new_offset_bits = w.LSN_BITS - new_sequence_bits
    assert 0 <= minimum_sequence < 1 << new_sequence_bits
    source_sequence = roots['oldest_lsn'] >> old_offset_bits
    sequence_delta = max(0, minimum_sequence - source_sequence)

    def old_offset(lsn):
        return (lsn & ((1 << old_offset_bits) - 1)) << w.OFFSET_SHIFT

    def rebound(lsn):
        if not lsn:
            return 0
        offset = old_offset(lsn)
        assert offset < len(old)
        return w.lsn_at(offset, journal_bytes,
                        sequence=(lsn >> old_offset_bits) + sequence_delta,
                        sequence_bits=new_sequence_bits)

    home = old_offset(roots['oldest_lsn']) // w.PAGE_BYTES * w.PAGE_BYTES
    assert old_offset(roots['restart_lsn']) // w.PAGE_BYTES * w.PAGE_BYTES == home
    quiet, qh, sequence = restore_page(old[home:home + w.PAGE_BYTES], w.PAGE)
    for name in ('copy_value', 'last_end_lsn'):
        w.PAGE.put(quiet, name, rebound(qh[name]))
    for root in roots.values():
        packet_first = old_offset(root) - home
        fields = {name: struct.unpack_from('<' + form, quiet,
                  packet_first + w.RECORD.offsets[name])[0]
                  for name, form in w.RECORD.fields}
        for name in ('lsn', 'previous_lsn', 'undo_next_lsn'):
            w.RECORD.put(quiet, name, rebound(fields[name]), packet_first)
        if fields['type'] == w.RESTART_TYPE:
            payload_first = packet_first + w.RECORD.size
            analysis, = struct.unpack_from('<Q', quiet,
                payload_first + CLIENT_RESTART.offsets['analysis_lsn'])
            CLIENT_RESTART.put(quiet, 'analysis_lsn', rebound(analysis), payload_first)
            retained_first = payload_first + fields['data_bytes'] - w.LSN_BYTES
            retained, = struct.unpack_from('<Q', quiet, retained_first)
            assert retained == roots['oldest_lsn']
            struct.pack_into('<Q', quiet, retained_first, rebound(retained))
            extension_first = payload_first + CLIENT_RESTART.size
            extension = QUIET_EXTENSION.unpack_from(quiet, extension_first)
            assert extension[0] == extension[3] == extension[4] == extension[5] == 0
            assert extension[2] == QUIET_PROFILE_SCALAR and extension[6] == rebound(retained)
            authored_state = historical_state
            if authored_state is None:
                authored_state = max(1, (rebound(retained) >> new_offset_bits) - 1) << new_offset_bits
            assert 0 < authored_state < rebound(retained)
            assert authored_state % (1 << new_offset_bits) == 0
            QUIET_EXTENSION.pack_into(quiet, extension_first,
                0, authored_state, QUIET_PROFILE_SCALAR, 0, 0, 0, rebound(retained))
        else:
            assert fields['type'] == w.UPDATE_TYPE
    journal = bytearray(journal_bytes)
    journal[home:home + w.PAGE_BYTES] = protect_page(quiet, w.PAGE, sequence)
    for page in range(w.RESTART_PAGES):
        restart, rh, sequence = restore_page(old[page * w.PAGE_BYTES:(page + 1) * w.PAGE_BYTES],
                                              w.RESTART_HEADER)
        area_first = rh['area_offset']
        client_first = area_first + area['clients_offset']
        w.RESTART_AREA.put(restart, 'current_lsn', rebound(area['current_lsn']), area_first)
        w.RESTART_AREA.put(restart, 'sequence_bits', new_sequence_bits, area_first)
        w.RESTART_AREA.put(restart, 'file_bytes', journal_bytes, area_first)
        for name, lsn in roots.items():
            w.CLIENT.put(restart, name, rebound(lsn), client_first)
        journal[page * w.PAGE_BYTES:(page + 1) * w.PAGE_BYTES] = protect_page(restart, w.RESTART_HEADER, sequence)
    attributes[slot] = f.nonresident(f.DATA,
        [(journal_bytes // f.CLUSTER, lcn)], journal_bytes,
        storage.attr_header(attribute)['instance'])
    f.put_record(image, v.LOGFILE_RECORD,
                 storage.encoded_record(v.LOGFILE_RECORD, attributes, header))
    bitmap_first = f.MFT_LCN * f.CLUSTER + f.BITMAP_RECORD * f.RECORD
    header, attributes = storage.record_parts(image[bitmap_first:bitmap_first + f.RECORD])
    slot = next(index for index, attribute in enumerate(attributes)
                if storage.attr_header(attribute)['type'] == f.DATA)
    attribute = attributes[slot]
    bitmap = bytearray(resident_value(attribute))
    for cluster in range(lcn + clusters, lcn + journal_bytes // f.CLUSTER):
        assert not bitmap[cluster // f.BYTE_BITS] & (1 << (cluster % f.BYTE_BITS))
        bitmap[cluster // f.BYTE_BITS] |= 1 << (cluster % f.BYTE_BITS)
    for cluster in range(lcn + journal_bytes // f.CLUSTER, lcn + clusters):
        assert bitmap[cluster // f.BYTE_BITS] & (1 << (cluster % f.BYTE_BITS))
        bitmap[cluster // f.BYTE_BITS] &= ~(1 << (cluster % f.BYTE_BITS))
    attributes[slot] = f.resident(f.DATA, bitmap, storage.attr_header(attribute)['instance'])
    f.put_record(image, f.BITMAP_RECORD,
                 storage.encoded_record(f.BITMAP_RECORD, attributes, header))
    f.put_data(image, lcn, journal)
    mft_first = f.MFT_LCN * f.CLUSTER
    f.put_data(image, f.MIRROR_LCN, image[mft_first:mft_first + v.MIRROR_RECORDS * f.RECORD])
    return image


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


def directory_spill_security():
    """A one-entry inline root fits; temporary external attributes do not."""
    system, users, administrator = sid(5, 18), sid(5, 32, 545), sid(5, 32, 544)
    creator_owner = sid(3, 0)
    propagation = OBJECT_INHERIT | CONTAINER_INHERIT
    parent = [(ALLOW, propagation, FULL_ACCESS, system),
              (ALLOW, propagation, FULL_ACCESS, administrator),
              (ALLOW, propagation, READ_ACCESS, users),
              (ALLOW, propagation, FULL_ACCESS, creator_owner)]
    directory = [(kind, flags | ACE_INHERITED, mask, trustee)
                 for kind, flags, mask, trustee in parent[:-1]] + [
                     (ALLOW, ACE_INHERITED, FULL_ACCESS, administrator),
                     (ALLOW, propagation | INHERIT_ONLY | ACE_INHERITED,
                      FULL_ACCESS, creator_owner)]
    child = [(kind, ACE_INHERITED, mask, trustee)
             for kind, _, mask, trustee in parent[:-1]] + [
                 (ALLOW, ACE_INHERITED, FULL_ACCESS, administrator)]
    return {'inline-spill-parent.bin': descriptor(parent),
            'inline-spill-directory.bin': descriptor(directory, True),
            'inline-spill-file.bin': descriptor(child, True)}


def generic_security_cases():
    """Literal type-specific results qualified by native private-object APIs."""
    users, authenticated = sid(5, 32, 545), sid(5, 11)
    administrator, system = sid(5, 32, 544), sid(5, 18)
    creator_owner, creator_group = sid(3, 0), sid(3, 1)
    propagation = OBJECT_INHERIT | CONTAINER_INHERIT
    parent = [(ALLOW, propagation, GENERIC_READ, users),
              (ALLOW, CONTAINER_INHERIT, GENERIC_WRITE, creator_owner),
              (ALLOW, propagation, GENERIC_ALL, creator_group),
              (ALLOW, OBJECT_INHERIT, GENERIC_EXECUTE, authenticated)]
    directory = [(ALLOW, ACE_INHERITED, FILE_GENERIC_READ, users),
                 (ALLOW, propagation | INHERIT_ONLY | ACE_INHERITED,
                  GENERIC_READ, users),
                 (ALLOW, ACE_INHERITED, FILE_GENERIC_WRITE, administrator),
                 (ALLOW, CONTAINER_INHERIT | INHERIT_ONLY | ACE_INHERITED,
                  GENERIC_WRITE, creator_owner),
                 (ALLOW, ACE_INHERITED, FULL_ACCESS, system),
                 (ALLOW, propagation | INHERIT_ONLY | ACE_INHERITED,
                  GENERIC_ALL, creator_group),
                 (ALLOW, OBJECT_INHERIT | INHERIT_ONLY | ACE_INHERITED,
                  GENERIC_EXECUTE, authenticated)]
    file = [(ALLOW, ACE_INHERITED, FILE_GENERIC_READ, users),
            (ALLOW, ACE_INHERITED, FULL_ACCESS, system),
            (ALLOW, ACE_INHERITED, FILE_GENERIC_EXECUTE, authenticated)]
    return {'generic-parent-security.bin': descriptor(parent),
            'generic-directory-security.bin': descriptor(directory, True),
            'generic-file-security.bin': descriptor(file, True)}


def directory_spill_image(directory, original, parent):
    import fixtures as f
    import filename_storage as storage

    image = bytearray(original)
    first = f.MFT_LCN * f.CLUSTER + f.ROOT_RECORD * f.RECORD
    header, attributes = storage.record_parts(image[first:first + f.RECORD])
    index = next(index for index, attribute in enumerate(attributes)
                 if storage.attr_header(attribute)['type'] == SECURITY_DESCRIPTOR_TYPE)
    attributes[index] = f.resident(SECURITY_DESCRIPTOR_TYPE, parent,
                                   storage.attr_header(attributes[index])['instance'])
    f.put_record(image, f.ROOT_RECORD, storage.encoded_record(f.ROOT_RECORD, attributes, header))
    (directory / 'directory-inline-spill.img').write_bytes(image)


def unused_storage_images(directory, original):
    """Keep free bytes opaque even when they imitate another owner's metadata."""
    import fixtures as f
    import filename_storage as storage
    from secure_store_fixtures import resident_value

    def parts(image, number):
        first = f.MFT_LCN * f.CLUSTER + number * f.RECORD
        return storage.record_parts(image[first:first + f.RECORD])

    def shift_children(buffer, header_offset):
        entries_offset, used, _, _ = f.INDEX_HEADER.unpack_from(buffer, header_offset)
        position, end = header_offset + entries_offset, header_offset + used
        while position < end:
            _, length, _, flags = f.INDEX_ENTRY.unpack_from(buffer, position)
            assert length >= f.INDEX_ENTRY.size and position + length <= end
            if flags & f.CHILD:
                trailer = position + length - f.U64_BYTES
                child, = struct.unpack_from('<Q', buffer, trailer)
                struct.pack_into('<Q', buffer, trailer, child + 1)
            position += length
        assert position == end

    def allocate_cluster(image, allocation, lcn):
        assert not allocation[lcn // f.BYTE_BITS] & (1 << (lcn % f.BYTE_BITS))
        header, attributes = parts(image, f.BITMAP_RECORD)
        index = next(index for index, attribute in enumerate(attributes)
                     if storage.attr_header(attribute)['type'] == f.DATA)
        allocated = bytearray(allocation)
        allocated[lcn // f.BYTE_BITS] |= 1 << (lcn % f.BYTE_BITS)
        attributes[index] = f.resident(f.DATA, allocated,
            storage.attr_header(attributes[index])['instance'])
        f.put_record(image, f.BITMAP_RECORD,
                     storage.encoded_record(f.BITMAP_RECORD, attributes, header))

    _, bitmap_attributes = parts(original, f.BITMAP_RECORD)
    allocation = resident_value(next(attribute for attribute in bitmap_attributes
                                    if storage.attr_header(attribute)['type'] == f.DATA))
    stale_file = f.file_record(f.ATTRIBUTE_EXTENSION_RECORD,
                              [f.standard(), f.resident(f.DATA, b'foreign-file')])
    stale_index = f.index_block(f.ATTRIBUTE_EXTENSION_RECORD, [])
    for profile in UNUSED_STORAGE_PROFILES:
        image = bytearray(original)
        if profile.startswith(('file-', 'mft-tail-')):
            block = bytearray(stale_file * (f.CLUSTER // f.RECORD))
            if profile.endswith('-torn'):
                for offset in range(0, f.CLUSTER, f.RECORD):
                    MST_HEADER.pack_into(block, offset, b'FILE', 0, 0)
        else:
            block = bytearray(stale_index)
            if profile != 'index-stale':
                MST_HEADER.pack_into(block, 0, b'INDX', 0, 0)
        if profile.startswith('mft-tail-'):
            # MFT allocation and size are distinct from initialization. Keep
            # one allocated mapped tail outside the original initialized range.
            header, attributes = parts(image, f.MFT_RECORD)
            index = next(index for index, attribute in enumerate(attributes)
                         if storage.attr_header(attribute)['type'] == f.DATA)
            attribute = attributes[index]
            stream, runs = storage.mapping(attribute)
            assert stream['initialized'] == stream['size']
            tail_lcn = next(cluster for cluster in range(len(image) // f.CLUSTER)
                            if not allocation[cluster // f.BYTE_BITS] &
                            (1 << (cluster % f.BYTE_BITS)))
            allocate_cluster(image, allocation, tail_lcn)
            runs.append((1, tail_lcn))
            attributes[index] = f.nonresident(f.DATA, runs, stream['size'],
                storage.attr_header(attribute)['instance'],
                allocated=sum(count for count, _ in runs) * f.CLUSTER,
                initialized=stream['initialized'])
            encoded = storage.encoded_record(f.MFT_RECORD, attributes, header)
            f.put_record(image, f.MFT_RECORD, encoded)
            f.put_data(image, f.MIRROR_LCN, encoded)
            f.put_data(image, tail_lcn, block)
        elif profile == 'index-unused-slot':
            # Shift every original live VCN up by one. VCN zero stays allocated
            # in the stream but has a clear bitmap bit and malformed bytes. The
            # very first rebuilding mutation will use this unused buffer.
            header, attributes = parts(image, f.ROOT_RECORD)
            index = next(index for index, attribute in enumerate(attributes)
                         if storage.attr_header(attribute)['type'] == f.INDEX_ALLOC)
            attribute = attributes[index]
            stream, runs = storage.mapping(attribute)
            assert len(runs) == 1 and runs[0][1] == f.INDEX_LCN
            clusters = runs[0][0]
            assert stream['initialized'] == clusters * f.CLUSTER
            spare_lcn = f.INDEX_LCN + clusters
            allocate_cluster(image, allocation, spare_lcn)
            attributes[index] = f.nonresident(f.INDEX_ALLOC,
                [(clusters + 1, f.INDEX_LCN)], (clusters + 1) * f.CLUSTER,
                storage.attr_header(attribute)['instance'], '$I30')
            root_index = next(index for index, attribute in enumerate(attributes)
                              if storage.attr_header(attribute)['type'] == f.INDEX_ROOT)
            root = bytearray(resident_value(attributes[root_index]))
            shift_children(root, f.INDEX_ROOT_HEADER.size)
            attributes[root_index] = f.resident(f.INDEX_ROOT, root,
                storage.attr_header(attributes[root_index])['instance'], '$I30')
            bits_index = next(index for index, attribute in enumerate(attributes)
                              if storage.attr_header(attribute)['type'] == f.BITMAP)
            bits = int.from_bytes(resident_value(attributes[bits_index]), 'little')
            assert bits == (1 << clusters) - 1
            attributes[bits_index] = f.resident(f.BITMAP,
                (bits << 1).to_bytes((clusters + 1 + f.BYTE_BITS - 1) // f.BYTE_BITS,
                                    'little'),
                storage.attr_header(attributes[bits_index])['instance'], '$I30')
            for vcn in range(clusters):
                before = bytearray(original[(f.INDEX_LCN + vcn) * f.CLUSTER:
                                             (f.INDEX_LCN + vcn + 1) * f.CLUSTER])
                fields = dict(zip(INDEX_BLOCK_FIELDS, INDEX_BLOCK_PREFIX.unpack_from(before)))
                assert fields['vcn'] == vcn
                for sector in range(1, fields['usa_count']):
                    tail = sector * f.SECTOR - f.U16_BYTES
                    saved = fields['usa_offset'] + sector * f.U16_BYTES
                    before[tail:tail + f.U16_BYTES] = before[saved:saved + f.U16_BYTES]
                fields['vcn'] += 1
                INDEX_BLOCK_PREFIX.pack_into(before, 0,
                    *(fields[name] for name in INDEX_BLOCK_FIELDS))
                shift_children(before, INDEX_BLOCK_PREFIX.size)
                f.protect(before, fields['usa_offset'])
                f.put_data(image, f.INDEX_LCN + vcn + 1, before)
            f.put_record(image, f.ROOT_RECORD,
                         storage.encoded_record(f.ROOT_RECORD, attributes, header))
            f.put_data(image, f.INDEX_LCN, block)
        else:
            for cluster in range(len(image) // f.CLUSTER):
                if not allocation[cluster // f.BYTE_BITS] & (1 << (cluster % f.BYTE_BITS)):
                    f.put_data(image, cluster, block)
        (directory / f'unused-{profile}.img').write_bytes(image)


def bitmap_storage_images(directory, original):
    """Bit changes retain nonresident bitmap metadata and allocated tail bytes."""
    import fixtures as f
    import filename_storage as storage

    def parts(image, number):
        first = f.MFT_LCN * f.CLUSTER + number * f.RECORD
        return storage.record_parts(image[first:first + f.RECORD])

    original_header, original_attributes = parts(original, f.BITMAP_RECORD)
    allocation_slot = next(index for index, attribute in enumerate(original_attributes)
                           if storage.attr_header(attribute)['type'] == f.DATA)
    original_allocation = storage.resident_value(original_attributes[allocation_slot])
    for profile in BITMAP_STORAGE_PROFILES:
        label = 'bitmap-storage-' + profile
        image = bytearray(original)
        allocation = bytearray(original_allocation)
        owners = []
        if profile in ('mft', 'both'):
            owners.append((f.MFT_RECORD, f.BITMAP))
        if profile in ('volume', 'both'):
            owners.append((f.BITMAP_RECORD, f.DATA))
        extents = []
        for number, kind in owners:
            lcn = next(first for first in range(len(image) // f.CLUSTER - BITMAP_ALLOCATION_CLUSTERS + 1)
                       if all(not allocation[cluster // f.BYTE_BITS] & (1 << (cluster % f.BYTE_BITS))
                              for cluster in range(first, first + BITMAP_ALLOCATION_CLUSTERS)))
            for cluster in range(lcn, lcn + BITMAP_ALLOCATION_CLUSTERS):
                allocation[cluster // f.BYTE_BITS] |= 1 << (cluster % f.BYTE_BITS)
            extents.append((number, kind, lcn))
        if profile == 'mft':
            attributes = list(original_attributes)
            attributes[allocation_slot] = f.resident(f.DATA, allocation,
                storage.attr_header(attributes[allocation_slot])['instance'])
            f.put_record(image, f.BITMAP_RECORD,
                         storage.encoded_record(f.BITMAP_RECORD, attributes, original_header))
        rows = []
        for number, kind, lcn in extents:
            header, attributes = parts(image, number)
            slot = next(index for index, attribute in enumerate(attributes)
                        if storage.attr_header(attribute)['type'] == kind)
            previous = attributes[slot]
            value = bytes(allocation) if number == f.BITMAP_RECORD else storage.resident_value(previous)
            assert 0 < len(value) < f.CLUSTER
            attribute = f.nonresident(kind, [(BITMAP_ALLOCATION_CLUSTERS, lcn)], len(value),
                storage.attr_header(previous)['instance'],
                allocated=BITMAP_ALLOCATION_CLUSTERS * f.CLUSTER, initialized=len(value))
            common = storage.attr_header(attribute)
            assert not common['name_length'] and common['name_offset'] == f.ATTR_HEADER.size + f.NONRESIDENT_HEADER.size
            attributes[slot] = attribute
            encoded = storage.encoded_record(number, attributes, header)
            f.put_record(image, number, encoded)
            if number == f.MFT_RECORD:
                f.put_data(image, f.MIRROR_LCN, encoded)
            allocation_bytes = bytearray([BITMAP_UNUSED_PATTERN]) * (BITMAP_ALLOCATION_CLUSTERS * f.CLUSTER)
            allocation_bytes[:len(value)] = value
            f.put_data(image, lcn, allocation_bytes)
            (directory / (label + '-' + str(number) + '.attribute')).write_bytes(attribute)
            (directory / (label + '-' + str(number) + '.tail')).write_bytes(allocation_bytes[f.CLUSTER:])
            rows.append(f'{number} {kind:x} {(lcn + 1) * f.CLUSTER}')
        (directory / (label + '.img')).write_bytes(image)
        (directory / (label + '.rows')).write_text('\n'.join(rows) + '\n')


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
    bodies.update(directory_spill_security())
    bodies.update(generic_security_cases())
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
        import logfile_fixtures as w
        (directory / 'minimum-journal.img').write_bytes(expanded_journal_image(
            image, (w.RESTART_PAGES + w.MIN_RECORD_PAGES) * w.PAGE_BYTES))
        (directory / 'history-source.img').write_bytes(
            expanded_journal_image(image, HISTORY_JOURNAL_BYTES))
        directory_ancestor_images(directory, image, bodies['parent-security.bin'])
        generic = bytearray(image)
        attributes[index] = f.resident(SECURITY_DESCRIPTOR_TYPE,
                                      bodies['generic-parent-security.bin'], instance)
        f.put_record(generic, f.ROOT_RECORD,
                     storage.encoded_record(f.ROOT_RECORD, attributes, header))
        (directory / 'generic-security.img').write_bytes(generic)
        unused_storage_images(directory, image)
        for name in ('source', *(f'unused-{profile}' for profile in UNUSED_STORAGE_PROFILES)):
            original = (directory / f'{name}.img').read_bytes()
            (directory / f'large-{name}.img').write_bytes(expanded_journal_image(original))
        large = (directory / 'large-source.img').read_bytes()
        allocation_reservation_image(directory, large)
        directory_spill_image(directory, large, bodies['inline-spill-parent.bin'])
        (directory / 'large-reuse-wrapped.img').write_bytes(wrapped_free_file_image(large))
        bitmap_storage_images(directory, large)
    manifest = dict(writeOffset=WRITE_OFFSET, payloadBytes=PAYLOAD_BYTES,
                    growBytes=GROW_BYTES, shrinkBytes=SHRINK_BYTES,
                    regrowBytes=REGROW_BYTES, children=CHILDREN,
                    childNameUnits=NAME_UNITS, reuseOperations=REUSE_OPERATIONS,
                    unusedStorageProfiles=list(UNUSED_STORAGE_PROFILES),
                    bitmapStorageProfiles=list(BITMAP_STORAGE_PROFILES),
                    directoryAncestorProfiles=list(ANCESTOR_PROFILES),
                    bytes={name: dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                           for name, data in bodies.items()},
                    requiredScenarios=['resident-growth-and-storage-conversion',
                        'fragmented-allocation-and-zero-gap', 'shrink-and-zero-regrowth',
                        'cross-directory-move-and-replacement', 'file-and-directory-removal',
                        'MFT-generation-reuse', 'directory-index-split-and-MFT-growth',
                        'nonresident-bitmap-storage-preservation',
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
