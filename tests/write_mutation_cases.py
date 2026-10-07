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
MST_HEADER = struct.Struct('<4sHH')
INDEX_BLOCK_PREFIX = struct.Struct('<4sHHQQ')
INDEX_BLOCK_FIELDS = ('magic', 'usa_offset', 'usa_count', 'lsn', 'vcn')
UNUSED_STORAGE_PROFILES = ('file-stale', 'file-torn', 'index-stale', 'index-torn',
                           'index-unused-slot', 'mft-tail-stale', 'mft-tail-torn')
EXPANDED_JOURNAL_BYTES = 1024 * 1024


def expanded_journal_image(original):
    """Independently enlarge the authored quiet journal, preserving its two roots.

    Changing file size changes LSN offset width. Rebind each meaningful stored
    LSN, keep opaque Noop words intact, and protect the complete authored pages.
    This is a test predecessor, not a driver checkpoint/reuse operation.
    """
    import fixtures as f
    import filename_storage as storage
    import logfile_fixtures as w
    import validation_fixtures as v
    from secure_store_fixtures import resident_value
    from write_journal_fixtures import restore_page, protect_page
    from logfile_checkpoint_fixtures import CLIENT_RESTART

    image = bytearray(original)
    first = f.MFT_LCN * f.CLUSTER + v.LOGFILE_RECORD * f.RECORD
    header, attributes = storage.record_parts(image[first:first + f.RECORD])
    slot = next(index for index, attribute in enumerate(attributes)
                if storage.attr_header(attribute)['type'] == f.DATA)
    attribute = attributes[slot]
    stream, runs = storage.mapping(attribute)
    assert len(runs) == 1 and stream['initialized'] == stream['size']
    assert stream['size'] < EXPANDED_JOURNAL_BYTES
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
    new_sequence_bits = w.LSN_BITS + w.OFFSET_SHIFT - EXPANDED_JOURNAL_BYTES.bit_length()

    def old_offset(lsn):
        return (lsn & ((1 << old_offset_bits) - 1)) << w.OFFSET_SHIFT

    def rebound(lsn):
        if not lsn:
            return 0
        offset = old_offset(lsn)
        assert offset < len(old)
        return w.lsn_at(offset, EXPANDED_JOURNAL_BYTES,
                        sequence=lsn >> old_offset_bits, sequence_bits=new_sequence_bits)

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
        else:
            assert fields['type'] == w.UPDATE_TYPE
    journal = bytearray(EXPANDED_JOURNAL_BYTES)
    journal[home:home + w.PAGE_BYTES] = protect_page(quiet, w.PAGE, sequence)
    for page in range(w.RESTART_PAGES):
        restart, rh, sequence = restore_page(old[page * w.PAGE_BYTES:(page + 1) * w.PAGE_BYTES],
                                              w.RESTART_HEADER)
        area_first = rh['area_offset']
        client_first = area_first + area['clients_offset']
        w.RESTART_AREA.put(restart, 'current_lsn', rebound(area['current_lsn']), area_first)
        w.RESTART_AREA.put(restart, 'sequence_bits', new_sequence_bits, area_first)
        w.RESTART_AREA.put(restart, 'file_bytes', EXPANDED_JOURNAL_BYTES, area_first)
        for name, lsn in roots.items():
            w.CLIENT.put(restart, name, rebound(lsn), client_first)
        journal[page * w.PAGE_BYTES:(page + 1) * w.PAGE_BYTES] = protect_page(restart, w.RESTART_HEADER, sequence)
    attributes[slot] = f.nonresident(f.DATA,
        [(EXPANDED_JOURNAL_BYTES // f.CLUSTER, lcn)], EXPANDED_JOURNAL_BYTES,
        storage.attr_header(attribute)['instance'])
    f.put_record(image, v.LOGFILE_RECORD,
                 storage.encoded_record(v.LOGFILE_RECORD, attributes, header))
    bitmap_first = f.MFT_LCN * f.CLUSTER + f.BITMAP_RECORD * f.RECORD
    header, attributes = storage.record_parts(image[bitmap_first:bitmap_first + f.RECORD])
    slot = next(index for index, attribute in enumerate(attributes)
                if storage.attr_header(attribute)['type'] == f.DATA)
    attribute = attributes[slot]
    bitmap = bytearray(resident_value(attribute))
    for cluster in range(lcn + clusters, lcn + EXPANDED_JOURNAL_BYTES // f.CLUSTER):
        assert not bitmap[cluster // f.BYTE_BITS] & (1 << (cluster % f.BYTE_BITS))
        bitmap[cluster // f.BYTE_BITS] |= 1 << (cluster % f.BYTE_BITS)
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
        unused_storage_images(directory, image)
        for name in ('source', *(f'unused-{profile}' for profile in UNUSED_STORAGE_PROFILES)):
            original = (directory / f'{name}.img').read_bytes()
            (directory / f'large-{name}.img').write_bytes(expanded_journal_image(original))
    manifest = dict(writeOffset=WRITE_OFFSET, payloadBytes=PAYLOAD_BYTES,
                    growBytes=GROW_BYTES, shrinkBytes=SHRINK_BYTES,
                    regrowBytes=REGROW_BYTES, children=CHILDREN,
                    childNameUnits=NAME_UNITS, reuseOperations=REUSE_OPERATIONS,
                    unusedStorageProfiles=list(UNUSED_STORAGE_PROFILES),
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
