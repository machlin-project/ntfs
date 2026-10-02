"""Original mirror replicas, protection/slack cases and complete geometries.

The oracle authors replica differences independently of the C comparison. Larger
declared mirror tails are deliberately unqualified, including stale/zero tails.
"""
from contextlib import contextmanager
import struct
import fixtures as f
import validation_fixtures as v

FILE_FIELDS = ('magic', 'usa_offset', 'usa_count', 'lsn', 'sequence', 'links',
               'attrs_offset', 'flags', 'used', 'allocated', 'base_reference',
               'next_instance', 'reserved', 'record_number')
SMALL_CLUSTER = 1024
SMALL_IMAGE_BYTES = 1024 * 1024
LARGE_CLUSTER = 64 * 1024
SECOND_MIRROR_LCN = 104
LOGFILE_RECORD = 2
VOLUME_LABEL_UNITS = 200
STALE_TAIL_BYTE = 0xA7
OTHER_PROTECTION_SEQUENCE = f.FIXUP_SEQUENCE + 1
STAGE_MOUNT, STAGE_ATTRIBUTES, STAGE_FINISHED, STAGE_MIRROR = 1, 3, 6, 7
RESULTS = {'ok': 'success', 'corrupt': 'corrupt metadata',
           'unsupported': 'unsupported format'}
SMALL_GEOMETRY = {'CLUSTER': SMALL_CLUSTER, 'MIRROR_LCN': 96,
                  'UPCASE_LCN': 128, 'INDEX_LCN': 272, 'IMAGE_SIZE': SMALL_IMAGE_BYTES}
LARGE_GEOMETRY = {'CLUSTER': LARGE_CLUSTER, 'MIRROR_LCN': 6,
                  'UPCASE_LCN': 8, 'INDEX_LCN': 10}
SMALL_DATA = {'FIRST_DATA_LCN': 280, 'SECOND_DATA_LCN': 282, 'ORPHAN_LCN': 288}
LARGE_DATA = {'FIRST_DATA_LCN': 12, 'SECOND_DATA_LCN': 14, 'ORPHAN_LCN': 15}


@contextmanager
def geometry(source, layout, data):
    previous = {name: getattr(f, name) for name in layout}
    old_data = {name: getattr(v, name) for name in data}
    upcase_start = f.UPCASE_LCN * f.CLUSTER
    upcase = source[upcase_start:upcase_start + v.UPCASE_UNITS * f.U16_BYTES]
    try:
        for name, value in layout.items():
            setattr(f, name, value)
        for name, value in data.items():
            setattr(v, name, value)
        image = bytearray(source[:f.IMAGE_SIZE])
        image[f.BOOT_FIELDS['cluster_sectors']] = f.CLUSTER // f.SECTOR
        image[f.BOOT_FIELDS['index_code']] = -(f.CLUSTER.bit_length() - 1) % f.BYTE_VALUES
        struct.pack_into('<Q', image, f.BOOT_FIELDS['mirror'], f.MIRROR_LCN)
        struct.pack_into('<Q', image, f.BOOT_FIELDS['sectors'], f.IMAGE_SIZE // f.SECTOR)
        f.put_data(image, f.UPCASE_LCN, upcase)
        yield image
    finally:
        for name, value in previous.items():
            setattr(f, name, value)
        for name, value in old_data.items():
            setattr(v, name, value)


def replica_position(number, mirror):
    offset = number * f.RECORD
    for count, lcn in mirror.runs:
        length = count * f.CLUSTER
        if offset < length:
            assert lcn is not None
            return lcn * f.CLUSTER + offset
        offset -= length
    raise AssertionError('Replica slot is outside the authored mirror mapping')


def transform_record(encoded, *, fields=None, change=None, protection=None):
    value = bytearray(encoded)
    header = dict(zip(FILE_FIELDS, f.FILE_HEADER.unpack_from(value)))
    usa = header['usa_offset']
    for sector in range(1, header['usa_count']):
        tail = sector * f.SECTOR - f.U16_BYTES
        saved = usa + sector * f.U16_BYTES
        value[tail:tail + f.U16_BYTES] = value[saved:saved + f.U16_BYTES]
    if fields:
        header.update(fields)
        f.FILE_HEADER.pack_into(value, 0, *(header[name] for name in FILE_FIELDS))
    if change:
        change(value, header)
    f.protect(value, usa)
    if protection is not None:
        struct.pack_into('<H', value, usa, protection)
        for sector in range(1, header['usa_count']):
            struct.pack_into('<H', value, sector * f.SECTOR - f.U16_BYTES, protection)
    return value


def replace_replica(image, number, mirror, transform):
    position = replica_position(number, mirror)
    image[position:position + f.RECORD] = transform(image[position:position + f.RECORD])


def long_volume_record():
    attributes = [f.standard(), v.filename(v.Link('$Volume')),
                  f.resident(f.VOL_NAME, ('V' * VOLUME_LABEL_UNITS).encode('utf-16le'),
                             v.VOLUME_NAME_INSTANCE),
                  f.resident(f.VOL_INFO, v.VOLUME_INFORMATION.pack(
                      f.NTFS_MAJOR_VERSION, f.NTFS_MINOR_VERSION, 0), v.VOLUME_INFO_INSTANCE)]
    return f.file_record(f.VOLUME_RECORD, attributes)


def author(output, source):
    cases = []

    def save(name, image, result='ok', *, slots=v.MIRROR_RECORDS,
             compared=v.MIRROR_RECORDS, unchecked=0, subject=None, stage=None):
        filename = 'validation-mirror-' + name + '.img'
        (output / filename).write_bytes(image)
        expected = {'mirror_record_slots': str(slots),
                    'mirror_records_compared': str(compared),
                    'mirror_unchecked_records': str(unchecked)}
        if stage is not None:
            expected['stage'] = stage
        if subject is not None:
            expected['record_number'] = str(subject)
        cases.append({'image': filename, 'result': RESULTS[result], 'complete': result == 'ok',
                      'mirror': expected})

    default = v.Mirror(((1, f.MIRROR_LCN),))
    standard = v.build(source, 'standard', mirror=default)
    for name, arguments, slots, result in (
            ('short', {'size': (v.MIRROR_RECORDS - 1) * f.RECORD}, v.MIRROR_RECORDS - 1, 'corrupt'),
            ('partial-record', {'size': v.MIRROR_RECORDS * f.RECORD - 1}, v.MIRROR_RECORDS - 1, 'corrupt'),
            ('partial-initialization', {'initialized': v.MIRROR_RECORDS * f.RECORD - 1}, v.MIRROR_RECORDS, 'corrupt'),
            ('wrong-anchor', {'runs': ((1, v.ORPHAN_LCN),)}, v.MIRROR_RECORDS, 'corrupt'),
            ('missing-data', {'missing': True}, 0, 'corrupt'),
            ('resident-data', {'resident': True}, 0, 'corrupt'),
            ('sparse', {'flags': f.SPARSE}, v.MIRROR_RECORDS, 'unsupported'),
            ('larger-than-supported', {'runs': ((2, f.MIRROR_LCN),),
                                       'size': v.MIRROR_RECORDS * f.RECORD + f.RECORD},
             v.MIRROR_RECORDS + 1, 'unsupported')):
        options = {'runs': default.runs, **arguments}
        image = v.build(source, 'standard', mirror=v.Mirror(**options))
        save(name, image, result, slots=slots, compared=0, subject=v.MIRROR_RECORD,
             stage=STAGE_MIRROR)
    encrypted = v.build(source, 'standard', mirror=v.Mirror(default.runs, flags=f.ENCRYPTED))
    save('encrypted', encrypted, 'unsupported', slots=0, compared=0, stage=STAGE_ATTRIBUTES)

    for name, fields in (('different-sequence', {'sequence': f.SYSTEM_SEQUENCE + 1}),
                         ('different-lsn', {'lsn': 1}), ('different-link-count', {'links': 2}),
                         ('invalid-used-span', {'used': f.FILE_HEADER.size}),
                         ('inactive-copy', {'flags': 0})):
        image = bytearray(standard)
        replace_replica(image, v.MIRROR_RECORD, default,
                        lambda record: transform_record(record, fields=fields))
        save(name, image, 'corrupt', compared=v.MIRROR_RECORD, subject=v.MIRROR_RECORD,
             stage=STAGE_MIRROR)
    for name, flags in (('directory-owner', f.FILE_IS_DIRECTORY),
                        ('view-owner', f.FILE_VIEW_INDEX),
                        ('uninterpreted-owner', f.FILE_UNINTERPRETED)):
        image = bytearray(standard)
        position = f.MFT_LCN * f.CLUSTER + v.MIRROR_RECORD * f.RECORD
        encoded = transform_record(image[position:position + f.RECORD],
                                   fields={'flags': f.FILE_IN_USE | flags})
        image[position:position + f.RECORD] = encoded
        replica = replica_position(v.MIRROR_RECORD, default)
        image[replica:replica + f.RECORD] = encoded
        save(name, image, 'unsupported', slots=0, compared=0, subject=v.MIRROR_RECORD,
             stage=STAGE_MIRROR)

    image = bytearray(standard)
    replace_replica(image, v.MIRROR_RECORD, default,
                    lambda record: transform_record(record, protection=OTHER_PROTECTION_SEQUENCE))
    save('independent-protection', image)
    for name, location in (('different-slack', lambda header: header['used'] + f.U16_BYTES),
                           ('different-slack-tail', lambda header: f.RECORD - f.U16_BYTES)):
        image = bytearray(standard)
        def change(value, header):
            value[location(header)] ^= STALE_TAIL_BYTE
        replace_replica(image, v.MIRROR_RECORD, default,
                        lambda record: transform_record(record, change=change))
        save(name, image)

    image = bytearray(standard)
    position = replica_position(f.VOLUME_RECORD, default) + f.SECTOR - f.U16_BYTES
    image[position] ^= 1
    save('torn-final-copy', image, 'corrupt', compared=f.VOLUME_RECORD,
         subject=f.VOLUME_RECORD, stage=STAGE_MIRROR)
    image = bytearray(standard)
    image[replica_position(LOGFILE_RECORD, default)] = STALE_TAIL_BYTE
    save('different-opaque-free-slot', image, 'corrupt', compared=LOGFILE_RECORD,
         subject=LOGFILE_RECORD, stage=STAGE_MIRROR)

    image = bytearray(standard)
    unused = transform_record(f.file_record(LOGFILE_RECORD, [f.standard()]), fields={'flags': 0})
    f.put_record(image, LOGFILE_RECORD, unused)
    position = replica_position(LOGFILE_RECORD, default)
    image[position:position + f.RECORD] = unused
    save('identical-opaque-free-record', image)
    replace_replica(image, LOGFILE_RECORD, default,
                    lambda record: transform_record(record, protection=OTHER_PROTECTION_SEQUENCE))
    save('different-opaque-free-protection', image, 'corrupt', compared=LOGFILE_RECORD,
         subject=LOGFILE_RECORD,
         stage=STAGE_MIRROR)

    image = bytearray(standard)
    replace_replica(image, f.MFT_RECORD, default,
                    lambda record: transform_record(record, fields={'lsn': 1}))
    save('bootstrap-difference', image, 'corrupt', slots=0, compared=0, stage=STAGE_MOUNT)
    image = bytearray(standard)
    encoded = long_volume_record()
    f.put_record(image, f.VOLUME_RECORD, encoded)
    position = replica_position(f.VOLUME_RECORD, default)
    image[position:position + f.RECORD] = encoded
    save('used-protected-tail', image)
    def change_used_tail(value, header):
        tail = f.SECTOR - f.U16_BYTES
        assert tail + f.U16_BYTES <= header['used']
        value[tail] ^= 1
    replace_replica(image, f.VOLUME_RECORD, default,
                    lambda record: transform_record(record, change=change_used_tail))
    save('different-used-protected-tail', image, 'corrupt', compared=f.VOLUME_RECORD,
         subject=f.VOLUME_RECORD, stage=STAGE_MIRROR)

    with geometry(source, SMALL_GEOMETRY, SMALL_DATA) as small_source:
        runs = ((1, f.MIRROR_LCN), (v.MIRROR_RECORDS - 1, SECOND_MIRROR_LCN))
        contiguous = v.Mirror(((v.MIRROR_RECORDS, f.MIRROR_LCN),))
        save('small-clusters', v.build(small_source, 'standard', mirror=contiguous))
        for name, mirror in (('fragmented', v.Mirror(runs)),
                             ('list-resident', v.Mirror(runs, listed=True)),
                             ('list-nonresident', v.Mirror(runs, listed=True,
                                                         list_lcn=v.ORPHAN_LCN))):
            image = v.build(small_source, 'standard', mirror=mirror)
            save(name, image)
            replace_replica(image, f.VOLUME_RECORD, mirror,
                            lambda record: transform_record(record, fields={'lsn': 1}))
            save(name + '-late-difference', image, 'corrupt', compared=f.VOLUME_RECORD,
                 subject=f.VOLUME_RECORD, stage=STAGE_MIRROR)

    with geometry(source, LARGE_GEOMETRY, LARGE_DATA) as large_source:
        slots = f.CLUSTER // f.RECORD
        extra = slots - v.MIRROR_RECORDS
        for name, size, initialized in (('large-cluster-prefix', v.MIRROR_RECORDS * f.RECORD, None),
                                        ('extended', f.CLUSTER, None),
                                        ('extended-prefix-initialized', f.CLUSTER,
                                         v.MIRROR_RECORDS * f.RECORD)):
            mirror = v.Mirror(((1, f.MIRROR_LCN),), size=size, initialized=initialized)
            image = v.build(large_source, 'standard', mirror=mirror)
            save(name, image, slots=size // f.RECORD, unchecked=0 if size < f.CLUSTER else extra)
            if size == f.CLUSTER:
                image[replica_position(v.MIRROR_RECORDS, mirror)] = STALE_TAIL_BYTE
                save(name + '-unqualified-tail', image, slots=slots, unchecked=extra)
    return cases
