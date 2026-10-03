"""Original per-file descriptor inventories for complete read-only diagnostics.

Only selected unnamed zero-ID storage is interpreted. Descriptor packets come
from our independent named-field author; no product decoder supplies a verdict.
"""
import fixtures as f
import validation_fixtures as v
import secure_fixtures as s
from secure_store_fixtures import attributes, kind, resident_value

STAGE_ATTRIBUTES, STAGE_FINISHED, STAGE_SECURITY = 3, 6, 9
DESCRIPTOR_FIRST_LCN, DESCRIPTOR_SECOND_LCN = 170, 178
LIST_INSTANCE = 7
EXTENSION_RECORD = 41
LARGE_DESCRIPTOR_BYTES = 9001
DESCRIPTOR_MAX_BYTES = 1024 * 1024
UNKNOWN_ACL_REVISION = 0xff
UNKNOWN_ACE_TYPE = 0xff
INVALID_SID_COUNT = 16
FILE_ATTRIBUTE_SYSTEM = 0x0004
SID_FIELDS = ('revision', 'count', 'authority')
ACL_FIELDS = ('revision', 'reserved1', 'length', 'count', 'reserved2')


def rewrite(image, number, values):
    start = f.MFT_LCN * f.CLUSTER + number * f.RECORD
    header = dict(zip(s.FILE_HEADER_FIELDS, f.FILE_HEADER.unpack_from(image, start)))
    values.sort(key=kind)
    f.put_record(image, number, f.file_record(number, values,
                 directory=bool(header['flags'] & f.FILE_IS_DIRECTORY),
                 base=header['base'], links=header['links']))


def replace_security(image, number, replacements):
    values = [value for value in attributes(image, number) if kind(value) != v.SECURITY_ATTRIBUTE]
    rewrite(image, number, values + replacements)


def descriptor(payload, name=''):
    return f.resident(v.SECURITY_ATTRIBUTE, payload, v.SECURITY_INSTANCE, name)


def header_change(payload, **changes):
    result = bytearray(payload)
    fields = dict(zip(s.DESCRIPTOR_FIELDS, s.DESCRIPTOR.unpack_from(result)))
    fields.update(changes)
    s.DESCRIPTOR.pack_into(result, 0, *(fields[name] for name in s.DESCRIPTOR_FIELDS))
    return bytes(result)


def acl_change(payload, **changes):
    result = bytearray(payload)
    offset = dict(zip(s.DESCRIPTOR_FIELDS, s.DESCRIPTOR.unpack_from(result)))['dacl']
    fields = dict(zip(ACL_FIELDS, s.ACL.unpack_from(result, offset)))
    fields.update(changes)
    s.ACL.pack_into(result, offset, *(fields[name] for name in ACL_FIELDS))
    return bytes(result)


def sid_change(payload, **changes):
    result = bytearray(payload)
    offset = dict(zip(s.DESCRIPTOR_FIELDS, s.DESCRIPTOR.unpack_from(result)))['owner']
    fields = dict(zip(SID_FIELDS, s.SID_HEADER.unpack_from(result, offset)))
    fields.update(changes)
    s.SID_HEADER.pack_into(result, offset, *(fields[name] for name in SID_FIELDS))
    return bytes(result)


def bitmap_bits(image, number, type_, instance, indices):
    values = attributes(image, number)
    payload = bytearray(resident_value(next(value for value in values if kind(value) == type_)))
    for index in indices:
        payload[index // f.BYTE_BITS] |= 1 << (index % f.BYTE_BITS)
    rewrite(image, number, [f.resident(type_, payload, instance) if kind(value) == type_ else value
                            for value in values])


def replicas(image):
    first = f.MFT_LCN * f.CLUSTER
    f.put_data(image, f.MIRROR_LCN, image[first:first + v.MIRROR_RECORDS * f.RECORD])


def add_nonresident(image, payload, *, initialized=None, flags=0, listed=False):
    clusters = (len(payload) + f.CLUSTER - 1) // f.CLUSTER
    runs = [(1, DESCRIPTOR_FIRST_LCN)]
    if clusters > 1:
        runs.append((clusters - 1, DESCRIPTOR_SECOND_LCN))
    if any((lcn + count) * f.CLUSTER > len(image) for count, lcn in runs):
        return False
    first_runs = runs[:1] if listed else runs
    replace_security(image, v.HELLO_RECORD, [f.nonresident(v.SECURITY_ATTRIBUTE,
                     first_runs, len(payload), v.SECURITY_INSTANCE,
                     initialized=initialized, flags=flags, allocated=clusters * f.CLUSTER)])
    position = 0
    for count, lcn in runs:
        size = count * f.CLUSTER
        f.put_data(image, lcn, payload[position:position + size])
        position += size
    bitmap_bits(image, f.BITMAP_RECORD, f.DATA, v.DATA_INSTANCE,
                (lcn + offset for count, lcn in runs for offset in range(count)))
    if listed:
        owner, extension = f.file_reference(v.HELLO_RECORD), f.file_reference(EXTENSION_RECORD)
        listing = (f.list_entry(owner, v.SI_INSTANCE, 0, f.SI)
                   + f.list_entry(owner, v.FILENAME_INSTANCE, 0, f.FILENAME)
                   + f.list_entry(owner, v.SECURITY_INSTANCE, 0, v.SECURITY_ATTRIBUTE)
                   + f.list_entry(extension, v.SECURITY_INSTANCE, 1, v.SECURITY_ATTRIBUTE)
                   + f.list_entry(owner, v.DATA_INSTANCE, 0, f.DATA))
        values = attributes(image, v.HELLO_RECORD)
        values.append(f.resident(f.ATTR_LIST, listing, LIST_INSTANCE))
        rewrite(image, v.HELLO_RECORD, values)
        f.put_record(image, EXTENSION_RECORD, f.file_record(EXTENSION_RECORD,
                     [f.nonresident(v.SECURITY_ATTRIBUTE, runs[1:], 0,
                                    v.SECURITY_INSTANCE, lowest=1)], base=owner, links=0))
        bitmap_bits(image, f.MFT_RECORD, f.BITMAP, v.MFT_BITMAP_INSTANCE, [EXTENSION_RECORD])
    replicas(image)
    return True


def author(output, source):
    cases = []
    baseline = v.build(source, 'standard')

    def save(label, image, result='success', *, subject=v.HELLO_RECORD,
             stage=STAGE_SECURITY, attribute=v.SECURITY_ATTRIBUTE):
        name = 'validation-file-security-' + label + '.img'
        (output / name).write_bytes(image)
        success = result == 'success'
        cases.append({'image': name, 'result': result, 'complete': success,
                      'inventory': {'stage': STAGE_FINISHED if success else stage,
                                    'record_number': '0' if success else str(subject),
                                    'reference': '0000000000000000' if success else f'{f.file_reference(subject):016x}',
                                    'related_reference': '0000000000000000' if stage == STAGE_SECURITY or success
                                                         else f'{f.file_reference(subject):016x}',
                                    'attribute_type': 0 if success else attribute,
                                    'cluster': '0'}})

    for state in ('absent', 'null', 'empty', 'present'):
        image = bytearray(baseline)
        replace_security(image, v.HELLO_RECORD, [descriptor(s.sd(state))])
        save(state, image)
    for label, payload, result in (
            ('missing', None, 'corrupt metadata'),
            ('zero', b'', 'corrupt metadata'),
            ('short', s.sd()[:s.DESCRIPTOR.size - 1], 'corrupt metadata'),
            ('revision', header_change(s.sd(), revision=0), 'corrupt metadata'),
            ('absolute', header_change(s.sd('absent'), control=0), 'unsupported format'),
            ('owner-inside-header', header_change(s.sd(), owner=s.DESCRIPTOR.size - f.U16_BYTES), 'corrupt metadata'),
            ('sid-revision', sid_change(s.sd(), revision=0), 'corrupt metadata'),
            ('sid-count', sid_change(s.sd(), count=INVALID_SID_COUNT), 'corrupt metadata'),
            ('absent-dacl-offset', header_change(s.sd(), control=s.SD_SELF_RELATIVE), 'corrupt metadata'),
            ('acl-size', acl_change(s.sd(), length=s.ACL.size - f.U16_BYTES), 'corrupt metadata'),
            ('acl-revision', acl_change(s.sd(), revision=UNKNOWN_ACL_REVISION), 'unsupported format')):
        image = bytearray(baseline)
        replace_security(image, v.HELLO_RECORD, [] if payload is None else [descriptor(payload)])
        save(label, image, result)
    image = bytearray(baseline)
    replace_security(image, v.HELLO_RECORD, [descriptor(s.sd(), 'other')])
    save('named-only', image, 'corrupt metadata')
    image = bytearray(baseline)
    values = [v.standard(FILE_ATTRIBUTE_SYSTEM) if kind(value) == f.SI else value
              for value in attributes(image, v.HELLO_RECORD)
              if kind(value) != v.SECURITY_ATTRIBUTE]
    rewrite(image, v.HELLO_RECORD, values)
    save('ordinary-system-flag-missing', image, 'corrupt metadata')
    image = bytearray(baseline)
    replace_security(image, v.HELLO_RECORD, [descriptor(s.sd()),
                     f.resident(v.SECURITY_ATTRIBUTE, s.sd(), v.SECURITY_INSTANCE + 1)])
    save('duplicate', image, 'corrupt metadata', stage=STAGE_ATTRIBUTES)
    image = bytearray(baseline)
    payload = bytearray(s.sd())
    dacl = dict(zip(s.DESCRIPTOR_FIELDS, s.DESCRIPTOR.unpack_from(payload)))['dacl']
    payload[dacl + s.ACL.size] = UNKNOWN_ACE_TYPE
    replace_security(image, v.HELLO_RECORD, [descriptor(payload)])
    save('opaque-ace', image)
    image = bytearray(baseline)
    values = [v.standard(common_only=True) if kind(value) == f.SI else value
              for value in attributes(image, v.HELLO_RECORD)]
    rewrite(image, v.HELLO_RECORD, values)
    save('legacy-standard', image)
    image = v.build(source, 'hardlinks')
    replace_security(image, v.HELLO_RECORD, [descriptor(s.sd('empty'))])
    save('hardlinks', image)
    for label, number, result in (('root', f.ROOT_RECORD, 'corrupt metadata'),
                                  ('unrelated-system', f.UPCASE_RECORD, 'corrupt metadata')):
        image = bytearray(baseline)
        replace_security(image, number, [descriptor(header_change(s.sd(), revision=0))])
        save(label, image, result, subject=number)
    for number, case in ((f.MFT_RECORD, 'standard'), (v.MIRROR_RECORD, 'standard'),
                         (v.LOGFILE_RECORD, 'logfile-empty'), (f.BITMAP_RECORD, 'standard'),
                         (v.BAD_CLUSTERS_RECORD, 'bad-clusters-empty'), (f.UPCASE_RECORD, 'standard')):
        for label, payload, result in (('missing', None, 'success'),
                                       ('invalid', header_change(s.sd(), revision=0), 'corrupt metadata')):
            image = v.build(source, case)
            replace_security(image, number, [] if payload is None else [descriptor(payload)])
            replicas(image)
            save('internal-' + str(number) + '-' + label, image, result, subject=number)
    for number in (f.VOLUME_RECORD, v.BOOT_RECORD):
        image = bytearray(baseline)
        replace_security(image, number, [])
        replicas(image)
        save('required-internal-' + str(number), image, 'corrupt metadata', subject=number)
    for label, payload, result in (('inert-absent', None, 'success'),
                                    ('inert-present', s.sd('null'), 'success'),
                                    ('inert-invalid', header_change(s.sd(), revision=0), 'corrupt metadata')):
        image = v.build(source, 'reserved-inert')
        if payload is not None:
            replace_security(image, v.RESERVED_FIRST, [descriptor(payload)])
        save(label, image, result, subject=v.RESERVED_FIRST)
    image = bytearray(baseline)
    owner, extension = f.file_reference(v.HELLO_RECORD), f.file_reference(EXTENSION_RECORD)
    values = [value for value in attributes(image, v.HELLO_RECORD) if kind(value) != v.SECURITY_ATTRIBUTE]
    listing = (f.list_entry(owner, v.SI_INSTANCE, 0, f.SI)
               + f.list_entry(owner, v.FILENAME_INSTANCE, 0, f.FILENAME)
               + f.list_entry(extension, v.SECURITY_INSTANCE, 0, v.SECURITY_ATTRIBUTE)
               + f.list_entry(owner, v.DATA_INSTANCE, 0, f.DATA))
    values.append(f.resident(f.ATTR_LIST, listing, LIST_INSTANCE))
    rewrite(image, v.HELLO_RECORD, values)
    f.put_record(image, EXTENSION_RECORD, f.file_record(EXTENSION_RECORD,
                 [descriptor(s.sd())], base=owner, links=0))
    bitmap_bits(image, f.MFT_RECORD, f.BITMAP, v.MFT_BITMAP_INSTANCE, [EXTENSION_RECORD])
    replicas(image)
    save('listed-resident', image)
    for label, size, result, options in (
            ('nonresident', len(s.sd()), 'success', {}),
            ('fragmented', LARGE_DESCRIPTOR_BYTES, 'success', {}),
            ('listed-fragmented', LARGE_DESCRIPTOR_BYTES, 'success', {'listed': True}),
            ('uninitialized', LARGE_DESCRIPTOR_BYTES, 'corrupt metadata', {'initialized': LARGE_DESCRIPTOR_BYTES - 1}),
            ('sparse-flag', LARGE_DESCRIPTOR_BYTES, 'corrupt metadata', {'flags': f.SPARSE}),
            ('maximum', DESCRIPTOR_MAX_BYTES, 'success', {}),
            ('over-limit', DESCRIPTOR_MAX_BYTES + 1, 'resource limit', {})):
        image = bytearray(baseline)
        payload = s.sd() + bytes(size - len(s.sd()))
        if add_nonresident(image, payload, **options):
            save(label, image, result)
    return cases
