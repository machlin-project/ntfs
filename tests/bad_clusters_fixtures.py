"""Original complete bad-cluster inventories; no bad-sector bytes are read.

All list references, sparse holes and physical owners come from this author.
The diagnostic's expected inventories do not import product decoder results.
Flagged storage retains explicit unsupported qualification.
"""
import struct
import fixtures as f
import validation_fixtures as v
from secure_store_fixtures import attributes, kind, resident_value

BAD_NAME = '$Bad'
FIRST_BAD_CLUSTER, SECOND_BAD_CLUSTER = 160, 192
SECOND_BAD_COUNT = 2
EXTENSION_RECORD, SECOND_EXTENSION_RECORD = 40, 41
LIST_LCN = 172
BAD_INSTANCE = 5
CONTINUATION_INSTANCE = 7
SECOND_CONTINUATION_INSTANCE = 8
LIST_INSTANCE = 9
UNKNOWN_ATTRIBUTE_FLAG = 0x0040
INVALID_MAPPING_BYTE = 0xff
STAGE_FINISHED = 6
STAGE_ATTRIBUTES, STAGE_ALLOCATION = 3, 5
BASE_RECORDS = 10
BASE_STREAMS = 7
BASE_RUNS = 7
BASE_CLAIMED_CLUSTERS = 53
ORDINARY_BAD_CONTENT = b'ordinary named stream'
NONRESIDENT_FIELDS = ('lowest', 'highest', 'mapping_offset', 'compression_unit',
                      'allocated', 'size', 'initialized')
ATTRIBUTE_FIELDS = ('type', 'length', 'nonresident', 'name_length', 'name_offset',
                    'flags', 'instance')
FILE_HEADER = struct.Struct('<4sHHQHHHHIIQHHI')
FILE_FIELDS = ('magic', 'usa_offset', 'usa_count', 'lsn', 'sequence', 'links',
               'attrs_offset', 'flags', 'used', 'allocated', 'base',
               'next_instance', 'alignment', 'number')


def rewrite(image, number, values):
    start = f.MFT_LCN * f.CLUSTER + number * f.RECORD
    fields = dict(zip(FILE_FIELDS, FILE_HEADER.unpack_from(image, start)))
    values.sort(key=kind)
    f.put_record(image, number, f.file_record(number, values,
                 directory=bool(fields['flags'] & f.FILE_IS_DIRECTORY),
                 base=fields['base'], links=fields['links']))


def bitmap(image, number, type_, instance, *, set_bits=(), clear_bits=()):
    values = attributes(image, number)
    data = bytearray(resident_value(next(value for value in values if kind(value) == type_)))
    for index in set_bits:
        data[index // f.BYTE_BITS] |= 1 << (index % f.BYTE_BITS)
    for index in clear_bits:
        data[index // f.BYTE_BITS] &= ~(1 << (index % f.BYTE_BITS))
    rewrite(image, number, [f.resident(type_, data, instance) if kind(value) == type_ else value
                            for value in values])


def replicas(image):
    first = f.MFT_LCN * f.CLUSTER
    f.put_data(image, f.MIRROR_LCN, image[first:first + v.MIRROR_RECORDS * f.RECORD])


def extent(runs, size, instance, lowest=0, *, flags=0, initialized=0, allocated=None):
    return f.nonresident(f.DATA, runs, size, instance, BAD_NAME,
                         lowest=lowest, flags=flags, initialized=initialized,
                         allocated=allocated)


def extent_change(attribute, **changes):
    result = bytearray(attribute)
    fields = dict(zip(NONRESIDENT_FIELDS,
                      f.NONRESIDENT_HEADER.unpack_from(result, f.ATTR_HEADER.size)))
    fields.update(changes)
    f.NONRESIDENT_HEADER.pack_into(result, f.ATTR_HEADER.size,
                                  *(fields[name] for name in NONRESIDENT_FIELDS))
    return bytes(result)


def build(source, label):
    image = v.build(source, 'bad-clusters-empty')
    cluster_count = len(image) // f.CLUSTER
    volume_bytes = cluster_count * f.CLUSTER
    owner = f.file_reference(v.BAD_CLUSTERS_RECORD)
    extension = f.file_reference(EXTENSION_RECORD)
    second_extension = f.file_reference(SECOND_EXTENSION_RECORD)
    values = [value for value in attributes(image, v.BAD_CLUSTERS_RECORD)
              if kind(value) != f.DATA or dict(zip(ATTRIBUTE_FIELDS,
                         f.ATTR_HEADER.unpack_from(value)))['name_length'] == 0]
    first = extent([(FIRST_BAD_CLUSTER, None)], volume_bytes, BAD_INSTANCE,
                   initialized=volume_bytes if label == 'initialized-full' else 0,
                   allocated=volume_bytes)
    tail_runs = [(1, FIRST_BAD_CLUSTER),
                 (cluster_count - FIRST_BAD_CLUSTER - 1, None)]
    continuation = extent(tail_runs, 0, CONTINUATION_INSTANCE, FIRST_BAD_CLUSTER)
    extension_values = [continuation]
    second_values = []
    first_reference = owner
    continuation_reference = extension
    extension_owner = owner
    physical = {FIRST_BAD_CLUSTER}
    extra_clusters = set()

    if label == 'all-holes':
        physical.clear()
        extension_values = [extent([(cluster_count - FIRST_BAD_CLUSTER, None)],
                                   0, CONTINUATION_INSTANCE, FIRST_BAD_CLUSTER)]
    elif label == 'multiple':
        extension_values = [extent([(1, FIRST_BAD_CLUSTER),
                          (SECOND_BAD_CLUSTER - FIRST_BAD_CLUSTER - 1, None)],
                         0, CONTINUATION_INSTANCE, FIRST_BAD_CLUSTER)]
        second_values = [extent([(SECOND_BAD_COUNT, SECOND_BAD_CLUSTER),
                         (cluster_count - SECOND_BAD_CLUSTER - SECOND_BAD_COUNT, None)],
                        0, SECOND_CONTINUATION_INSTANCE, SECOND_BAD_CLUSTER)]
        physical.update(range(SECOND_BAD_CLUSTER, SECOND_BAD_CLUSTER + SECOND_BAD_COUNT))
    elif label == 'first-in-extension':
        first_reference = extension
        first = extent([(FIRST_BAD_CLUSTER, None), *tail_runs], volume_bytes,
                       BAD_INSTANCE, allocated=volume_bytes)
        extension_values = [first]
        continuation_reference = None
    elif label == 'owner-continuation':
        continuation_reference = owner
        extension_values = []
        values.append(continuation)
    elif label == 'stale-reference':
        continuation_reference = f.file_reference(EXTENSION_RECORD, f.FILE_SEQUENCE + 1)
    elif label == 'wrong-owner':
        extension_owner = f.file_reference(v.HELLO_RECORD)
    elif label in ('gap', 'overlap'):
        lowest = FIRST_BAD_CLUSTER + (1 if label == 'gap' else -1)
        extension_values = [extent([(cluster_count - lowest, None)],
                                   0, CONTINUATION_INSTANCE, lowest)]
        physical.clear()
    elif label == 'short':
        extension_values = [extent([(1, FIRST_BAD_CLUSTER),
                           (cluster_count - FIRST_BAD_CLUSTER - 2, None)],
                          0, CONTINUATION_INSTANCE, FIRST_BAD_CLUSTER)]
    elif label == 'excess':
        extension_values = [extent([(1, FIRST_BAD_CLUSTER),
                           (cluster_count - FIRST_BAD_CLUSTER, None)],
                          0, CONTINUATION_INSTANCE, FIRST_BAD_CLUSTER)]
    elif label == 'wrong-target':
        target = FIRST_BAD_CLUSTER + 1
        extension_values = [extent([(1, target),
                           (cluster_count - FIRST_BAD_CLUSTER - 1, None)],
                          0, CONTINUATION_INSTANCE, FIRST_BAD_CLUSTER)]
        physical = {target}
    elif label == 'continuation-sparse':
        extension_values = [extent(tail_runs, 0, CONTINUATION_INSTANCE,
                                   FIRST_BAD_CLUSTER, flags=f.SPARSE)]
    elif label == 'continuation-compression-unit':
        extension_values = [extent_change(continuation, compression_unit=1)]
    elif label == 'invalid-mapping':
        damaged = bytearray(continuation)
        mapping_offset = dict(zip(NONRESIDENT_FIELDS,
            f.NONRESIDENT_HEADER.unpack_from(damaged, f.ATTR_HEADER.size)))['mapping_offset']
        damaged[mapping_offset:] = bytes([INVALID_MAPPING_BYTE]) * (len(damaged) - mapping_offset)
        extension_values = [bytes(damaged)]
    elif label == 'resident-first':
        first = f.resident(f.DATA, b'', BAD_INSTANCE, BAD_NAME)
    elif label == 'allocated-size':
        first = extent_change(first, allocated=volume_bytes - f.CLUSTER)
    elif label == 'initialized-partial':
        first = extent_change(first, initialized=1)
    elif label == 'first-compression-unit':
        first = extent_change(first, compression_unit=1)
    elif label in ('first-sparse', 'first-encrypted', 'first-compressed', 'first-unknown'):
        flags = {'first-sparse': f.SPARSE, 'first-encrypted': f.ENCRYPTED,
                 'first-compressed': f.COMPRESSED, 'first-unknown': UNKNOWN_ATTRIBUTE_FLAG}[label]
        first = extent([(FIRST_BAD_CLUSTER, None)], volume_bytes, BAD_INSTANCE,
                       flags=flags, allocated=volume_bytes)
    elif label == 'orphan-extension':
        first = extent([(FIRST_BAD_CLUSTER, None), *tail_runs], volume_bytes,
                       BAD_INSTANCE, allocated=volume_bytes)
        continuation_reference = None
    elif label == 'ordinary-name':
        ordinary = attributes(image, v.HELLO_RECORD)
        ordinary.append(f.resident(f.DATA, ORDINARY_BAD_CONTENT, v.ADS_INSTANCE, BAD_NAME))
        rewrite(image, v.HELLO_RECORD, ordinary)

    if first_reference == owner:
        values.append(first)
    listing = [f.list_entry(owner, v.SI_INSTANCE, 0, f.SI),
               f.list_entry(owner, v.FILENAME_INSTANCE, 0, f.FILENAME),
               f.list_entry(owner, v.SECURITY_INSTANCE, 0, v.SECURITY_ATTRIBUTE),
               f.list_entry(owner, v.DATA_INSTANCE, 0),
               f.list_entry(first_reference, BAD_INSTANCE, 0, name=BAD_NAME)]
    if continuation_reference is not None and label != 'missing-continuation':
        listed_lowest = (FIRST_BAD_CLUSTER + (1 if label == 'gap' else -1)
                         if label in ('gap', 'overlap') else FIRST_BAD_CLUSTER)
        listing.append(f.list_entry(continuation_reference, CONTINUATION_INSTANCE,
                                    listed_lowest, name=BAD_NAME))
    if second_values:
        listing.append(f.list_entry(second_extension, SECOND_CONTINUATION_INSTANCE,
                                    SECOND_BAD_CLUSTER, name=BAD_NAME))
    if label == 'duplicate-list':
        listing.append(listing[-1])
    if label == 'duplicate-first':
        second_values = [extent([(cluster_count, None)], volume_bytes,
                               SECOND_CONTINUATION_INSTANCE, allocated=volume_bytes)]
        listing.append(f.list_entry(second_extension, SECOND_CONTINUATION_INSTANCE,
                                    0, name=BAD_NAME))
    if label == 'out-of-order':
        listing[-2:] = reversed(listing[-2:])
    payload = b''.join(listing)
    list_attribute = f.resident(f.ATTR_LIST, payload, LIST_INSTANCE)
    if label == 'nonresident-list':
        f.put_data(image, LIST_LCN, payload)
        extra_clusters.add(LIST_LCN)
        list_attribute = f.nonresident(f.ATTR_LIST, [(1, LIST_LCN)], len(payload), LIST_INSTANCE)
    values.append(list_attribute)
    rewrite(image, v.BAD_CLUSTERS_RECORD, values)
    extensions = []
    for number, contents in ((EXTENSION_RECORD, extension_values),
                              (SECOND_EXTENSION_RECORD, second_values)):
        if contents:
            f.put_record(image, number, f.file_record(number, contents,
                         base=extension_owner, links=0))
            extensions.append(number)
    bitmap(image, f.MFT_RECORD, f.BITMAP, v.MFT_BITMAP_INSTANCE, set_bits=extensions)
    bitmap(image, f.BITMAP_RECORD, f.DATA, v.DATA_INSTANCE,
           set_bits=physical | extra_clusters,
           clear_bits=[FIRST_BAD_CLUSTER] if label == 'free-bad-cluster' else [])
    replicas(image)
    return image, {'base_records': str(BASE_RECORDS), 'extension_records': str(len(extensions)),
                   'record_slots': str(f.MFT_COUNT), 'records_scanned': str(f.MFT_COUNT),
                   'filename_attributes': str(BASE_RECORDS - 1),
                   'index_entries': str(BASE_RECORDS - 1), 'directories': '1',
                   'deferred_dos_link_counts': '0',
                   'physical_runs': str(BASE_RUNS + bool(physical)
                                        + bool(second_values) + len(extra_clusters)),
                   'streams': str(BASE_STREAMS + len(extra_clusters)),
                   'claimed_clusters': str(BASE_CLAIMED_CLUSTERS + len(physical) + len(extra_clusters)),
                   'allocated_clusters': str(BASE_CLAIMED_CLUSTERS + len(physical) + len(extra_clusters)),
                   'unclaimed_clusters': '0', 'stage': STAGE_FINISHED,
                   'reference': '0000000000000000', 'related_reference': '0000000000000000',
                   'record_number': '0', 'attribute_type': 0, 'cluster': '0'}


def author(output, source):
    cases = []
    positives = ('split', 'all-holes', 'multiple', 'first-in-extension', 'owner-continuation',
                 'nonresident-list', 'initialized-full', 'ordinary-name')
    corrupt = ('gap', 'overlap', 'short', 'excess', 'wrong-target', 'resident-first',
               'allocated-size', 'initialized-partial', 'first-compression-unit',
               'continuation-compression-unit', 'continuation-sparse', 'invalid-mapping',
               'missing-continuation', 'duplicate-list', 'duplicate-first', 'out-of-order',
               'orphan-extension', 'free-bad-cluster')
    unsupported = ('first-sparse', 'first-encrypted', 'first-compressed', 'first-unknown')
    stale = ('stale-reference', 'wrong-owner')
    for labels, result in ((positives, 'success'), (corrupt, 'corrupt metadata'),
                           (unsupported, 'unsupported format'), (stale, 'stale file reference')):
        for label in labels:
            image, inventory = build(source, label)
            name = 'validation-bad-chain-' + label + '.img'
            (output / name).write_bytes(image)
            case = {'image': name, 'result': result, 'complete': result == 'success'}
            if result == 'success':
                case['inventory'] = inventory
            else:
                subject = EXTENSION_RECORD if label == 'orphan-extension' else v.BAD_CLUSTERS_RECORD
                related = f.file_reference(v.BAD_CLUSTERS_RECORD)
                attribute, cluster, stage = f.DATA, 0, STAGE_ATTRIBUTES
                if label in ('stale-reference', 'wrong-owner'):
                    related = f.file_reference(EXTENSION_RECORD,
                              f.FILE_SEQUENCE + 1 if label == 'stale-reference' else f.FILE_SEQUENCE)
                    attribute = 0
                elif label == 'free-bad-cluster':
                    related, cluster, stage = 0, FIRST_BAD_CLUSTER, STAGE_ALLOCATION
                case['inventory'] = {'stage': stage, 'record_number': str(subject),
                     'reference': f'{f.file_reference(subject):016x}',
                     'related_reference': f'{related:016x}', 'attribute_type': attribute,
                     'cluster': str(cluster)}
            cases.append(case)
    return cases
