"""Independent complete-view inventories and off-path corruption observations."""
import json
import struct
import fixtures as f
import secure_fixtures as s

STAGE_SII, STAGE_SII_ALLOCATION = 1, 2
STAGE_SDH, STAGE_SDH_ALLOCATION = 3, 4
STAGE_DESCRIPTORS, STAGE_FINISHED = 5, 6
CATALOG_ENTRIES = 129
LEAF_ENTRIES = 3
CATALOG_SII_LCN, CATALOG_SDH_LCN = 270, 320
INDEX_GARBAGE = 0xa9
VALID_DEPTH, EXCESS_DEPTH = 31, 32


def ordered(locators, by_hash):
    return sorted(locators.values(),
                  key=lambda value: (value['hash'], value['id']) if by_hash else value['id'])


def tree_root(locators, by_hash=False, block_size=f.CLUSTER, last_child=None):
    values = ordered(locators, by_hash)
    unit = f.CLUSTER if f.CLUSTER <= block_size else f.SECTOR
    next_vcn = block_size // unit if last_child is None else last_child
    return s.view_root(s.view_entry(values[2], by_hash, 0) + s.view_entry(child=next_vcn),
                       by_hash, True, block_size=block_size, clusters=block_size // unit)


def tree_blocks(locators, by_hash=False, block_size=f.CLUSTER, extra=False, damage=None):
    values = ordered(locators, by_hash)
    unit = f.CLUSTER if f.CLUSTER <= block_size else f.SECTOR
    right = values[3:]
    if damage == 'lower':
        right = [values[1]]
    blocks = [s.view_block(0, b''.join(s.view_entry(value, by_hash) for value in values[:2])
                           + s.view_entry(), block_size=block_size),
              s.view_block(block_size // unit,
                           b''.join(s.view_entry(value, by_hash) for value in right)
                           + s.view_entry(), block_size=block_size)]
    if damage == 'torn':
        blocks[1][f.SECTOR - f.U16_BYTES] ^= 1
    elif damage == 'vcn':
        fields = list(s.INDEX_BLOCK_HEADER.unpack_from(blocks[1]))
        fields[-1] = 0
        s.INDEX_BLOCK_HEADER.pack_into(blocks[1], 0, *fields)
    elif damage == 'usa':
        fields = list(f.INDEX_HEADER.unpack_from(blocks[1], s.INDEX_BLOCK_HEADER.size))
        fields[0] = f.INDEX_HEADER.size
        f.INDEX_HEADER.pack_into(blocks[1], s.INDEX_BLOCK_HEADER.size, *fields)
    if extra:
        blocks.append(bytes([INDEX_GARBAGE]) * block_size)
    return blocks


def catalog_blocks(locators, by_hash):
    values = ordered(locators, by_hash)
    groups = [values[start:start + LEAF_ENTRIES + 1]
              for start in range(0, len(values), LEAF_ENTRIES + 1)]
    separators, leaves = [], []
    for slot, group in enumerate(groups):
        leaf = group if slot == len(groups) - 1 else group[:-1]
        leaves.append(s.view_block(slot + 1, b''.join(s.view_entry(v, by_hash) for v in leaf)
                                   + s.view_entry()))
        if slot != len(groups) - 1:
            separators.append(s.view_entry(group[-1], by_hash, slot + 1))
    internal = s.view_block(0, b''.join(separators) + s.view_entry(child=len(leaves)), True)
    return [internal, *leaves]


def author(output, save, descriptors):
    manifest = []

    def case(label, result='success', stage=STAGE_FINISHED, counts=None, **options):
        if not save('store-' + label, **options):
            return
        bodies = options.get('bodies', descriptors)
        expected = {'image': 'secure-store-' + label + '.img', 'result': result,
                    'stage': stage, 'complete': result == 'success'}
        if expected['complete']:
            expected['counts'] = {'sii_entries': len(bodies), 'sdh_entries': len(bodies),
                                  'descriptors': len(bodies),
                                  'descriptor_bytes': sum(map(len, bodies.values())),
                                  'sii_blocks': 0, 'sdh_blocks': 0}
        expected.setdefault('counts', {}).update(counts or {})
        manifest.append(expected)

    case('leaf')
    case('physical-order', body_order=list(reversed(sorted(descriptors))))
    case('maximum-id', bodies={s.DWORD_MAX: s.sd()}, file_id=s.DWORD_MAX)
    case('large', bodies={s.SECURITY_ID: s.sd() + bytes(s.LARGE_DESCRIPTOR_BYTES - len(s.sd()))})
    case('maximum', bodies={s.SECURITY_ID: s.sd() + bytes(s.SDS_BLOCK_BYTES - s.LOCATOR.size - len(s.sd()))})
    case('second-pair', bodies={s.SECURITY_ID: s.sd()}, start_offset=s.SDS_PAIR_BYTES)
    case('listed', listed='valid')
    case('empty', sii=lambda loc: s.view_root(s.view_entry()),
         sdh=lambda loc: s.view_root(s.view_entry(), True), file_id=0,
         counts={'sii_entries': 0, 'sdh_entries': 0, 'descriptors': 0, 'descriptor_bytes': 0})
    for block_size in (f.SECTOR, f.CLUSTER, 2 * f.CLUSTER):
        case('tree-' + str(block_size),
             sii=lambda loc, size=block_size: tree_root(loc, block_size=size),
             sdh=lambda loc, size=block_size: tree_root(loc, True, size),
             tree={by_hash: (lambda loc, h=by_hash, size=block_size:
                             tree_blocks(loc, h, size)) for by_hash in (False, True)},
             index_lcns={False: s.SII_LCN, True: s.SDH_LCN + 4},
             counts={'sii_blocks': 2, 'sdh_blocks': 2})
    case('free-garbage', sii=tree_root,
         tree={False: lambda loc: tree_blocks(loc, extra=True)}, bitmaps={False: b'\x03'},
         counts={'sii_blocks': 2})
    case('leaf-free-storage', tree={False: lambda loc: [bytes([INDEX_GARBAGE]) * f.CLUSTER]},
         bitmaps={False: b'\x00'})
    many = {s.SECURITY_ID + index: s.sd('null') for index in range(CATALOG_ENTRIES)}
    blocks = 1 + (CATALOG_ENTRIES + LEAF_ENTRIES) // (LEAF_ENTRIES + 1)
    bits = ((1 << blocks) - 1).to_bytes((blocks + f.BYTE_BITS - 1) // f.BYTE_BITS, 'little')
    case('catalog', bodies=many,
         sii=lambda loc: s.view_root(s.view_entry(child=0), large=True),
         sdh=lambda loc: s.view_root(s.view_entry(child=0), True, True),
         tree={h: (lambda loc, h=h: catalog_blocks(loc, h)) for h in (False, True)},
         bitmaps={False: bits, True: bits},
         index_lcns={False: CATALOG_SII_LCN, True: CATALOG_SDH_LCN},
         counts={'sii_blocks': blocks, 'sdh_blocks': blocks})
    for count in (VALID_DEPTH, EXCESS_DEPTH):
        case('depth-' + str(count), bodies={s.SECURITY_ID: s.sd()}, deep=(count, False),
             counts={'sii_blocks': count} if count == VALID_DEPTH else None,
             result='success' if count == VALID_DEPTH else 'resource limit',
             stage=STAGE_FINISHED if count == VALID_DEPTH else STAGE_SII)
    case('cycle', bodies={s.SECURITY_ID: s.sd()}, deep=(2, True),
         result='corrupt metadata', stage=STAGE_SII)
    for by_hash in (False, True):
        prefix = 'sdh' if by_hash else 'sii'
        root_option = {'sdh' if by_hash else 'sii': lambda loc, h=by_hash: tree_root(loc, h)}
        for damage in ('lower', 'torn', 'vcn', 'usa'):
            case(prefix + '-right-' + damage, result='corrupt metadata',
                 stage=STAGE_SDH if by_hash else STAGE_SII,
                 tree={by_hash: lambda loc, h=by_hash, d=damage: tree_blocks(loc, h, damage=d)},
                 **root_option)
        case(prefix + '-alias', result='corrupt metadata',
             stage=STAGE_SDH if by_hash else STAGE_SII,
             tree={by_hash: lambda loc, h=by_hash: tree_blocks(loc, h)},
             **{'sdh' if by_hash else 'sii': lambda loc, h=by_hash: tree_root(loc, h, last_child=0)})
        for label, bits, extra, length in (('orphan', b'\x07', True, None),
                                          ('outside', b'\x07', False, None),
                                          ('late-used', b'\x03\x01', False, None),
                                          ('partial', b'\x03', True, 3 * f.CLUSTER - 1)):
            case(prefix + '-' + label, result='corrupt metadata',
                 stage=STAGE_SDH_ALLOCATION if by_hash else STAGE_SII_ALLOCATION,
                 tree={by_hash: lambda loc, h=by_hash, extra=extra: tree_blocks(loc, h, extra=extra)},
                 bitmaps={by_hash: bits}, index_sizes={} if length is None else {by_hash: length},
                 **root_option)
        case(prefix + '-free-child', result='corrupt metadata',
             stage=STAGE_SDH if by_hash else STAGE_SII,
             tree={by_hash: lambda loc, h=by_hash: tree_blocks(loc, h)},
             bitmaps={by_hash: b'\x01'}, **root_option)
    case('missing-sdh', result='corrupt metadata', stage=STAGE_SDH,
         sdh=lambda loc: s.view_root(b''.join(s.view_entry(value, True)
                         for value in ordered(loc, True) if value['id'] != s.SECURITY_ID + 3)
                         + s.view_entry(), True))
    case('extra-sdh', result='corrupt metadata', stage=STAGE_SDH,
         sdh=lambda loc: s.view_root(b''.join(s.view_entry(value, True)
                         for value in sorted([*loc.values(), dict(loc[s.SECURITY_ID], id=s.SECURITY_ID + 4)],
                                              key=lambda v: (v['hash'], v['id'])))
                         + s.view_entry(), True))
    case('locator-disagrees', result='corrupt metadata', stage=STAGE_SDH,
         sdh=lambda loc: s.view_root(b''.join(s.view_entry(dict(value, offset=s.SDS_ALIGNMENT)
                         if value['id'] == s.SECURITY_ID + 3 else value, True)
                         for value in ordered(loc, True)) + s.view_entry(), True))
    case('overlap', result='corrupt metadata', stage=STAGE_DESCRIPTORS,
         locator_changes={s.SECURITY_ID + 1: {'offset': s.SDS_ALIGNMENT}})
    last_offset = 0
    for security_id, payload in sorted(descriptors.items()):
        if security_id == max(descriptors):
            break
        last_offset = (last_offset + s.LOCATOR.size + len(payload) + s.SDS_ALIGNMENT - 1) // s.SDS_ALIGNMENT * s.SDS_ALIGNMENT
    for label, offset in (('off-path-primary', last_offset + s.LOCATOR.size),
                          ('off-path-copy-header', s.SDS_BLOCK_BYTES + last_offset),
                          ('off-path-copy-body', s.SDS_BLOCK_BYTES + last_offset + s.LOCATOR.size)):
        case(label, result='corrupt metadata', stage=STAGE_DESCRIPTORS,
             copies=[(offset, b'\xff')])
    invalid = bytearray(descriptors[max(descriptors)])
    fields = dict(zip(s.DESCRIPTOR_FIELDS, s.DESCRIPTOR.unpack_from(invalid)))
    fields['revision'] = 0
    s.DESCRIPTOR.pack_into(invalid, 0, *(fields[name] for name in s.DESCRIPTOR_FIELDS))
    case('off-path-descriptor', result='corrupt metadata', stage=STAGE_DESCRIPTORS,
         bodies={**descriptors, max(descriptors): bytes(invalid)})
    case('unknown-collation', result='unsupported format', stage=STAGE_SII,
         sii=lambda loc: s.view_root(s.view_entry(), collation=s.COLLATION_SECURITY_HASH))
    (output / 'secure-store-cases.json').write_text(json.dumps(manifest, indent=2) + '\n')
    author_validation(output)


def attributes(image, number):
    """Restore and extract only our own authored FILE attributes, with named fields."""
    start = f.MFT_LCN * f.CLUSTER + number * f.RECORD
    record = bytearray(image[start:start + f.RECORD])
    header = dict(zip(s.FILE_HEADER_FIELDS, f.FILE_HEADER.unpack_from(record)))
    for sector in range(1, header['usa_count']):
        tail = sector * f.SECTOR - f.U16_BYTES
        saved = header['usa_offset'] + sector * f.U16_BYTES
        record[tail:tail + f.U16_BYTES] = record[saved:saved + f.U16_BYTES]
    result, position = [], header['attrs_offset']
    while struct.unpack_from('<I', record, position)[0] != f.ATTR_END:
        fields = dict(zip(s.ATTR_HEADER_FIELDS, f.ATTR_HEADER.unpack_from(record, position)))
        result.append(bytes(record[position:position + fields['length']]))
        position += fields['length']
    return result


def kind(attribute):
    return dict(zip(s.ATTR_HEADER_FIELDS, f.ATTR_HEADER.unpack_from(attribute)))['type']


def resident_value(attribute):
    header = dict(zip(('length', 'offset', 'indexed', 'reserved'),
                      f.RESIDENT_HEADER.unpack_from(attribute, f.ATTR_HEADER.size)))
    return attribute[header['offset']:header['offset'] + header['length']]


def author_validation(output):
    import validation_fixtures as v

    source, _, _ = f.make_image()
    manifest = []
    secure_filename_instance = s.SDS_LIST_INSTANCE + 1
    nonresident_fields = ('lowest', 'highest', 'runs_offset', 'compression',
                          'allocated', 'size', 'initialized')

    def save(label, variant='leaf', file_id=s.SECURITY_ID, absent=False, file_payload=None):
        image = v.build(source, 'standard')
        secure_source = (output / ('secure-store-' + variant + '.img')).read_bytes()
        secure_attributes = attributes(secure_source, s.SECURE_RECORD)
        hello = attributes(image, v.HELLO_RECORD)
        hello = [f.standard(security_id=file_id) if kind(attr) == f.SI else attr for attr in hello]
        if file_payload is not None:
            hello = [f.resident(v.SECURITY_ATTRIBUTE, file_payload, v.SECURITY_INSTANCE)
                     if kind(attr) == v.SECURITY_ATTRIBUTE else attr for attr in hello]
        f.put_record(image, v.HELLO_RECORD, f.file_record(v.HELLO_RECORD, hello))
        if not absent:
            secure_attributes.append(v.filename(v.Link('$Secure'), secure_filename_instance))
            secure_attributes.sort(key=kind)
            f.put_record(image, s.SECURE_RECORD, f.file_record(s.SECURE_RECORD, secure_attributes, view=True))
            # This complete inventory uses a leaf store: only SDS owns clusters.
            sds = next(attr for attr in secure_attributes if kind(attr) == f.DATA)
            storage = dict(zip(nonresident_fields, f.NONRESIDENT_HEADER.unpack_from(sds, f.ATTR_HEADER.size)))
            first = s.SDS_LCN * f.CLUSTER
            image[first:first + storage['allocated']] = secure_source[first:first + storage['allocated']]
            mft = attributes(image, f.MFT_RECORD)
            bits = bytearray(resident_value(next(attr for attr in mft if kind(attr) == f.BITMAP)))
            bits[s.SECURE_RECORD // f.BYTE_BITS] |= 1 << (s.SECURE_RECORD % f.BYTE_BITS)
            mft = [f.resident(f.BITMAP, bits, v.MFT_BITMAP_INSTANCE) if kind(attr) == f.BITMAP else attr for attr in mft]
            f.put_record(image, f.MFT_RECORD, f.file_record(f.MFT_RECORD, mft))
            allocation = attributes(image, f.BITMAP_RECORD)
            bits = bytearray(resident_value(next(attr for attr in allocation if kind(attr) == f.DATA)))
            for cluster in range(s.SDS_LCN, s.SDS_LCN + storage['allocated'] // f.CLUSTER):
                bits[cluster // f.BYTE_BITS] |= 1 << (cluster % f.BYTE_BITS)
            allocation = [f.resident(f.DATA, bits, v.DATA_INSTANCE) if kind(attr) == f.DATA else attr for attr in allocation]
            f.put_record(image, f.BITMAP_RECORD, f.file_record(f.BITMAP_RECORD, allocation))
            items = [(f.MFT_RECORD, v.Link('$MFT'), False), (v.MIRROR_RECORD, v.Link('$MFTMirr'), False),
                     (f.VOLUME_RECORD, v.Link('$Volume'), False), (f.BITMAP_RECORD, v.Link('$Bitmap'), False),
                     (v.BOOT_RECORD, v.Link('$Boot'), False), (f.UPCASE_RECORD, v.Link('$UpCase'), False),
                     (s.SECURE_RECORD, v.Link('$Secure'), False), (v.HELLO_RECORD, v.Link('hello.txt'), False),
                     (v.FRAGMENTED_RECORD, v.Link('fragmented.bin'), False)]
            items.sort(key=v.collation)
            f.put_data(image, f.INDEX_LCN, f.index_block(0, [v.index_entry(*item) for item in items]))
            first = f.MFT_LCN * f.CLUSTER
            f.put_data(image, f.MIRROR_LCN, image[first:first + v.MIRROR_RECORDS * f.RECORD])
        name = 'validation-secure-' + label + '.img'
        (output / name).write_bytes(image)
        success = label in ('valid', 'inline-valid')
        manifest.append({'image': name, 'result': 'success' if success else 'corrupt metadata',
                         'complete': success, 'stage': 6 if success else 9,
                         'record_number': 0 if success else v.HELLO_RECORD
                                          if absent or label in ('missing-id', 'inline-invalid')
                                          else s.SECURE_RECORD})

    save('valid')
    save('inline-valid', file_id=0, file_payload=s.sd('empty'))
    save('inline-invalid', file_id=0, file_payload=v.SECURITY_HEADER.pack(
        0, 0, v.SECURITY_SELF_RELATIVE, 0, 0, 0, 0))
    save('missing-id', file_id=s.SECURITY_ID + 4)
    save('missing-store', absent=True)
    for variant in ('off-path-primary', 'off-path-copy-header', 'off-path-copy-body', 'off-path-descriptor'):
        save(variant, variant)
    (output / 'secure-store-validation-cases.json').write_text(json.dumps(manifest, indent=2) + '\n')
