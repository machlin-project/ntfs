#!/usr/bin/env python3
"""Independent FILE mutation goldens, address oracles and admission profiles."""
from pathlib import Path
import json
import struct
import sys

import fixtures as f
import filename_storage as storage
import secure_fixtures as s
import validation_fixtures as v
from logfile_fixtures import Layout
from overwrite_fixtures import get_record, set_record, replace_attribute
from record_protect_fixtures import FILE, protected

STANDARD = Layout((('created', 'Q'), ('modified', 'Q'), ('changed', 'Q'),
    ('accessed', 'Q'), ('attributes', 'I'), ('max_versions', 'I'), ('version', 'I'),
    ('class_id', 'I'), ('owner_id', 'I'), ('security_id', 'I'), ('quota', 'Q'), ('usn', 'Q')))
ORIGINAL_LSN, NEW_LSN = 100, 500
NEW_TIME = 134357146906613431
ARCHIVE = 0x20
READ_ONLY, SYSTEM, SPARSE, COMPRESSED, ENCRYPTED = 1, 4, 0x200, 0x800, 0x4000
SUCCESS, INVALID, CORRUPT, UNSUPPORTED, STALE = 0, 9, 2, 3, 10
REFERENCE = f.file_reference(v.FRAGMENTED_RECORD)


def restored(raw):
    result = bytearray(raw)
    header = dict(zip(s.FILE_HEADER_FIELDS, f.FILE_HEADER.unpack_from(result)))
    for sector in range(1, header['usa_count']):
        tail = sector * f.SECTOR - f.U16_BYTES
        saved = header['usa_offset'] + sector * f.U16_BYTES
        assert result[tail:tail + f.U16_BYTES] == result[
            header['usa_offset']:header['usa_offset'] + f.U16_BYTES]
        result[tail:tail + f.U16_BYTES] = result[saved:saved + f.U16_BYTES]
    return result, header


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    original, _, _ = f.make_image()
    base = v.build(original, 'logfile-empty')
    header, attrs = get_record(base, v.FRAGMENTED_RECORD)
    header['lsn'] = ORIGINAL_LSN
    standard = STANDARD.pack(dict(created=17, modified=19, changed=23, accessed=29,
        class_id=31, owner_id=37, quota=41, usn=43))
    attrs = [f.resident(f.SI, standard, v.SI_INSTANCE)
             if storage.attr_header(attr)['type'] == f.SI else attr for attr in attrs]
    set_record(base, v.FRAGMENTED_RECORD, header, attrs)
    cases = []

    def add(name, image, code=SUCCESS, reference=REFERENCE, time=NEW_TIME, lsn=NEW_LSN):
        (output / (name + '.img')).write_bytes(image)
        row = dict(name=name, code=code, reference=reference, time=time, lsn=lsn)
        if code == SUCCESS:
            raw_first = f.MFT_LCN * f.CLUSTER + v.FRAGMENTED_RECORD * f.RECORD
            before, h = restored(image[raw_first:raw_first + f.RECORD])
            _, values = get_record(image, v.FRAGMENTED_RECORD)
            position = h['attrs_offset']
            for value in values:
                if storage.attr_header(value)['type'] == f.SI:
                    break
                position += len(value)
            else:
                raise AssertionError('Missing authored standard information')
            resident = dict(zip(storage.RESIDENT_FIELDS,
                f.RESIDENT_HEADER.unpack_from(value, f.ATTR_HEADER.size)))
            after = bytearray(before)
            FILE.put(after, 'lsn', lsn)
            first = position + resident['offset']
            STANDARD.put(after, 'modified', time, first)
            STANDARD.put(after, 'changed', time, first)
            attributes = struct.unpack_from('<I', after, first + STANDARD.offsets['attributes'])[0]
            STANDARD.put(after, 'attributes', attributes | ARCHIVE, first)
            usa = struct.unpack_from('<H', before, h['usa_offset'])[0]
            protected_after = protected(after, h['usa_offset'], h['usa_count'], usa)
            for suffix, data in (('before', before), ('after', after), ('protected', protected_after)):
                (output / (name + '.' + suffix)).write_bytes(data)
            record_position = v.FRAGMENTED_RECORD * f.RECORD
            vcn = record_position // f.CLUSTER
            row.update(mft_reference=f.file_reference(f.MFT_RECORD), target_vcn=vcn,
                target_lcn=f.MFT_LCN + vcn, cluster_physical=(f.MFT_LCN + vcn) * f.CLUSTER,
                cluster_index=record_position % f.CLUSTER // f.SECTOR, record_offset=position,
                attribute_offset=resident['offset'] + STANDARD.offsets['modified'],
                change_bytes=STANDARD.size - STANDARD.offsets['modified'], snapshot_bytes=h['used'])
        cases.append(row)

    add('ordinary', base)
    add('zero-time', base, time=0)
    add('maximum-time', base, time=(1 << 63) - 1)
    add('maximum-lsn', base, lsn=(1 << 64) - 1)
    add('invalid-time', base, INVALID, time=1 << 63)
    add('zero-lsn', base, INVALID, lsn=0)
    add('stale-lsn', base, STALE, lsn=ORIGINAL_LSN)
    add('older-lsn', base, STALE, lsn=ORIGINAL_LSN - 1)
    add('resident', base, UNSUPPORTED, f.file_reference(v.HELLO_RECORD))
    add('directory', base, UNSUPPORTED, f.ROOT_REF)
    add('system-record', base, UNSUPPORTED, f.file_reference(f.UPCASE_RECORD))
    for name, attributes in (('archived', ARCHIVE), ('read-only', READ_ONLY), ('system', SYSTEM),
                              ('sparse', SPARSE), ('compressed', COMPRESSED), ('encrypted', ENCRYPTED)):
        image = bytearray(base)
        value = bytearray(standard)
        STANDARD.put(value, 'attributes', attributes)
        replace_attribute(image, v.FRAGMENTED_RECORD, f.SI, f.resident(f.SI, value, v.SI_INSTANCE))
        add(name, image, SUCCESS if attributes == ARCHIVE else UNSUPPORTED)
    image = bytearray(base)
    replace_attribute(image, v.FRAGMENTED_RECORD, f.SI,
                      v.standard(common_only=True))
    add('common-standard', image, UNSUPPORTED)
    image = bytearray(base)
    header, attrs = get_record(image, v.FRAGMENTED_RECORD)
    header['usa_offset'] = f.FILE_HEADER_LEGACY.size
    set_record(image, v.FRAGMENTED_RECORD, header, attrs)
    add('legacy-header', image, UNSUPPORTED)
    image = bytearray(base)
    header, attrs = get_record(image, v.FRAGMENTED_RECORD)
    header['flags'] |= f.FILE_VIEW_INDEX
    set_record(image, v.FRAGMENTED_RECORD, header, attrs)
    add('view-record', image, UNSUPPORTED)
    image = bytearray(base)
    header, attrs = get_record(image, v.FRAGMENTED_RECORD)
    listing = b''.join(f.list_entry(REFERENCE, storage.attr_header(a)['instance'], 0,
        storage.attr_header(a)['type'], storage.attr_name(a)) for a in attrs)
    attrs.append(f.resident(f.ATTR_LIST, listing, v.LIST_INSTANCE))
    set_record(image, v.FRAGMENTED_RECORD, header, attrs)
    add('listed-record', image, UNSUPPORTED)
    image = bytearray(base)
    first = f.MFT_LCN * f.CLUSTER + v.FRAGMENTED_RECORD * f.RECORD
    FILE.put(image, 'record_number', v.FRAGMENTED_RECORD + 1, first)
    add('wrong-record-number', image, CORRUPT)
    image = bytearray(base)
    header, attrs = get_record(image, f.MFT_RECORD)
    header['sequence'] += 1
    set_record(image, f.MFT_RECORD, header, attrs)
    first = f.MFT_LCN * f.CLUSTER
    f.put_data(image, f.MIRROR_LCN, image[first:first + v.MIRROR_RECORDS * f.RECORD])
    add('unqualified-mft-sequence', image, UNSUPPORTED)
    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    (output / 'cases.rows').write_text(''.join(
        f"{r['name']} {r['code']} {r['reference']} {r['time']} {r['lsn']} " +
        ' '.join(str(r.get(field, 0)) for field in ('mft_reference', 'target_vcn', 'target_lcn',
            'cluster_physical', 'cluster_index', 'record_offset', 'attribute_offset',
            'change_bytes', 'snapshot_bytes')) + '\n' for r in cases))
    return len(cases)


if __name__ == '__main__':
    count = author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('independent metadata mutation goldens\n')
    print(f'Authored {count} FILE mutation profiles')
