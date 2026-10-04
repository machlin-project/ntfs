"""Complete filename storage for independently authored synthetic namespaces.

Callers supply the exact FILE_NAME bodies used to author their directory indexes.
This writer does not ask the C reader to discover names or invent missing links.
It retains existing stream bodies and adds checked locations to existing lists.
Large inventories grow the synthetic MFT instead of omitting filename storage.
"""
import struct

import fixtures as f
import secure_fixtures as s
from secure_store_fixtures import kind, resident_value

RESIDENT_FIELDS = ('length', 'offset', 'indexed', 'reserved')
NONRESIDENT_FIELDS = ('lowest', 'highest', 'pairs_offset', 'compression_unit',
                      'allocated', 'size', 'initialized')
LIST_FIELDS = ('type', 'length', 'name_length', 'name_offset', 'lowest',
               'reference', 'instance')
FILENAME_FIELDS = ('parent', 'created', 'modified', 'changed', 'accessed',
                   'allocated', 'size', 'attributes', 'ea', 'length', 'namespace')
RUN_FIELD_BITS = 4
RUN_FIELD_MASK = (1 << RUN_FIELD_BITS) - 1
WIRE_U16_MAX = (1 << (f.U16_BYTES * f.BYTE_BITS)) - 1
ATTRIBUTE_TERMINATOR = struct.Struct('<II')


def attr_header(value):
    return dict(zip(s.ATTR_HEADER_FIELDS, f.ATTR_HEADER.unpack_from(value)))


def attr_name(value):
    header = attr_header(value)
    first = header['name_offset']
    last = first + header['name_length'] * f.U16_BYTES
    return value[first:last].decode('utf-16le', errors='surrogatepass')


def mapping(value):
    """Decode this fixture author's own nonresident mapping pairs."""
    header = dict(zip(NONRESIDENT_FIELDS,
                      f.NONRESIDENT_HEADER.unpack_from(value, f.ATTR_HEADER.size)))
    runs, offset, lcn = [], header['pairs_offset'], 0
    while value[offset]:
        widths = value[offset]
        length_bytes, delta_bytes = widths & RUN_FIELD_MASK, widths >> RUN_FIELD_BITS
        offset += 1
        assert length_bytes and offset + length_bytes + delta_bytes <= len(value)
        count = int.from_bytes(value[offset:offset + length_bytes], 'little')
        offset += length_bytes
        physical = None
        if delta_bytes:
            lcn += int.from_bytes(value[offset:offset + delta_bytes], 'little', signed=True)
            physical = lcn
        offset += delta_bytes
        assert count and (physical is None or physical >= 0)
        runs.append((count, physical))
    return header, runs


def mapped_bytes(image, runs, offset, size):
    result = bytearray()
    logical = 0
    for count, lcn in runs:
        run_bytes = count * f.CLUSTER
        if offset < logical + run_bytes and len(result) < size:
            within = max(0, offset - logical)
            take = min(run_bytes - within, size - len(result))
            assert lcn is not None
            start = lcn * f.CLUSTER + within
            result += image[start:start + take]
            offset += take
        logical += run_bytes
    assert len(result) == size
    return result


def record_parts(record):
    """Restore our FILE snapshot while retaining legacy header geometry."""
    record = bytearray(record)
    common = dict(zip(s.FILE_HEADER_FIELDS,
                      f.FILE_HEADER_LEGACY.unpack_from(record)))
    assert common['magic'] == b'FILE' and common['allocated'] == f.RECORD
    legacy = common['usa_offset'] == f.FILE_HEADER_LEGACY.size
    assert legacy or common['usa_offset'] == f.FILE_HEADER.size
    header = common if legacy else dict(zip(s.FILE_HEADER_FIELDS, f.FILE_HEADER.unpack_from(record)))
    for sector in range(1, header['usa_count']):
        tail = sector * f.SECTOR - f.U16_BYTES
        saved = header['usa_offset'] + sector * f.U16_BYTES
        record[tail:tail + f.U16_BYTES] = record[saved:saved + f.U16_BYTES]
    values, position = [], header['attrs_offset']
    while struct.unpack_from('<I', record, position)[0] != f.ATTR_END:
        attr = attr_header(record[position:])
        assert attr['length'] >= f.ATTR_HEADER.size
        assert position + attr['length'] <= header['used']
        values.append(bytes(record[position:position + attr['length']]))
        position += attr['length']
    return header, values


def encoded_record(number, values, header, *, links=None, base=None):
    values = sorted(values, key=kind)
    legacy = header['usa_offset'] == f.FILE_HEADER_LEGACY.size
    encoded = bytearray(f.file_record(number, values,
                         directory=bool(header['flags'] & f.FILE_IS_DIRECTORY),
                         sequence=header['sequence'],
                         base=header['base'] if base is None else base,
                         links=header['links'] if links is None else links,
                         legacy=legacy, view=bool(header['flags'] & f.FILE_VIEW_INDEX),
                         uninterpreted=bool(header['flags'] & f.FILE_UNINTERPRETED)))
    wire = f.FILE_HEADER_LEGACY if legacy else f.FILE_HEADER
    fields = dict(zip(s.FILE_HEADER_FIELDS, wire.unpack_from(encoded)))
    fields['lsn'], fields['flags'] = header['lsn'], header['flags']
    fields['next_instance'] = max((attr_header(value)['instance'] for value in values), default=0) + 1
    assert fields['next_instance'] <= WIRE_U16_MAX
    wire.pack_into(encoded, 0, *(fields[name] for name in s.FILE_HEADER_FIELDS[:len(fields)]))
    return bytes(encoded)


class FilenameStorage:
    """Author known fixtures with a complete base MFT mapping and resident bitmap.

    The initialized MFT must fill its runs. Extra records append beyond that
    span; spare mapped tails and MFT attribute-list bootstrap are not supported.
    This is an author for trusted inputs, not an untrusted volume parser.
    """
    def __init__(self, original):
        self.image = bytearray(original)
        first = f.MFT_LCN * f.CLUSTER
        self.mft_header, self.mft_values = record_parts(self.image[first:first + f.RECORD])
        self.mft_data = next(value for value in self.mft_values
                             if kind(value) == f.DATA and not attr_name(value))
        self.mft_info, self.runs = mapping(self.mft_data)
        assert self.mft_info['lowest'] == 0
        assert self.mft_info['size'] == self.mft_info['initialized']
        assert self.mft_info['size'] == sum(count * f.CLUSTER for count, _ in self.runs)
        assert all(lcn is not None for _, lcn in self.runs)
        self.original_records = self.mft_info['size'] // f.RECORD
        self.mft_record_slots = self.original_records
        self.next_record = self.original_records
        self.records = {}
        self.parts = {}
        reserved = {cluster for count, lcn in self.runs if lcn is not None
                    for cluster in range(lcn, lcn + count)}
        for number in range(self.original_records):
            raw = mapped_bytes(self.image, self.runs, number * f.RECORD, f.RECORD)
            if raw[:len(b'FILE')] != b'FILE':
                continue
            header, values = record_parts(raw)
            self.parts[number] = (header, values)
            for value in values:
                if attr_header(value)['nonresident']:
                    _, runs = mapping(value)
                    reserved.update(cluster for count, lcn in runs if lcn is not None
                                    for cluster in range(lcn, lcn + count))
        _, bitmap_values = self.parts[f.BITMAP_RECORD]
        bitmap = next(value for value in bitmap_values if kind(value) == f.DATA and not attr_name(value))
        assert not attr_header(bitmap)['nonresident']
        self.bitmap = bytearray(resident_value(bitmap))
        reserved.update(cluster for cluster in range(len(self.bitmap) * f.BYTE_BITS)
                        if self.bitmap[cluster // f.BYTE_BITS] & (1 << (cluster % f.BYTE_BITS)))
        self.next_cluster = max(reserved) + 1
        self.allocated = []

    def allocate(self, size):
        count = (size + f.CLUSTER - 1) // f.CLUSTER
        lcn = self.next_cluster
        assert count and (lcn + count) * f.CLUSTER <= len(self.image)
        self.next_cluster += count
        self.allocated.extend(range(lcn, lcn + count))
        return lcn, count

    def list_value(self, number, values):
        value = next((value for value in values if kind(value) == f.ATTR_LIST), None)
        if value is None:
            header = self.parts[number][0]
            reference = f.file_reference(number, header['sequence'])
            return [f.list_entry(reference, attr_header(v)['instance'],
                                 mapping(v)[0]['lowest'] if attr_header(v)['nonresident'] else 0,
                                 kind(v), attr_name(v)) for v in values]
        if attr_header(value)['nonresident']:
            info, runs = mapping(value)
            payload = mapped_bytes(self.image, runs, 0, info['size'])
        else:
            payload = resident_value(value)
        entries, offset = [], 0
        while offset < len(payload):
            entry = dict(zip(LIST_FIELDS, f.ATTR_LIST_ENTRY.unpack_from(payload, offset)))
            assert entry['length'] >= f.ATTR_LIST_ENTRY.size
            entries.append(bytes(payload[offset:offset + entry['length']]))
            offset += entry['length']
        assert offset == len(payload)
        return entries

    def filenames(self, number, payloads):
        header, original = self.parts[number]
        assert header['base'] == 0 and payloads
        assert not any(kind(v) == f.FILENAME for v in original)
        assert len(payloads) <= WIRE_U16_MAX
        first_instance = max(attr_header(v)['instance'] for v in original) + 1
        reference = f.file_reference(number, header['sequence'])
        existing_list = next((v for v in original if kind(v) == f.ATTR_LIST), None)
        # Compute fit before assigning local instance IDs. Spilled names use
        # IDs local to each extension, even for inventories larger than the
        # available ID span in the original base record.
        name_bytes = sum(len(f.resident(f.FILENAME, payload)) for payload in payloads)
        if header['attrs_offset'] + sum(map(len, original)) + name_bytes + ATTRIBUTE_TERMINATOR.size <= f.RECORD:
            assert first_instance + len(payloads) <= WIRE_U16_MAX
            names = [f.resident(f.FILENAME, payload, first_instance + index)
                     for index, payload in enumerate(payloads)]
            values = original + names
            if existing_list is not None:
                entries = self.list_value(number, original)
                entries += [f.list_entry(reference, attr_header(v)['instance'], 0, f.FILENAME) for v in names]
                values = [v for v in values if kind(v) != f.ATTR_LIST]
                values.append(self.list_attribute(entries, attr_header(existing_list)['instance'], values))
            self.records[number] = encoded_record(number, values, header, links=len(names))
            return
        values = [v for v in original if kind(v) != f.ATTR_LIST]
        entries = self.list_value(number, original)
        group = []
        for payload in payloads:
            value = f.resident(f.FILENAME, payload, len(group))
            if f.align(f.FILE_HEADER.size + (f.RECORD // f.SECTOR + 1) * f.U16_BYTES) + sum(map(len, group + [value])) + ATTRIBUTE_TERMINATOR.size > f.RECORD:
                entries += self.extension(reference, group)
                group = []
                value = f.resident(f.FILENAME, payload, len(group))
            group.append(value)
        if group:
            entries += self.extension(reference, group)
        instance = attr_header(existing_list)['instance'] if existing_list is not None else first_instance
        values.append(self.list_attribute(entries, instance, values))
        self.records[number] = encoded_record(number, values, header, links=len(payloads))

    def extension(self, owner, values):
        number = self.next_record
        self.next_record += 1
        self.records[number] = f.file_record(number, values, links=0, base=owner)
        return [f.list_entry(f.file_reference(number), attr_header(v)['instance'], 0, f.FILENAME) for v in values]

    def list_attribute(self, entries, instance, values):
        entries.sort(key=lambda e: dict(zip(LIST_FIELDS, f.ATTR_LIST_ENTRY.unpack_from(e)))['type'])
        payload = b''.join(entries)
        resident = f.resident(f.ATTR_LIST, payload, instance)
        base_bytes = f.align(f.FILE_HEADER.size + (f.RECORD // f.SECTOR + 1) * f.U16_BYTES)
        if base_bytes + sum(map(len, values)) + len(resident) + ATTRIBUTE_TERMINATOR.size <= f.RECORD:
            return resident
        lcn, clusters = self.allocate(len(payload))
        f.put_data(self.image, lcn, payload)
        return f.nonresident(f.ATTR_LIST, [(clusters, lcn)], len(payload), instance)

    def finish(self):
        runs = list(self.runs)
        if self.next_record > self.original_records:
            extra = (self.next_record - self.original_records) * f.RECORD
            lcn, count = self.allocate(extra)
            f.put_data(self.image, lcn, bytes(count * f.CLUSTER))
            runs.append((count, lcn))
            initialized = self.original_records * f.RECORD + count * f.CLUSTER
            self.mft_record_slots = initialized // f.RECORD
            header = attr_header(self.mft_data)
            replacement = f.nonresident(f.DATA, runs, initialized, header['instance'])
            current_header, values = (record_parts(self.records[f.MFT_RECORD])
                                      if f.MFT_RECORD in self.records
                                      else (self.mft_header, self.mft_values))
            values = [replacement if value == self.mft_data else value for value in values]
            self.records[f.MFT_RECORD] = encoded_record(f.MFT_RECORD, values, current_header)
        for cluster in self.allocated:
            self.bitmap[cluster // f.BYTE_BITS] |= 1 << (cluster % f.BYTE_BITS)
        header, values = (record_parts(self.records[f.BITMAP_RECORD])
                          if f.BITMAP_RECORD in self.records else self.parts[f.BITMAP_RECORD])
        values = [f.resident(f.DATA, self.bitmap, attr_header(value)['instance'])
                  if kind(value) == f.DATA and not attr_name(value) else value for value in values]
        self.records[f.BITMAP_RECORD] = encoded_record(f.BITMAP_RECORD, values, header)
        for number, record in self.records.items():
            logical, offset, copied = 0, number * f.RECORD, 0
            for count, lcn in runs:
                span = count * f.CLUSTER
                if offset < logical + span and copied < len(record):
                    within = max(0, offset - logical)
                    take = min(span - within, len(record) - copied)
                    start = lcn * f.CLUSTER + within
                    self.image[start:start + take] = record[copied:copied + take]
                    offset += take
                    copied += take
                logical += span
            assert copied == len(record)
        if f.MFT_RECORD in self.records:
            f.put_data(self.image, f.MIRROR_LCN, self.records[f.MFT_RECORD])
        return self.image
