"""Independent bounded FILE/I30 observer for private hard-link storage acceptance.

This reads only exact disposable image files. It is a test oracle for the admitted
512/4096/1024 geometry and base-record attributes, not a general NTFS reader.
"""
import struct

import fixtures as wire
import filename_storage as storage
from secure_fixtures import FILE_HEADER_FIELDS

MST_HEADER = struct.Struct('<4sHHQ')
INDEX_BLOCK_PREFIX = struct.Struct('<4sHHQQ')
REFERENCE_MASK = (1 << wire.REFERENCE_SEQUENCE_SHIFT) - 1
MAX_INDEX_BLOCKS = 1024


def restore(value, magic):
    result = bytearray(value)
    signature, offset, count, _ = MST_HEADER.unpack_from(result)
    assert signature == magic and count == len(result) // wire.SECTOR + 1
    assert MST_HEADER.size <= offset and offset + count * wire.U16_BYTES <= wire.SECTOR
    marker = result[offset:offset + wire.U16_BYTES]
    for sector in range(1, count):
        tail = sector * wire.SECTOR - wire.U16_BYTES
        saved = offset + sector * wire.U16_BYTES
        assert result[tail:tail + wire.U16_BYTES] == marker
        result[tail:tail + wire.U16_BYTES] = result[saved:saved + wire.U16_BYTES]
    return bytes(result)


def attribute(values, kind, name=''):
    selected = [value for value in values
                if storage.attr_header(value)['type'] == kind and storage.attr_name(value) == name]
    assert len(selected) == 1
    return selected[0]


class Image:
    def __init__(self, path):
        self.path = path
        boot = self.at(0, wire.SECTOR)
        assert boot[wire.BOOT_FIELDS['oem']:wire.BOOT_FIELDS['oem'] + 8] == b'NTFS    '
        sector = struct.unpack_from('<H', boot, wire.BOOT_FIELDS['sector_size'])[0]
        assert sector == wire.SECTOR and boot[wire.BOOT_FIELDS['cluster_sectors']] * sector == wire.CLUSTER
        assert struct.unpack_from('<b', boot, wire.BOOT_FIELDS['record_code'])[0] == -10
        mft = struct.unpack_from('<Q', boot, wire.BOOT_FIELDS['mft'])[0]
        raw = self.at(mft * wire.CLUSTER, wire.RECORD)
        restore(raw, b'FILE')
        _, attrs = storage.record_parts(raw)
        assert not any(storage.attr_header(value)['type'] == wire.ATTR_LIST for value in attrs)
        self.mft_info, self.mft_runs = storage.mapping(attribute(attrs, wire.DATA))
        assert self.mft_info['lowest'] == 0

    def at(self, first, count):
        assert 0 <= first <= self.path.stat().st_size and count <= self.path.stat().st_size - first
        with self.path.open('rb') as source:
            source.seek(first)
            value = source.read(count)
        assert len(value) == count
        return value

    def mapped(self, runs, offset, count):
        result = bytearray()
        logical = 0
        for clusters, lcn in runs:
            span = clusters * wire.CLUSTER
            if offset < logical + span and len(result) < count:
                within = max(0, offset - logical)
                take = min(span - within, count - len(result))
                assert lcn is not None
                result += self.at(lcn * wire.CLUSTER + within, take)
                offset += take
            logical += span
        assert len(result) == count
        return bytes(result)

    def record(self, reference):
        number = reference & REFERENCE_MASK
        assert (number + 1) * wire.RECORD <= self.mft_info['initialized']
        raw = self.mapped(self.mft_runs, number * wire.RECORD, wire.RECORD)
        logical = restore(raw, b'FILE')
        header, attrs = storage.record_parts(raw)
        assert header['sequence'] == reference >> wire.REFERENCE_SEQUENCE_SHIFT
        assert header['flags'] & wire.FILE_IN_USE and header['base'] == 0
        assert not any(storage.attr_header(value)['type'] == wire.ATTR_LIST for value in attrs)
        return logical, header, attrs

    def resolve(self, path):
        assert path.startswith('/') and not path.endswith('/')
        raw = self.mapped(self.mft_runs, wire.ROOT_RECORD * wire.RECORD, wire.RECORD)
        restore(raw, b'FILE')
        header, _ = storage.record_parts(raw)
        reference = wire.file_reference(wire.ROOT_RECORD, header['sequence'])
        for component in path[1:].split('/'):
            wanted = component.encode('utf-16le')
            matches = [child for child, key in self.keys(reference)
                       if key[wire.FILENAME_HEADER.size:] == wanted]
            assert len(matches) == 1
            reference = matches[0]
        return reference

    def streams(self, reference):
        _, _, attrs = self.record(reference)
        result = {}
        for value in attrs:
            header = storage.attr_header(value)
            if header['type'] != wire.DATA:
                continue
            name = storage.attr_name(value)
            assert name not in result
            if header['nonresident']:
                info, runs = storage.mapping(value)
                assert info['lowest'] == 0 and info['initialized'] == info['size'] <= 1024 * 1024
                result[name] = self.mapped(runs, 0, info['size'])
            else:
                result[name] = storage.resident_value(value)
        assert '' in result
        return result

    def keys(self, reference):
        _, header, attrs = self.record(reference)
        assert header['flags'] & wire.FILE_IS_DIRECTORY
        root = storage.resident_value(attribute(attrs, wire.INDEX_ROOT, '$I30'))
        roots = wire.INDEX_ROOT_HEADER.unpack_from(root)
        assert roots[0] == wire.FILENAME and roots[1] == wire.COLLATION_FILENAME
        assert roots[2] == wire.CLUSTER
        allocation = [value for value in attrs if storage.attr_header(value)['type'] == wire.INDEX_ALLOC]
        assert len(allocation) <= 1
        mapping = storage.mapping(allocation[0]) if allocation else None
        seen = set()

        def walk(value, header_offset):
            first, used, allocated, _ = wire.INDEX_HEADER.unpack_from(value, header_offset)
            assert wire.INDEX_HEADER.size <= first <= used <= allocated <= len(value) - header_offset
            position, end = header_offset + first, header_offset + used
            result = []
            while position < end:
                child_ref, length, key_bytes, flags = wire.INDEX_ENTRY.unpack_from(value, position)
                assert flags & ~(wire.CHILD | wire.END) == 0
                assert length >= wire.INDEX_ENTRY.size and length % wire.WIRE_ALIGNMENT == 0
                assert position + length <= end and key_bytes <= length - wire.INDEX_ENTRY.size
                if flags & wire.CHILD:
                    assert mapping is not None
                    child = struct.unpack_from('<Q', value, position + length - wire.U64_BYTES)[0]
                    assert child not in seen and len(seen) < MAX_INDEX_BLOCKS
                    seen.add(child)
                    raw = self.mapped(mapping[1], child * wire.CLUSTER, wire.CLUSTER)
                    block = restore(raw, b'INDX')
                    assert INDEX_BLOCK_PREFIX.unpack_from(block)[-1] == child
                    result += walk(block, INDEX_BLOCK_PREFIX.size)
                if flags & wire.END:
                    assert key_bytes == 0 and position + length == end
                    return result
                assert key_bytes >= wire.FILENAME_HEADER.size
                first_key = position + wire.INDEX_ENTRY.size
                key = value[first_key:first_key + key_bytes]
                fields = wire.FILENAME_HEADER.unpack_from(key)
                assert key_bytes == wire.FILENAME_HEADER.size + fields[-2] * wire.U16_BYTES
                assert fields[0] == reference
                result.append((child_ref, key))
                position += length
            raise AssertionError('Missing index terminator')

        return walk(root, wire.INDEX_ROOT_HEADER.size)


def verify_transform(before, after, reference, source_parent, source_name, parent, name):
    old, new = Image(before), Image(after)
    old_record, old_header, old_attrs = old.record(reference)
    new_record, new_header, new_attrs = new.record(reference)
    source_units = source_name.encode('utf-16le')
    matches = [value for value in old_attrs if storage.attr_header(value)['type'] == wire.FILENAME
               and storage.resident_value(value)[wire.FILENAME_HEADER.size:] == source_units
               and wire.FILENAME_HEADER.unpack_from(storage.resident_value(value))[0] == source_parent]
    assert len(matches) == 1
    selected = list(wire.FILENAME_HEADER.unpack_from(storage.resident_value(matches[0])))
    assert selected[-1] != wire.NAMESPACE_DOS
    selected[0], selected[-2], selected[-1] = parent, len(name), wire.NAMESPACE_POSIX
    expected_value = wire.FILENAME_HEADER.pack(*selected) + name.encode('utf-16le')
    additions = [value for value in new_attrs if value not in old_attrs]
    assert len(additions) == 1 and storage.attr_header(additions[0])['type'] == wire.FILENAME
    assert storage.attr_header(additions[0])['instance'] == old_header['next_instance']
    assert storage.resident_value(additions[0]) == expected_value
    value_offset = wire.ATTR_HEADER.size + wire.RESIDENT_HEADER.size
    attribute_bytes = wire.align(value_offset + len(expected_value))
    addition = (wire.ATTR_HEADER.pack(wire.FILENAME, attribute_bytes, 0, 0, 0, 0,
                                    old_header['next_instance']) +
                wire.RESIDENT_HEADER.pack(len(expected_value), value_offset, 1, 0) + expected_value +
                bytes(attribute_bytes - value_offset - len(expected_value)))
    assert additions[0] == addition
    assert [value for value in new_attrs if value != additions[0]] == old_attrs
    assert new_header['links'] == old_header['links'] + 1
    assert new_header['next_instance'] == old_header['next_instance'] + 1
    for field in FILE_HEADER_FIELDS:
        if field in old_header and field not in ('lsn', 'links', 'used', 'next_instance'):
            assert old_header[field] == new_header[field], field
    insertion = old_header['attrs_offset'] + sum(len(value) for value in old_attrs
                                                if storage.attr_header(value)['type'] <= wire.FILENAME)
    expected_record = bytearray(old_record[:insertion] + addition + old_record[insertion:old_header['used']] +
                                old_record[old_header['used'] + len(addition):])
    header = dict(old_header)
    header.update(lsn=new_header['lsn'], links=old_header['links'] + 1,
                  used=old_header['used'] + len(addition), next_instance=old_header['next_instance'] + 1)
    wire.FILE_HEADER.pack_into(expected_record, 0, *(header[field] for field in FILE_HEADER_FIELDS))
    usa_offset, usa_count = header['usa_offset'], header['usa_count']
    expected_record[usa_offset:usa_offset + usa_count * wire.U16_BYTES] = new_record[
        usa_offset:usa_offset + usa_count * wire.U16_BYTES]
    assert bytes(expected_record) == new_record
    assert old.streams(reference) == new.streams(reference)
    for directory in {source_parent, parent}:
        old_keys, new_keys = old.keys(directory), new.keys(directory)
        if directory == parent:
            assert new_keys.count((reference, expected_value)) == 1
            new_keys.remove((reference, expected_value))
        assert old_keys == new_keys
        _, _, old_directory = old.record(directory)
        _, _, new_directory = new.record(directory)
        excluded = (wire.INDEX_ROOT, wire.INDEX_ALLOC, wire.BITMAP)
        assert [value for value in old_directory if storage.attr_header(value)['type'] not in excluded] == [
            value for value in new_directory if storage.attr_header(value)['type'] not in excluded]
    return dict(completeTargetFile=True, exactSelectedCache=True, oldFilenameAttributes=True,
                sourceAndDestinationKeys=True, parentUnselectedAttributes=True,
                physicalNames=new_header['links'])
