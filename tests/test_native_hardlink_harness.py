#!/usr/bin/env python3
"""Independent raw hard-link witness contract; no Windows or C execution verdict."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

import fixtures as wire
import filename_storage as storage
import write_hardlink_fixtures as author
from native_hardlink_observer import Image, restore, verify_transform
from native_hardlink_batch import same_metadata
from write_metadata_fixtures import FILE
from record_protect_fixtures import protected

FIXTURES = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else None


class HardlinkObserver(unittest.TestCase):
    def test_authored_transforms_and_unchanged_streams(self):
        profiles = {'cross-parent', 'same-parent', 'paired-source'}
        observed = 0
        with tempfile.TemporaryDirectory() as temporary:
            for row in (FIXTURES / 'cases.txt').read_text().splitlines():
                label, code, reference, source_parent, source_name, parent, name, physical, golden = row.split()
                if label not in profiles:
                    continue
                self.assertEqual(int(code), 0)
                reference, source_parent, parent, physical = map(int, (reference, source_parent, parent, physical))
                before = FIXTURES / (label + '.img')
                image = bytearray(before.read_bytes())
                raw = (FIXTURES / golden).read_bytes()
                header = storage.record_parts(image[physical:physical + wire.RECORD])[0]
                new_record = protected(raw, header['usa_offset'], header['usa_count'], wire.FIXUP_SEQUENCE)
                image[physical:physical + wire.RECORD] = new_record
                parent_number = parent & ((1 << wire.REFERENCE_SEQUENCE_SHIFT) - 1)
                parent_header, attrs = author.parts(image, parent_number)
                root = author.attr_of(attrs, wire.INDEX_ROOT, '$I30')
                entries = Image(before).keys(parent)
                value = (FIXTURES / (label + '.filename')).read_bytes()
                entries.append((reference, value))
                entries.sort(key=lambda entry: entry[1][wire.FILENAME_HEADER.size:].decode('utf-16le').upper())
                content = author.root_with_entries([author.directory_entry(ref, key) for ref, key in entries])
                attrs[attrs.index(root)] = wire.resident(wire.INDEX_ROOT, content,
                    storage.attr_header(root)['instance'], '$I30')
                author.put(image, parent_number, parent_header, attrs)
                after = Path(temporary) / (label + '.img')
                after.write_bytes(image)
                report = verify_transform(before, after, reference, source_parent, source_name, parent, name)
                self.assertTrue(report['completeTargetFile'])
                self.assertTrue(report['sourceAndDestinationKeys'])
                observed += 1
                invalid = bytearray(image)
                target_number = reference & ((1 << wire.REFERENCE_SEQUENCE_SHIFT) - 1)
                invalid_header, invalid_attrs = author.parts(invalid, target_number)
                added = next(value for value in invalid_attrs
                             if storage.attr_header(value)['instance'] == header['next_instance'])
                changed = bytearray(added)
                resident = dict(zip(storage.RESIDENT_FIELDS,
                                    wire.RESIDENT_HEADER.unpack_from(changed, wire.ATTR_HEADER.size)))
                resident['indexed'] = 0
                wire.RESIDENT_HEADER.pack_into(changed, wire.ATTR_HEADER.size,
                                              *(resident[field] for field in storage.RESIDENT_FIELDS))
                invalid_attrs[invalid_attrs.index(added)] = bytes(changed)
                author.put(invalid, target_number, invalid_header, invalid_attrs)
                unindexed = Path(temporary) / (label + '-unindexed.img')
                unindexed.write_bytes(invalid)
                with self.assertRaises(AssertionError):
                    verify_transform(before, unindexed, reference, source_parent, source_name, parent, name)
                # A changed old ADS or SI byte cannot be legitimized by a new
                # filename: the complete-record oracle rejects the transform.
                header, attrs = author.parts(image, reference & ((1 << wire.REFERENCE_SEQUENCE_SHIFT) - 1))
                stream = author.attr_of(attrs, wire.DATA, 'notes')
                data = bytearray(storage.resident_value(stream))
                data[-1] ^= 1
                attrs[attrs.index(stream)] = wire.resident(wire.DATA, data,
                    storage.attr_header(stream)['instance'], 'notes')
                author.put(image, reference & ((1 << wire.REFERENCE_SEQUENCE_SHIFT) - 1), header, attrs)
                corrupted = Path(temporary) / (label + '-changed-ads.img')
                corrupted.write_bytes(image)
                with self.assertRaises(AssertionError):
                    verify_transform(before, corrupted, reference, source_parent, source_name, parent, name)
        self.assertEqual(observed, len(profiles))

    def test_torn_protected_record_refused(self):
        image = FIXTURES / 'cross-parent.img'
        raw = Image(image)
        value = bytearray(raw.mapped(raw.mft_runs, wire.ROOT_RECORD * wire.RECORD, wire.RECORD))
        restore(value, b'FILE')
        value[wire.SECTOR - wire.U16_BYTES] ^= 1
        with self.assertRaises(AssertionError):
            restore(value, b'FILE')

    def test_index_split_predecessor_is_walked(self):
        rows = [row.split() for row in (FIXTURES / 'cases.txt').read_text().splitlines()]
        row = next(row for row in rows if row[0] == 'index-split')
        raw = Image(FIXTURES / 'index-split.img')
        entries = raw.keys(int(row[5]))
        self.assertEqual(len(entries), author.INDEX_RECORDS)
        for _, key in entries:
            self.assertEqual(struct.unpack_from('<Q', key)[0], int(row[5]))

    def test_unmodified_file_sibling_remains_exact(self):
        raw = Image(FIXTURES / 'cross-parent.img')
        before = raw.mapped(raw.mft_runs, 0, wire.CLUSTER)
        actual = bytearray(before)
        FILE.put(actual, 'lsn', 123, wire.RECORD)
        region = dict(attribute_type=wire.DATA, reference=wire.file_reference(wire.MFT_RECORD))
        same_metadata(before, before, before, region)
        with self.assertRaises(AssertionError):
            same_metadata(bytes(actual), before, before, region)


if __name__ == '__main__':
    assert FIXTURES is not None
    unittest.main()
