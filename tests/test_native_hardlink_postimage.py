#!/usr/bin/env python3
"""Synthetic contracts for read-only postimage extraction and old-byte witnesses."""
from pathlib import Path
import hashlib
import sys
import tempfile
import unittest

import fixtures as wire
import filename_storage as storage
import write_hardlink_fixtures as author
from native_hardlink_observer import Image
from native_hardlink_postimage import all_alias_parents, old_endpoint, partition

FIXTURES = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else None


class PostimageContracts(unittest.TestCase):
    def test_exact_partition_including_tail_and_holes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / 'disk.raw', root / 'partition.ntfs'
            prefix = b'P' * wire.SECTOR
            data = b'A' * wire.SECTOR + bytes(wire.CLUSTER) + b'Z' * wire.SECTOR
            original = prefix + data + b'T' * wire.SECTOR
            source.write_bytes(original)
            observed = partition(source, destination, len(prefix), len(data))
            self.assertEqual(observed, hashlib.sha256(data).hexdigest())
            self.assertEqual(destination.read_bytes(), data)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o444)
            with self.assertRaises(ValueError):
                partition(source, root / 'bad', len(original), wire.SECTOR)
            self.assertFalse((root / 'bad').exists())
            with self.assertRaises(FileExistsError):
                partition(source, destination, len(prefix), len(data))

    def test_complete_old_file_and_ads_witness(self):
        row = next(row.split() for row in (FIXTURES / 'cases.txt').read_text().splitlines()
                   if row.startswith('cross-parent '))
        reference, source_parent, parent = int(row[2]), int(row[3]), int(row[5])
        source = FIXTURES / 'cross-parent.img'
        old = Image(source)
        result = old_endpoint(old, old, reference, source_parent, parent)
        self.assertTrue(result['completeTargetFile'])
        self.assertTrue(result['exactDataAndAds'])
        with tempfile.TemporaryDirectory() as temporary:
            value = bytearray(source.read_bytes())
            number = reference & ((1 << wire.REFERENCE_SEQUENCE_SHIFT) - 1)
            header, attrs = author.parts(value, number)
            standard = author.attr_of(attrs, wire.SI)
            standard_value = bytearray(storage.resident_value(standard))
            author.STANDARD.put(standard_value, 'changed', 123456789)
            attrs[attrs.index(standard)] = wire.resident(wire.SI, standard_value,
                                                        storage.attr_header(standard)['instance'])
            author.put(value, number, header, attrs)
            changed = Path(temporary) / 'changed-si.img'
            changed.write_bytes(value)
            with self.assertRaises(ValueError):
                old_endpoint(old, Image(changed), reference, source_parent, parent)

    def test_original_alias_in_another_parent_is_checked(self):
        row = next(row.split() for row in (FIXTURES / 'cases.txt').read_text().splitlines()
                   if row.startswith('cross-parent '))
        reference, selected_parent, original_parent = int(row[2]), int(row[3]), int(row[5])
        record_mask = (1 << wire.REFERENCE_SEQUENCE_SHIFT) - 1
        image = bytearray((FIXTURES / 'cross-parent.img').read_bytes())
        header, attrs = author.parts(image, reference & record_mask)
        key = wire.key('old-alias', parent=original_parent, namespace=wire.NAMESPACE_POSIX)
        attrs.append(wire.resident(wire.FILENAME, key, header['next_instance']))
        header['links'] += 1
        author.put(image, reference & record_mask, header, attrs)
        parent_header, parent_attrs = author.parts(image, original_parent & record_mask)
        root = author.attr_of(parent_attrs, wire.INDEX_ROOT, '$I30')
        parent_attrs[parent_attrs.index(root)] = wire.resident(wire.INDEX_ROOT,
            author.root_with_entries([author.directory_entry(reference, key)]),
            storage.attr_header(root)['instance'], '$I30')
        author.put(image, original_parent & record_mask, parent_header, parent_attrs)
        with tempfile.TemporaryDirectory() as temporary:
            before, changed = Path(temporary) / 'before.img', Path(temporary) / 'changed.img'
            before.write_bytes(image)
            original = Image(before)
            checked = all_alias_parents(original, original, reference, selected_parent, 'new-name', False)
            self.assertEqual(set(checked['parentReferences']), {str(selected_parent), str(original_parent)})
            changed_key = bytearray(key)
            author.FILENAME.put(changed_key, 'modified', 987654321)
            parent_header, parent_attrs = author.parts(image, original_parent & record_mask)
            root = author.attr_of(parent_attrs, wire.INDEX_ROOT, '$I30')
            parent_attrs[parent_attrs.index(root)] = wire.resident(wire.INDEX_ROOT,
                author.root_with_entries([author.directory_entry(reference, changed_key)]),
                storage.attr_header(root)['instance'], '$I30')
            author.put(image, original_parent & record_mask, parent_header, parent_attrs)
            changed.write_bytes(image)
            with self.assertRaises(ValueError):
                all_alias_parents(original, Image(changed), reference, selected_parent, 'new-name', False)


if __name__ == '__main__':
    assert FIXTURES is not None
    unittest.main()
