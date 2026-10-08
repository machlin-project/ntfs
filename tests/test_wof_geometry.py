"""Independent physical allocation checks for ordinary and compact WOF peers."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import fixtures as f
import wof_file_fixtures as w

FILE_FIELDS = ('magic', 'usa_offset', 'usa_count', 'lsn', 'sequence', 'links',
               'attributes', 'flags', 'used', 'allocated', 'base', 'next_id',
               'reserved', 'number')
ATTRIBUTE_FIELDS = ('kind', 'length', 'nonresident', 'name_units', 'name_offset',
                    'flags', 'instance')
NONRESIDENT_FIELDS = ('lowest', 'highest', 'mapping', 'compression', 'allocated',
                      'size', 'initialized')
COMPACT_BYTES = 1024 * 1024
ORDINARY_BYTES = 8 * COMPACT_BYTES


def attributes(image, number):
    start = f.MFT_LCN * f.CLUSTER + number * f.RECORD
    record = bytearray(image[start:start + f.RECORD])
    header = dict(zip(FILE_FIELDS, f.FILE_HEADER.unpack_from(record)))
    for sector in range(1, header['usa_count']):
        saved = header['usa_offset'] + sector * f.U16_BYTES
        tail = sector * f.SECTOR - f.U16_BYTES
        record[tail:tail + f.U16_BYTES] = record[saved:saved + f.U16_BYTES]
    offset = header['attributes']
    while struct.unpack_from('<I', record, offset)[0] != f.ATTR_END:
        fields = dict(zip(ATTRIBUTE_FIELDS, f.ATTR_HEADER.unpack_from(record, offset)))
        assert fields['length'] >= f.ATTR_HEADER.size
        value = record[offset:offset + fields['length']]
        name_offset = fields['name_offset']
        fields['name'] = value[name_offset:name_offset + fields['name_units'] * f.U16_BYTES].decode('utf-16le')
        yield fields, value
        offset += fields['length']


def backing(image, number):
    for fields, value in attributes(image, number):
        if fields['kind'] == f.DATA and fields['name'] == w.BACKING_NAME:
            header = dict(zip(NONRESIDENT_FIELDS, f.NONRESIDENT_HEADER.unpack_from(value, f.ATTR_HEADER.size)))
            offset, lcn, runs = header['mapping'], 0, []
            while value[offset]:
                lengths = value[offset]
                count_bytes, delta_bytes = lengths & 15, lengths >> 4
                offset += 1
                count = int.from_bytes(value[offset:offset + count_bytes], 'little')
                offset += count_bytes
                lcn += int.from_bytes(value[offset:offset + delta_bytes], 'little', signed=True)
                offset += delta_bytes
                assert count and delta_bytes
                runs.append((lcn, count))
            return header, runs
    raise AssertionError('missing physical WOF backing')


class GeometryTests(unittest.TestCase):
    def test_authored_pairs(self):
        for image_bytes in (COMPACT_BYTES, ORDINARY_BYTES):
            with self.subTest(image_bytes=image_bytes), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                with patch.object(f, 'IMAGE_SIZE', image_bytes):
                    source, _, _ = f.make_image()
                    w.author(output, source)
                original = (output / 'wof-file-pages.img').read_bytes()
                for filename in ('wof-cache-pair.img', 'wof-cache-bad-peer.img'):
                    image = (output / filename).read_bytes()
                    self.assertEqual(len(image), image_bytes)
                    primary, primary_runs = backing(image, w.FILE_RECORD)
                    peer, peer_runs = backing(image, w.CACHE_PEER_RECORD)
                    occupied = set(range(f.ALLOCATED_CLUSTERS))
                    for lcn, count in (*primary_runs, *peer_runs):
                        extent = set(range(lcn, lcn + count))
                        self.assertTrue(extent)
                        self.assertLessEqual((lcn + count) * f.CLUSTER, image_bytes)
                        self.assertTrue(occupied.isdisjoint(extent))
                        occupied.update(extent)
                    for lcn, count in primary_runs:
                        span = slice(lcn * f.CLUSTER, (lcn + count) * f.CLUSTER)
                        self.assertEqual(image[span], original[span])
                    self.assertGreater(primary['size'], w.TABLE_PAGE_BYTES)
                    self.assertGreater(peer['size'], 0)
                    for fields, value in attributes(image, f.BITMAP_RECORD):
                        if fields['kind'] == f.DATA:
                            size, start, _, _ = f.RESIDENT_HEADER.unpack_from(value, f.ATTR_HEADER.size)
                            bitmap = value[start:start + size]
                            actual = {cluster for cluster in range(image_bytes // f.CLUSTER)
                                      if bitmap[cluster // f.BYTE_BITS] & (1 << (cluster % f.BYTE_BITS))}
                            self.assertEqual(actual, occupied)
                    if image_bytes == ORDINARY_BYTES:
                        self.assertEqual(peer_runs[0][0], w.CACHE_PEER_LCN)
                        self.assertEqual(peer['size'], primary['size'])

    def test_no_fit_is_explicit(self):
        self.assertIsNone(w.cache_peer_lcn(f.ALLOCATED_CLUSTERS * f.CLUSTER, 2, 1))


if __name__ == '__main__':
    unittest.main()
