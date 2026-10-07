"""Verify the exact archive receipt and refusal boundary before native use."""
from pathlib import Path
import hashlib
import gzip
import http.client
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
from windows_image_archive import ImageArchiveReceiver

IMAGE_BYTES = 65537
IMAGE = bytes((index * 29 + 7) % 256 for index in range(IMAGE_BYTES))
IMAGE_HASH = hashlib.sha256(IMAGE).hexdigest()
GZIP_TRAILER_BYTES = 8
LARGE_IMAGE_BYTES = 2 * 1024 * 1024 + 1


class Archive(unittest.TestCase):
    def transfer(self, receiver, path, value, length=None, additional_headers=None):
        host, port = receiver.server.server_address
        connection = http.client.HTTPConnection(host, port, timeout=10)
        try:
            headers = {'Content-Length': str(len(value) if length is None else length)}
            headers.update(additional_headers or {})
            connection.request('PUT', path, body=value, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_complete_persisted_exact_image_and_duplicate_refusal(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with ImageArchiveReceiver(root, '127.0.0.1', '127.0.0.1', {'fixture': IMAGE_HASH}, IMAGE_BYTES) as receiver:
                status, result = self.transfer(receiver, '/images/fixture', IMAGE)
                self.assertEqual(status, 200)
                self.assertTrue(result['success'] and result['persisted'])
                self.assertEqual(result['bytes'], IMAGE_BYTES)
                self.assertEqual(result['sha256'], IMAGE_HASH)
                image = Path(result['path'])
                self.assertEqual(image.read_bytes(), IMAGE)
                self.assertEqual(image.stat().st_mode & 0o777, 0o444)
                self.assertEqual(image.stat().st_nlink, 1)
                self.assertEqual(self.transfer(receiver, '/images/fixture', IMAGE)[0], 409)
                self.assertEqual(image.read_bytes(), IMAGE)

    def test_wrong_hash_keeps_partial_without_successful_receipt(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with ImageArchiveReceiver(root, '127.0.0.1', '127.0.0.1', {'fixture': IMAGE_HASH}, IMAGE_BYTES) as receiver:
                self.assertEqual(self.transfer(receiver, '/images/fixture', bytes(IMAGE_BYTES))[0], 500)
                self.assertFalse(receiver.receipts)
                self.assertEqual(len(receiver.errors), 1)
                self.assertFalse((root / 'fixture.native.vhd').exists())
                self.assertEqual((root / 'fixture.uploading').read_bytes(), bytes(IMAGE_BYTES))

    def test_complete_gzip_image_retains_exact_original_bytes(self):
        image = (IMAGE * (LARGE_IMAGE_BYTES // IMAGE_BYTES + 1))[:LARGE_IMAGE_BYTES]
        image_hash = hashlib.sha256(image).hexdigest()
        packed = gzip.compress(image, mtime=0)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with ImageArchiveReceiver(root, '127.0.0.1', '127.0.0.1', {'fixture': image_hash}, LARGE_IMAGE_BYTES) as receiver:
                status, result = self.transfer(receiver, '/images/fixture', packed,
                    additional_headers={'Content-Encoding': 'gzip', 'X-Native-Image-Length': str(LARGE_IMAGE_BYTES)})
                self.assertEqual(status, 200)
                self.assertEqual(result['bytes'], LARGE_IMAGE_BYTES)
                self.assertEqual(result['wireBytes'], len(packed))
                self.assertEqual(result['contentEncoding'], 'gzip')
                self.assertEqual(Path(result['path']).read_bytes(), image)
                self.assertEqual(result['sha256'], image_hash)

    def test_gzip_output_bound_and_unfinished_trailer_keep_only_partial(self):
        packed = gzip.compress(IMAGE, mtime=0)
        for value, decoded_length in ((packed, 1), (packed[:-GZIP_TRAILER_BYTES], IMAGE_BYTES)):
            with self.subTest(decoded_length=decoded_length), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                with ImageArchiveReceiver(root, '127.0.0.1', '127.0.0.1', {'fixture': IMAGE_HASH}, IMAGE_BYTES) as receiver:
                    status, _ = self.transfer(receiver, '/images/fixture', value,
                        additional_headers={'Content-Encoding': 'gzip', 'X-Native-Image-Length': str(decoded_length)})
                    self.assertEqual(status, 500)
                    self.assertFalse(receiver.receipts)
                    self.assertFalse((root / 'fixture.native.vhd').exists())
                    self.assertTrue((root / 'fixture.uploading').exists())

    def test_unknown_route_oversized_image_and_other_peer_do_not_create_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with ImageArchiveReceiver(root, '127.0.0.1', '127.0.0.1', {'fixture': IMAGE_HASH}, IMAGE_BYTES) as receiver:
                self.assertEqual(self.transfer(receiver, '/images/other', b'x')[0], 403)
                self.assertEqual(self.transfer(receiver, '/images/fixture', b'x', IMAGE_BYTES + 1)[0], 413)
                self.assertFalse(list(root.iterdir()))
            with ImageArchiveReceiver(root, '127.0.0.1', '192.0.2.1', {'fixture': IMAGE_HASH}, IMAGE_BYTES) as receiver:
                self.assertEqual(self.transfer(receiver, '/images/fixture', b'x')[0], 403)
                self.assertFalse(list(root.iterdir()))


if __name__ == '__main__':
    unittest.main()
