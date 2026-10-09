#!/usr/bin/env python3
"""Check fresh common-profile authoring without compiling or running a writer."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import prepare_write_benchmark_profile as profile
import filename_storage as storage
import fixtures as fixture
import logfile_fixtures as wire
import validation_fixtures as volume_fixture
from write_journal_fixtures import restore_page, fields
from logfile_checkpoint_fixtures import CLIENT_RESTART


class CommonProfile(unittest.TestCase):
    def test_fresh_profile_and_unchanged_source(self):
        original = SOURCE.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'new'
            report = profile.prepare(SOURCE, output)
            self.assertEqual(SOURCE.read_bytes(), original)
            self.assertEqual(report['source_sha256'], hashlib.sha256(original).hexdigest())
            image = (output / report['image']).read_bytes()
            self.assertEqual(report['image_sha256'], hashlib.sha256(image).hexdigest())
            self.assertTrue(report['old_and_new_admission_pending'])
            first = fixture.MFT_LCN * fixture.CLUSTER + volume_fixture.LOGFILE_RECORD * fixture.RECORD
            _, attributes = storage.record_parts(image[first:first + fixture.RECORD])
            stream, runs = storage.mapping(next(value for value in attributes
                if storage.attr_header(value)['type'] == fixture.DATA))
            self.assertEqual(stream['size'], 4 * 1024 * 1024)
            self.assertEqual(len(runs), 1)
            log_first = runs[0][1] * fixture.CLUSTER
            restart, header, _ = restore_page(image[log_first:log_first + wire.PAGE_BYTES], wire.RESTART_HEADER)
            area = fields(wire.RESTART_AREA, restart, header['area_offset'])
            client = fields(wire.CLIENT, restart, header['area_offset'] + area['clients_offset'])
            self.assertEqual(area['sequence_bits'], 44)
            self.assertGreaterEqual(client['oldest_lsn'] >> 20, 17)
            logical = (client['restart_lsn'] & ((1 << 20) - 1)) << wire.OFFSET_SHIFT
            home = logical // wire.PAGE_BYTES * wire.PAGE_BYTES
            page, _, _ = restore_page(image[log_first + home:log_first + home + wire.PAGE_BYTES], wire.PAGE)
            payload = logical - home + wire.RECORD.size
            historical_offset = payload + CLIENT_RESTART.size + struct.calcsize('<Q')
            historical, = struct.unpack_from('<Q', page, historical_offset)
            self.assertEqual(historical, 0x01000000)
            self.assertLess(historical, client['oldest_lsn'])
            before = (output / 'profile.json').read_bytes()
            with self.assertRaises(FileExistsError):
                profile.prepare(SOURCE, output)
            self.assertEqual((output / 'profile.json').read_bytes(), before)

    def test_compare_rejects_new_fixture_before_toolchain_or_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'absent'
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/benchmark_write.py'),
                'compare', '--output', str(output), '--fixture', str(SOURCE),
                '--compiler', '/nonexistent-compiler'], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'--fixture is only valid for a new prepare stage', result.stderr)
            self.assertFalse(output.exists())

    def test_invalid_source_is_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'absent'
            with self.assertRaises(ValueError):
                profile.prepare(root, output)
            large = root / 'large'
            with large.open('wb') as stream:
                stream.truncate(profile.SOURCE_BYTES_MAX + 1)
            with self.assertRaises(ValueError):
                profile.prepare(large, output)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    SOURCE = Path(sys.argv.pop(1)).resolve(strict=True)
    unittest.main()
