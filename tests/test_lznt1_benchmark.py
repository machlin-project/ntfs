#!/usr/bin/env python3
"""Harness fixtures are deterministic originals; preparation refuses reuse."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from benchmark_lznt1 import author


class EncoderBenchmarkFixtures(unittest.TestCase):
    def test_deterministic_and_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / 'first', root / 'second'
            profiles = author(first)
            self.assertEqual(profiles, author(second))
            self.assertEqual(len(profiles), 18)
            self.assertEqual(len({entry['name'] for entry in profiles}), len(profiles))
            self.assertEqual(json.loads((first / 'profiles.json').read_text()), profiles)
            for entry in profiles:
                name = f"{entry['name']}.data"
                data = (first / name).read_bytes()
                self.assertEqual(len(data), entry['bytes'])
                self.assertEqual(data, (second / name).read_bytes())
            self.assertEqual((first / 'empty.data').read_bytes(), b'')
            self.assertEqual((first / 'tiny-raw.data').read_bytes(), b'CAT')
            self.assertEqual((first / 'zeros-1048576.data').read_bytes(), b'\0' * 1048576)
            mixed = (first / 'mixed-65536.data').read_bytes()
            noise = (first / 'noise-65536.data').read_bytes()
            for offset in range(0, len(mixed), 4096):
                expected = noise[offset:offset + 4096] if offset % 8192 else b'Q' * 4096
                self.assertEqual(mixed[offset:offset + 4096], expected)
            with self.assertRaises(FileExistsError):
                author(first)


if __name__ == '__main__':
    unittest.main()
