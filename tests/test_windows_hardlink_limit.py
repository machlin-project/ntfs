#!/usr/bin/env python3
"""Synthetic observer/report contracts. These are never native Windows evidence."""
from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest import mock
import ctypes
import json

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hardlink_observer',
    ROOT / 'scripts/collect_windows_hardlink_limit.py')
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class SyntheticProvider:
    def __init__(self, fail_early=None, limit_error=observer.ERROR_TOO_MANY_LINKS,
                 mutate_failure=False, wrong_count=False):
        self.entries = set()
        self.fail_early = fail_early
        self.limit_error = limit_error
        self.mutate_failure = mutate_failure
        self.wrong_count = wrong_count
        self.payload = self.ads = None

    def create(self, name, payload, ads):
        self.entries.add(name)
        self.payload, self.ads = payload, ads

    def observe(self, name):
        assert name in self.entries
        return dict(volume_serial=17, file_id=29,
            links=len(self.entries) + (1 if self.wrong_count else 0),
            size=len(self.payload), attributes=32,
            payload_sha256=observer.sha256(self.payload),
            ads_sha256=observer.sha256(self.ads), raw_file_information_hex='synthetic')

    def link(self, name, source):
        assert source in self.entries and name not in self.entries
        if self.fail_early is not None and len(self.entries) == self.fail_early:
            return False, 5
        if len(self.entries) == observer.MAX_ADDITIONAL_LINKS + 1:
            if self.mutate_failure:
                self.ads += b'changed'
            return False, self.limit_error
        self.entries.add(name)
        return True, 0

    def names(self):
        return set(self.entries)


class ObserverContract(unittest.TestCase):
    def test_wire_layout(self):
        self.assertEqual(ctypes.sizeof(observer.FileTime), 8)
        self.assertEqual(ctypes.sizeof(observer.FileInformation), 52)
        self.assertEqual(observer.FileInformation.links.offset, 40)
        self.assertEqual(observer.FileInformation.file_index_high.offset, 44)

    def test_bounded_complete_reporting(self):
        report = {}
        observer.collect(SyntheticProvider(), report)
        self.assertTrue(report['checks_complete'])
        self.assertEqual(len(report['calls']), 1023)
        self.assertEqual(report['observed_maximum_total_links'], 1024)
        self.assertEqual(len(report['checkpoints']), 7)
        self.assertEqual(report['limit_attempt']['win32_error'], 1142)
        self.assertNotIn('native', report)
        self.assertNotIn('complete', report)

    def test_early_failure_retained(self):
        report = {}
        with self.assertRaisesRegex(RuntimeError, 'failed early at additional link 7'):
            observer.collect(SyntheticProvider(fail_early=7), report)
        self.assertEqual(len(report['calls']), 7)
        self.assertEqual(report['calls'][-1]['win32_error'], 5)
        self.assertEqual(report['early_failure_state']['links'], 7)
        self.assertNotIn('checks_complete', report)

    def test_wrong_limit_error_refused(self):
        report = {}
        with self.assertRaisesRegex(RuntimeError, 'Unexpected limit error'):
            observer.collect(SyntheticProvider(limit_error=5), report)
        self.assertEqual(report['limit_attempt']['win32_error'], 5)
        self.assertNotIn('checks_complete', report)

    def test_failure_side_effect_refused(self):
        report = {}
        with self.assertRaisesRegex(RuntimeError, 'Failed call changed'):
            observer.collect(SyntheticProvider(mutate_failure=True), report)
        self.assertNotIn('checks_complete', report)

    def test_invented_initial_count_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'exactly one link'):
            observer.collect(SyntheticProvider(wrong_count=True), {})

    def test_preexisting_report_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'evidence'
            output.mkdir()
            marker = output / 'keep.txt'
            marker.write_bytes(b'original')
            with self.assertRaises(FileExistsError):
                observer.main(['--output', str(output)])
            self.assertEqual(marker.read_bytes(), b'original')

    def test_non_windows_never_claims_native(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                observer.sys, 'platform', 'linux'):
            output = Path(directory) / 'evidence'
            self.assertEqual(observer.main(['--output', str(output)]), 1)
            report = json.loads((output / 'report.json').read_text())
            self.assertFalse(report['native'])
            self.assertFalse(report['complete'])
            self.assertFalse(report['checks_complete'])
            self.assertNotIn('owned_temp_directory', report)


if __name__ == '__main__':
    unittest.main()
