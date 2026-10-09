#!/usr/bin/env python3
"""Original synthetic checks of corpus transport, never a native codec verdict."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('windows_lznt1', ROOT / 'scripts' / 'collect_windows_lznt1.py')
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)


class OriginalDecoder:
    def decode(self, packed, expected_size):
        if packed != b'\x02\x30CAT' or expected_size != 3:
            raise ValueError('Unexpected original transport packet')
        return {'status': 0, 'written': 3, 'input_unchanged': True,
                'output_guards': True, 'data': b'CAT'}


class Contracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.corpus = self.root / 'corpus'
        self.corpus.mkdir()
        (self.corpus / 'case-0000.data').write_bytes(b'CAT')
        (self.corpus / 'case-0000.packed').write_bytes(b'\x02\x30CAT')
        self.output = self.root / 'result'

    def collect(self, decoder=None):
        report = ORACLE.collect(self.corpus, self.output, test_decoder=decoder or OriginalDecoder())
        self.assertEqual(report, json.loads((self.output / 'report.json').read_text()))
        self.assertEqual(report['provenance'], ORACLE.SYNTHETIC_PROVENANCE)
        return report

    def test_complete_original_packet(self):
        report = self.collect()
        self.assertTrue(report['passed'] and report['complete'])
        self.assertEqual(len(report['cases']), 1)
        self.assertTrue(report['cases'][0]['source_files_unchanged'])
        with self.assertRaises(FileExistsError):
            ORACLE.collect(self.corpus, self.output, test_decoder=OriginalDecoder())

    def test_each_native_verdict_dimension_is_required(self):
        dimensions = {'status': 1, 'written': 2, 'input_unchanged': False,
                      'output_guards': False, 'data': b'DOG'}
        for index, (name, value) in enumerate(dimensions.items()):
            class IncorrectDecoder(OriginalDecoder):
                def decode(self, packed, expected_size):
                    result = super().decode(packed, expected_size)
                    result[name] = value
                    return result
            self.output = self.root / f'incorrect-{index}'
            report = self.collect(IncorrectDecoder())
            self.assertFalse(report['passed'] or report['complete'])
            self.assertEqual(len(report['cases']), 1)

    def test_source_changes_fail(self):
        path = self.corpus / 'case-0000.data'
        class MutatingDecoder(OriginalDecoder):
            def decode(self, packed, expected_size):
                result = super().decode(packed, expected_size)
                path.write_bytes(b'DOG')
                return result
        report = self.collect(MutatingDecoder())
        self.assertFalse(report['passed'])
        self.assertFalse(report['cases'][0]['source_files_unchanged'])

    def test_unpaired_rejected(self):
        (self.corpus / 'case-0000.data').unlink()
        self.assertFalse(self.collect()['passed'])

    def test_unit_and_packet_ordinals_are_independent(self):
        (self.corpus / 'unit-0000.data').write_bytes(b'CAT')
        (self.corpus / 'unit-0000.packed').write_bytes(b'\x02\x30CAT')
        report = self.collect()
        self.assertTrue(report['passed'] and report['complete'])
        self.assertEqual([row['case'] for row in report['cases']], ['0000', 'unit-0000'])

    def test_cross_family_members_cannot_form_a_pair(self):
        (self.corpus / 'case-0000.packed').rename(self.corpus / 'unit-0000.packed')
        report = self.collect()
        self.assertFalse(report['passed'] or report['complete'])
        self.assertEqual(report['cases'], [])

    def test_empty_rejected(self):
        (self.corpus / 'case-0000.data').write_bytes(b'')
        self.assertFalse(self.collect()['passed'])

    def test_unexpected_name_rejected(self):
        (self.corpus / 'untrusted.txt').write_text('nothing')
        self.assertFalse(self.collect()['passed'])

    def test_oversized_member_rejected(self):
        with (self.corpus / 'case-0000.data').open('wb') as stream:
            stream.truncate(ORACLE.MAX_INPUT_BYTES + 1)
        self.assertFalse(self.collect()['passed'])

    def test_count_bound_rejected(self):
        saved = ORACLE.MAX_CASES
        try:
            ORACLE.MAX_CASES = 0
            self.assertFalse(self.collect()['passed'])
        finally:
            ORACLE.MAX_CASES = saved

    def test_aggregate_bound_rejected(self):
        saved = ORACLE.MAX_CORPUS_BYTES
        try:
            ORACLE.MAX_CORPUS_BYTES = 1
            self.assertFalse(self.collect()['passed'])
        finally:
            ORACLE.MAX_CORPUS_BYTES = saved

    def test_missing_windows_is_not_a_pass(self):
        if ORACLE.sys.platform == 'win32':
            self.skipTest('Non-Windows refusal is tested only outside Windows')
        report = ORACLE.collect(self.corpus, self.output)
        self.assertFalse(report['passed'] or report['complete'])
        self.assertIn('requires Windows', report['error'])
        self.assertEqual(report['cases'], [])


if __name__ == '__main__':
    unittest.main()
