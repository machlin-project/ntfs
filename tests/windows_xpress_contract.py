#!/usr/bin/env python3
"""Synthetic native-transport checks, never a Windows XPRESS codec verdict."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('windows_xpress', ROOT / 'scripts/collect_windows_xpress.py')
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)
VECTORS = (('required', b'original packet', b'CAT', True),
           ('optional', b'variant packet', b'CAT', False))


class OriginalDecoder:
    def __init__(self):
        self.closed = 0

    def decode(self, packed, expected_size):
        if packed not in {row[1] for row in VECTORS} or expected_size != 3:
            raise ValueError('Unexpected synthetic transport input')
        return dict(accepted=True, last_error=0, written=3, input_unchanged=True,
                    output_guards=True, data=b'CAT')

    def close(self):
        self.closed += 1


class Contracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'result'

    def collect(self, decoder=None, vectors=VECTORS):
        decoder = decoder or OriginalDecoder()
        report = ORACLE.collect(self.output, test_decoder=decoder, test_vectors=vectors)
        self.assertEqual(report, json.loads((self.output / 'report.json').read_text()))
        self.assertEqual(report['provenance'], ORACLE.SYNTHETIC_PROVENANCE)
        self.assertFalse(report['native_observation'])
        return report, decoder

    def test_success_closes_and_preserves_originals(self):
        report, decoder = self.collect()
        self.assertTrue(report['complete'] and report['passed'] and report['closed'])
        self.assertEqual((report['required_cases'], report['accepted_cases'], decoder.closed), (1, 2, 1))
        self.assertEqual(report['compatibility_refusals'], [])
        with self.assertRaises(FileExistsError):
            self.collect()

    def test_each_required_verdict_dimension_fails(self):
        for index, (name, value) in enumerate(dict(accepted=False, written=2,
                input_unchanged=False, output_guards=False, data=b'DOG').items()):
            class Incorrect(OriginalDecoder):
                def decode(self, packed, expected_size):
                    result = super().decode(packed, expected_size)
                    result[name] = value
                    return result
            self.output = self.root / f'failure-{index}'
            report, decoder = self.collect(Incorrect())
            self.assertFalse(report['passed'] or report['complete'])
            self.assertEqual((report['failure_stage'], len(report['cases']), decoder.closed), ('comparison', 1, 1))

    def test_optional_refusal_is_explicit(self):
        class Refuses(OriginalDecoder):
            def decode(self, packed, expected_size):
                result = super().decode(packed, expected_size)
                if packed == VECTORS[1][1]:
                    result.update(accepted=False, last_error=605, written=0, data=b'???')
                return result
        report, _ = self.collect(Refuses())
        self.assertTrue(report['passed'] and report['complete'])
        self.assertEqual(report['compatibility_refusals'], ['optional'])
        self.assertEqual(report['accepted_cases'], 1)
        self.assertFalse(report['cases'][1]['compatible'])

    def test_optional_acceptance_with_wrong_data_fails(self):
        class Wrong(OriginalDecoder):
            def decode(self, packed, expected_size):
                result = super().decode(packed, expected_size)
                if packed == VECTORS[1][1]:
                    result['data'] = b'DOG'
                return result
        report, _ = self.collect(Wrong())
        self.assertFalse(report['passed'])
        self.assertEqual(report['active_case'], 'optional')

    def test_optional_refusal_cannot_hide_guard_damage(self):
        class Damaged(OriginalDecoder):
            def decode(self, packed, expected_size):
                result = super().decode(packed, expected_size)
                if packed == VECTORS[1][1]:
                    result.update(accepted=False, output_guards=False)
                return result
        report, _ = self.collect(Damaged())
        self.assertFalse(report['passed'])

    def test_source_change_fails_with_bounded_read(self):
        path = self.output / 'corpus/case-0000.data'
        class Mutating(OriginalDecoder):
            def decode(self, packed, expected_size):
                result = super().decode(packed, expected_size)
                with path.open('wb') as stream:
                    stream.truncate(ORACLE.MAX_CORPUS_BYTES + 1)
                return result
        report, _ = self.collect(Mutating())
        self.assertFalse(report['passed'])
        self.assertFalse(report['cases'][0]['source_files_unchanged'])

    def test_acquisition_refusal_is_distinct(self):
        with mock.patch.object(ORACLE, 'WindowsDecoder', side_effect=RuntimeError('API unavailable')), \
             mock.patch.object(ORACLE, 'vectors', return_value=iter(VECTORS)):
            report = ORACLE.collect(self.output)
        self.assertFalse(report['passed'] or report['native_observation'] or report['acquisition_complete'])
        self.assertEqual(report['failure_stage'], 'acquisition')
        self.assertEqual(report['cases'], [])

    def test_reset_failure_is_distinct_and_closes(self):
        class Refuses(OriginalDecoder):
            def decode(self, packed, expected_size):
                raise ORACLE.NativeStageError('reset', 'ResetDecompressor refused')
        report, decoder = self.collect(Refuses())
        self.assertEqual((report['failure_stage'], decoder.closed), ('reset', 1))
        self.assertFalse(report['passed'])

    def test_cleanup_failure_cannot_report_success(self):
        class Refuses(OriginalDecoder):
            def close(self):
                raise RuntimeError('Close refused')
        report, _ = self.collect(Refuses())
        self.assertFalse(report['passed'] or report['complete'])
        self.assertEqual(report['failure_stage'], 'cleanup')

    def test_bounds_and_unique_identities(self):
        cases = ((), (VECTORS[0], VECTORS[0]),
                 (('empty', b'packet', b'', True),),
                 (('large', bytes(ORACLE.MAX_PACKED_BYTES + 1), b'A', True),),
                 (('optional-only', b'packet', b'A', False),))
        for index, vectors in enumerate(cases):
            self.output = self.root / f'bound-{index}'
            report, _ = self.collect(vectors=vectors)
            self.assertFalse(report['passed'] or report['acquisition_complete'])
            self.assertEqual(report['failure_stage'], 'authoring')

    def test_count_and_aggregate_budgets(self):
        for index, (name, value) in enumerate((('MAX_CASES', 1), ('MAX_CORPUS_BYTES', 1))):
            self.output = self.root / f'budget-{index}'
            with mock.patch.object(ORACLE, name, value):
                report, _ = self.collect()
            self.assertFalse(report['passed'] or report['acquisition_complete'])

    def test_synthetic_inputs_cannot_claim_native(self):
        with self.assertRaises(ValueError):
            ORACLE.collect(self.output, test_vectors=VECTORS)
        self.assertFalse(self.output.exists())

    def test_original_fixture_inventory(self):
        rows = list(ORACLE.vectors())
        self.assertTrue(0 < len(rows) <= ORACLE.MAX_CASES)
        self.assertEqual(len({row[0] for row in rows}), len(rows))
        self.assertTrue(all(0 < len(row[2]) <= ORACLE.MAX_INPUT_BYTES for row in rows))
        self.assertTrue(all(0 < len(row[1]) <= ORACLE.MAX_PACKED_BYTES for row in rows))
        self.assertLessEqual(sum(len(row[1]) + len(row[2]) for row in rows), ORACLE.MAX_CORPUS_BYTES)
        self.assertTrue(any('width-15' in row[0] for row in rows))
        self.assertTrue(any('all-literals' in row[0] for row in rows))
        self.assertEqual(sum(not row[3] for row in rows), 4)


if __name__ == '__main__':
    unittest.main()
