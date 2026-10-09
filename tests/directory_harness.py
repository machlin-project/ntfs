"""Pure model and cut-selection regressions; never opens a device or starts a VM."""
import copy
from pathlib import Path
import tempfile
import unittest

import directory_scenarios as scenario
import fixtures as wire
from native_directory_batch import Batch, native_cuts, stage_values
from native_growth_faults import FRAME_BYTES, SECTOR_BYTES


class WriterRefusal(Exception):
    pass


class AdmissionBatch(Batch):
    """Observe ordering only; no executable, device or image backend exists."""
    def __init__(self, output, states):
        super().__init__(output, Path('/unused-build'), None)
        self.directories['native-growth'] = 42
        self.states = list(states)
        self.order = []

    def state(self, directory, name, image, reference):
        self.order.append(name)
        return self.states.pop(0)

    def checkpoint(self, ordinal, reason='periodic'):
        self.order.append(('checkpoint', ordinal, reason))

    def clone(self, directory, name, source, destination):
        self.order.append(name)
        destination.touch()

    def json_command(self, directory, name, argv):
        self.order.append(name)
        raise WriterRefusal('independent writer refusal')


def admitted_state(pressure):
    return dict(settled=True, mftReservedAllocationMask=0, checkpointNeeded=pressure)


class DirectoryHarness(unittest.TestCase):
    def test_checkpoint_pressure_precedes_frozen_predecessor_and_writer(self):
        for pressure in (False, True):
            with self.subTest(pressure=pressure), tempfile.TemporaryDirectory() as temporary:
                states = [admitted_state(pressure)]
                if pressure:
                    states.append(admitted_state(False))
                states.append(admitted_state(False))
                batch = AdmissionBatch(Path(temporary), states)
                with self.assertRaises(WriterRefusal):
                    batch.mutate(288, 'create', 'native-growth/next', (), None, 0)
                expected = ['admission-state']
                if pressure:
                    expected += [('checkpoint', 288, 'admission-pressure'),
                                 'admission-after-checkpoint']
                expected += ['clone-before', 'before-state', 'writer']
                self.assertEqual(batch.order, expected)
                self.assertEqual(batch.order.count('writer'), 1)
                self.assertFalse(batch.report['automaticRetry'])

    def test_unknown_or_unsettled_admission_stops_before_checkpoint_or_clone(self):
        invalid = [admitted_state(value) for value in (None, 0, 1, 'false')]
        invalid += [dict(settled=True, mftReservedAllocationMask=0),
                    dict(admitted_state(True), settled=False),
                    dict(admitted_state(True), mftReservedAllocationMask=1)]
        for state in invalid:
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temporary:
                batch = AdmissionBatch(Path(temporary), [state])
                with self.assertRaises((AssertionError, KeyError)):
                    batch.mutate(288, 'create', 'native-growth/next', (), None, 0)
                self.assertEqual(batch.order, ['admission-state'])

    def test_checkpoint_must_clear_pressure_before_freezing_predecessor(self):
        with tempfile.TemporaryDirectory() as temporary:
            batch = AdmissionBatch(Path(temporary), [admitted_state(True), admitted_state(True)])
            with self.assertRaises(AssertionError):
                batch.mutate(288, 'create', 'native-growth/next', (), None, 0)
            self.assertEqual(batch.order, ['admission-state',
                             ('checkpoint', 288, 'admission-pressure'),
                             'admission-after-checkpoint'])

    def test_phase_names_from_operations(self):
        files, folders, phases = set(), set(), []
        for operation, path, extra, phase in scenario.operations():
            if operation == 'mkdir':
                self.assertNotIn(path, folders)
                folders.add(path)
            elif operation == 'create':
                self.assertNotIn(path, files)
                files.add(path)
            elif operation == 'remove':
                files.remove(path)
            else:
                self.assertEqual(operation, 'rename')
                self.assertNotIn(extra[0], files)
                files.remove(path)
                files.add(extra[0])
            self.assertLessEqual(len(files), scenario.PRESSURE_FILES)
            if phase:
                self.assertEqual(files, set(scenario.expected(phase)))
                self.assertEqual(folders, set(scenario.DIRECTORIES))
                phases.append(phase)
        self.assertEqual(phases, list(scenario.PHASES))
        self.assertFalse(files)

    def test_content_oracle_is_bound_to_identity(self):
        self.assertEqual(scenario.contents(0, True)[:4], bytes((0, 0, 85, 122)))
        self.assertEqual(scenario.contents(1, True)[:4], bytes((0, 1, 102, 139)))
        self.assertEqual(len({scenario.contents(index, True) for index in range(400)}), 400)
        for phase in scenario.PHASES:
            self.assertEqual(set(scenario.expected(phase)), set(scenario.expected(phase, True)))
            self.assertTrue(all(len(value) == scenario.PAYLOAD_BYTES for value in scenario.expected(phase, True).values()))

    def test_cuts_cover_commit_sides_and_each_metadata_class(self):
        stages = stage_values()
        labels = ('DIRTY_FIRST', 'DIRTY_SECOND', 'PREPARE_COPY', 'PREPARE_HOME',
                  'COMMIT_COPY', 'COMMIT_HOME', 'METADATA_HOME', 'METADATA_HOME',
                  'METADATA_HOME', 'CLEAN_FIRST', 'CLEAN_SECOND')
        publications = [dict(stage=stages[label], physical=index * FRAME_BYTES,
                             bytes=FRAME_BYTES, barrier=True) for index, label in enumerate(labels)]
        regions = [dict(physical=publications[6]['physical'], attribute_type=wire.INDEX_ALLOC, index_allocated=True),
                   dict(physical=publications[7]['physical'], attribute_type=wire.INDEX_ALLOC, index_allocated=False),
                   dict(physical=publications[8]['physical'], attribute_type=wire.DATA, reference=0, mirror=False, logical=0)]
        plan = dict(publications=publications, regions=regions)
        original = copy.deepcopy(plan)
        cuts = native_cuts(plan, FRAME_BYTES)
        self.assertEqual(plan, original)
        selected = {(row['complete'], row['prefixBytes']) for row in cuts}
        self.assertEqual(len(selected), len(cuts))
        for position in (4, 5):
            self.assertIn((position, 0), selected)
            self.assertIn((position, SECTOR_BYTES), selected)
        for position in (6, 7, 8):
            self.assertIn((position, SECTOR_BYTES), selected)
        for row in cuts:
            self.assertEqual(row['winner'], row['complete'] > 4)


if __name__ == '__main__':
    unittest.main()
