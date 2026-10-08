"""Source exports and bounded Release-build process contracts, without Meson."""
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import check_reproducible as check
from environment import tool_environment


def archive_file(name, *, kind=tarfile.REGTYPE, size=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.linkname = '/outside'
        member.size = 3 if size is None else size
        archive.addfile(member, io.BytesIO(b'abc'))
    return output.getvalue()


class ReproducibilityTests(unittest.TestCase):
    def test_clean_export_and_existing_output_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'source'
            data = archive_file('core/example.c')
            check.export_sources(data, directory)
            self.assertEqual((directory / 'core/example.c').read_bytes(), b'abc')
            with self.assertRaises(FileExistsError):
                check.export_sources(data, directory)
            self.assertEqual((directory / 'core/example.c').read_bytes(), b'abc')

    def test_export_refuses_escaping_or_special_members_before_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            for name, kind in (('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
                               ('link', tarfile.SYMTYPE), ('hardlink', tarfile.LNKTYPE),
                               ('fifo', tarfile.FIFOTYPE)):
                directory = Path(temporary) / 'source'
                with self.subTest(name=name), self.assertRaises(ValueError):
                    check.export_sources(archive_file(name, kind=kind), directory)
                self.assertFalse(directory.exists())

    def test_export_byte_budgets(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'source'
            data = archive_file('source.c')
            with patch.object(check, 'MAX_SOURCE_ARCHIVE_BYTES', len(data) - 1):
                with self.assertRaisesRegex(ValueError, 'archive exceeds'):
                    check.export_sources(data, directory)
            with patch.object(check, 'MAX_SOURCE_EXPANDED_BYTES', 2):
                with self.assertRaisesRegex(ValueError, 'Expanded'):
                    check.export_sources(data, directory)
            self.assertFalse(directory.exists())

    def test_prefix_maps_cover_absolute_and_relative_compiler_paths(self):
        flags = json.loads(check.path_map_options(Path('/source tree'), Path('/build tree'))[0].split('=', 1)[1])
        self.assertIn('-ffile-prefix-map=/source tree=.', flags)
        self.assertIn('-ffile-prefix-map=../source tree=.', flags)
        self.assertIn('-fdebug-prefix-map=/build tree=.build', flags)

    def test_logged_success_and_failure_retain_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            log = directory / 'build.log'
            check.run_logged([sys.executable, '-c', 'print("clean result")'], log,
                             tool_environment(), 10, cwd=directory)
            self.assertEqual(log.read_text().strip(), 'clean result')
            with self.assertRaisesRegex(RuntimeError, 'exited 7'):
                check.run_logged([sys.executable, '-c', 'print("original failure"); raise SystemExit(7)'],
                                 log, tool_environment(), 10, cwd=directory)
            self.assertIn('original failure', log.read_text())

    def test_log_and_deadline_limits_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            log = directory / 'build.log'
            with patch.object(check, 'MAX_BUILD_LOG_BYTES', 128):
                with self.assertRaisesRegex(ValueError, 'retained-log budget'):
                    check.run_logged([sys.executable, '-c', 'print("x" * 4096)'], log,
                                     tool_environment(), 10, cwd=directory)
            self.assertEqual(log.stat().st_size, 128)
            with self.assertRaises(TimeoutError):
                check.run_logged([sys.executable, '-c', 'import time; time.sleep(20)'], log,
                                 tool_environment(), 0.1, cwd=directory)


if __name__ == '__main__':
    unittest.main()
