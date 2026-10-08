#!/usr/bin/env python3
"""Pinned-source, preservation and failure-report contracts; no external downloads."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import bootstrap_test_tools as bootstrap
import interoperability


class Response(io.BytesIO):
    def geturl(self):
        return bootstrap.ARCHIVE_URL


class ExternalToolContracts(unittest.TestCase):
    def test_static_utilities_do_not_install_library_or_system_helpers(self):
        configured = bootstrap.configure_command()
        for flag in ('--disable-ntfs-3g', '--disable-library', '--disable-shared',
                     '--enable-static', '--disable-mount-helper', '--disable-ldconfig'):
            self.assertIn(flag, configured)
        self.assertIn('--prefix=/ntfs-tools', configured)
        self.assertIn('--exec-prefix=/ntfs-tools', configured)

    def test_original_archive_pin_is_unchanged(self):
        self.assertEqual(bootstrap.ARCHIVE_SHA256,
                         'f20e36ee68074b845e3629e6bced4706ad053804cbaf062fbae60738f854170c')

    def test_download_hash_failure_retains_original_partial(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'original.download'
            with patch.object(bootstrap.urllib.request, 'urlopen', return_value=Response(b'wrong bytes')):
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    bootstrap.download(path)
            self.assertEqual(path.read_bytes(), b'wrong bytes')
            with patch.object(bootstrap.urllib.request, 'urlopen', return_value=Response(b'new bytes')):
                with self.assertRaises(FileExistsError):
                    bootstrap.download(path)
            self.assertEqual(path.read_bytes(), b'wrong bytes')

    def test_download_byte_budget_and_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(bootstrap.urllib.request, 'urlopen', return_value=Response(b'abcd')), \
                    patch.object(bootstrap, 'DOWNLOAD_BYTES_MAX', 3):
                with self.assertRaisesRegex(ValueError, 'byte budget'):
                    bootstrap.download(directory / 'large.download')
            value = b'original verified bytes'
            with patch.object(bootstrap.urllib.request, 'urlopen', return_value=Response(value)), \
                    patch.object(bootstrap, 'ARCHIVE_SHA256', hashlib.sha256(value).hexdigest()):
                self.assertEqual(bootstrap.download(directory / 'verified.download'), len(value))
            self.assertEqual((directory / 'verified.download').read_bytes(), value)

    def test_archive_rejects_escape_links_duplicates_and_limits(self):
        root = 'ntfs-3g_ntfsprogs-' + bootstrap.VERSION
        for names, link in ((['../escape'], False), (['other/entry'], False),
                            ([root + '/entry'], True), ([root + '/entry', root + '/./entry'], False)):
            with self.subTest(names=names, link=link), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                archive = directory / 'archive.tgz'
                with tarfile.open(archive, 'w:gz') as target:
                    for name in names:
                        item = tarfile.TarInfo(name)
                        if link:
                            item.type, item.linkname = tarfile.SYMTYPE, '../../escape'
                            target.addfile(item)
                        else:
                            item.size = 1
                            target.addfile(item, io.BytesIO(b'x'))
                with self.assertRaises(ValueError):
                    bootstrap.extract(archive, directory)
                self.assertFalse((directory / root).exists())

    def test_unexpected_git_tag_stops_before_checkout_or_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(output=root / 'reports', prefix=root / 'vendor/tools',
                                   compiler='cc', source='git-pinned')
            calls = []
            def run(argv, output, label, env, **kwargs):
                calls.append(label)
                return 'wrong-commit\n' if label == 'source-commit' else 'fake compiler\n'
            with patch.object(bootstrap, 'ROOT', root), \
                    patch.object(bootstrap, 'selected_toolchain', return_value={'CC': '/fake/compiler'}), \
                    patch.object(bootstrap, 'command', side_effect=run):
                with self.assertRaisesRegex(ValueError, 'pinned commit'):
                    bootstrap.bootstrap(args)
            self.assertEqual(calls, ['compiler-version', 'clone', 'source-commit'])
            report = json.loads((args.output / 'report.json').read_text())
            self.assertEqual(report['status'], 'fail')
            self.assertTrue(report['errors'])
            self.assertFalse(args.prefix.exists())

    def test_prefix_cannot_escape_vendor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(output=root / 'reports', prefix=root / 'vendor/../outside',
                                   compiler='cc', source='archive')
            with patch.object(bootstrap, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'ignored vendor'):
                    bootstrap.bootstrap(args)
            self.assertFalse((root / 'outside').exists())
            self.assertEqual(json.loads((args.output / 'report.json').read_text())['status'], 'fail')

    def test_oracle_missing_reader_reports_failure_and_preserves_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(output=root / 'report', reader=root / 'missing',
                                   tools=root / 'tools', tool_provenance=None)
            with self.assertRaises(FileNotFoundError):
                interoperability.verify(args)
            report_path = args.output / 'report.json'
            original = report_path.read_bytes()
            self.assertEqual(json.loads(original)['status'], 'fail')
            with self.assertRaises(FileExistsError):
                interoperability.verify(args)
            self.assertEqual(report_path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
