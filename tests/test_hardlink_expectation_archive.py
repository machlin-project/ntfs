#!/usr/bin/env python3
"""Synthetic immutable-archive selection, sparse bytes and refusal contracts."""
from pathlib import Path
import hashlib
import json
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from extract_hardlink_expectations import FILES, PREFIX, PROFILES, extract
from review_windows_hardlink import digest


def archive(path, *, duplicate=False, symlink=False, missing=False):
    before = b'original' + bytes(2 * 1024 * 1024) + b'trailing-sector-witness'
    entries = {f'{PREFIX}/result.json': json.dumps(dict(status='pass',
        storageFamily='selected-cache-posix-hardlink')).encode()}
    for profile in PROFILES:
        first = f'{PREFIX}/{profile}/selected-operation/'
        entries[first + 'before.ntfs'] = before
        entries[first + 'hardlink-transition.json'] = json.dumps(dict(
            sourceSha256=hashlib.sha256(before).hexdigest())).encode()
    if missing:
        entries.pop(FILES[-1])
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as output:
        for name, value in entries.items():
            if symlink and name == FILES[0]:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                output.writestr(info, value)
            else:
                output.writestr(name, value)
        output.writestr(f'{PREFIX}/unused/recovered.ntfs', bytes(8 * 1024 * 1024))
        output.writestr('../escape', b'never selected')
        if duplicate:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                output.writestr(FILES[0], entries[FILES[0]])
    binding = dict(sourceRun=1, sourceSha='1' * 40,
        artifacts=[dict(name='hardlink-c-preparation', id=2, digest='sha256:' + digest(path))])
    return binding, entries


class ArchiveContracts(unittest.TestCase):
    def test_only_originals_and_exact_sparse_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'source.zip', root / 'output'
            binding, entries = archive(source)
            original_hash = digest(source)
            result = extract(source, binding, output)
            self.assertEqual(result['status'], 'pass')
            self.assertEqual(result['extractedFiles'], 7)
            self.assertEqual({row['name'] for row in result['files']}, set(FILES))
            for name, value in entries.items():
                self.assertEqual((output / name).read_bytes(), value)
                self.assertEqual((output / name).stat().st_mode & 0o777, 0o444)
            self.assertFalse((output / PREFIX / 'unused').exists())
            self.assertFalse((root / 'escape').exists())
            self.assertEqual(digest(source), original_hash)

    def test_archive_digest_before_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'source.zip', root / 'output'
            binding, _ = archive(source)
            binding['artifacts'][0]['digest'] = 'sha256:' + '0' * 64
            with self.assertRaises(ValueError):
                extract(source, binding, output)
            self.assertFalse(output.exists())

    def test_duplicate_missing_and_link_originals_refused(self):
        for mode in ('duplicate', 'missing', 'symlink'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, output = root / 'source.zip', root / 'output'
                binding, _ = archive(source, **{mode: True})
                with self.assertRaises(ValueError):
                    extract(source, binding, output)
                self.assertEqual(json.loads((output / 'expectation-extraction.json').read_text())['status'], 'fail')


if __name__ == '__main__':
    unittest.main()
