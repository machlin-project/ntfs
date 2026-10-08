"""Independent synthetic packaging contracts; these fixtures are not runnable apps."""
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

TOOL = Path(__file__).resolve().parents[1] / 'scripts/package_unsigned.py'
spec = importlib.util.spec_from_file_location('package_unsigned', TOOL)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

SOURCE = {'role': 'packaging-checkout', 'revision': '0' * 40, 'tree': '1' * 40, 'epoch': 1720000000}
LICENSE = b'Fixture proprietary license; not a distribution grant.\n'
PROVENANCE = b'Fixture independently authored payloads, no external runtime.\n'


def universal(*, signed=False, adhoc=False, dependencies=(), cpus=(0x01000007, 0x0100000c)):
    slices = []
    for cpu in cpus:
        commands = []
        for dependency in dependencies:
            raw = dependency.encode() + b'\0'
            size = (24 + len(raw) + 7) & ~7
            commands.append(struct.pack('<6I', 0xc, size, 24, 0, 0, 0) + raw + b'\0' * (size - 24 - len(raw)))
        signature = b''
        if signed or adhoc:
            directory = struct.pack('>11I', 0xfade0c02, 44, 0x20001, 2 if adhoc else 0,
                                    0, 0, 0, 0, 0, 0, 0)
            signature = struct.pack('>5I', 0xfade0cc0, 20 + len(directory), 1, 0, 20) + directory
            offset = 32 + sum(map(len, commands)) + 16
            commands.append(struct.pack('<4I', 0x1d, 16, offset, len(signature)))
        body = b''.join(commands)
        slices.append(struct.pack('<8I', 0xfeedfacf, cpu, 0, 2, len(commands), len(body), 0, 0) + body + signature)
    cursor = 8 + len(cpus) * 20
    entries = []
    for cpu, data in zip(cpus, slices):
        entries.append(struct.pack('>5I', cpu, 0, cursor, len(data), 0))
        cursor += len(data)
    return struct.pack('>2I', 0xcafebabe, len(cpus)) + b''.join(entries + slices)


def write_file(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def fixture(root, **macho_options):
    app = root / 'Machlin NTFS.app'
    for subpath, identifier, package_type, executable in (
            ('', 'org.machlin.ntfs', 'APPL', 'Machlin NTFS'),
            ('Contents/Extensions/NTFSExtension.appex', 'org.machlin.ntfs.filesystem', 'XPC!', 'NTFSExtension')):
        bundle = app / subpath
        info = {'CFBundleIdentifier': identifier, 'CFBundlePackageType': package_type,
                'CFBundleExecutable': executable, 'CFBundleVersion': '1', 'CFBundleShortVersionString': '0.1.0'}
        if subpath:
            info['EXAppExtensionAttributes'] = {'EXExtensionPointIdentifier': 'com.apple.fskit.fsmodule'}
        write_file(bundle / 'Contents/Info.plist', plistlib.dumps(info))
        write_file(bundle / 'Contents/MacOS' / executable, universal(**macho_options), 0o755)
    write_file(app / 'Contents/Resources/localized/hello.txt', b'original independent resource\n', 0o440)
    (app / 'Contents/Resources/link').symlink_to('localized/hello.txt')
    return app


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.app = fixture(self.root)
        self.output = self.root / 'result'

    def package(self):
        return p.package(self.app, self.output, SOURCE, LICENSE, PROVENANCE)

    def refuse(self, message=None):
        with self.assertRaises((ValueError, OSError)) as caught:
            self.package()
        if message:
            self.assertIn(message, str(caught.exception))
        self.assertFalse((self.output / 'unsigned-fskit.tar').exists())
        if self.output.exists():
            self.assertEqual(json.loads((self.output / 'report.json').read_text())['status'], 'failed')

    def test_roundtrip_preserves_resource_modes_symlinks_contents_and_inventory(self):
        before = p.inventory(self.app)
        result = self.package()
        self.assertEqual(result['status'], 'pass')
        self.assertFalse(result['distribution_ready'])
        self.assertFalse(result['native_installation_qualified'])
        self.assertTrue(result['same_input_packaging_reproducible'])
        with tarfile.open(self.output / result['package']) as archive:
            members = {item.name: item for item in archive.getmembers()}
            self.assertEqual(members['Machlin NTFS.app/Contents/Resources/localized/hello.txt'].mode, 0o440)
            self.assertEqual(members['Machlin NTFS.app/Contents/Resources/link'].linkname, 'localized/hello.txt')
            self.assertTrue(members['Machlin NTFS.app/Contents/Resources/link'].issym())
            self.assertEqual(archive.extractfile('LICENSE').read(), LICENSE)
            self.assertEqual(archive.extractfile('PROVENANCE.md').read(), PROVENANCE)
            self.assertIn(b'not an installer', archive.extractfile('NOTICE.txt').read())
            manifest = json.load(archive.extractfile('manifest.json'))
            self.assertEqual(manifest['payload'], p.public_inventory(before))
            self.assertTrue(all(item.mtime == SOURCE['epoch'] for item in members.values()))
            destination = self.root / 'extracted'
            destination.mkdir()
            archive.extractall(destination, filter='data')
        self.assertEqual((destination / 'Machlin NTFS.app/Contents/Resources/link').read_bytes(), b'original independent resource\n')
        self.assertEqual(p.inventory(self.app), before)

    def test_relocated_identical_inputs_ignore_mtime_and_produce_identical_archives(self):
        one = self.package()
        relocated = self.root / 'relocated'
        relocated.mkdir()
        self.app = fixture(relocated)
        for path in self.app.rglob('*'):
            os.utime(path, (700, 800), follow_symlinks=False)
        self.output = relocated / 'result'
        two = self.package()
        self.assertEqual(one['sha256'], two['sha256'])

    def test_existing_directory_file_and_dangling_output_preserved(self):
        self.output.mkdir()
        (self.output / 'sentinel').write_text('caller content')
        with self.assertRaises(FileExistsError):
            self.package()
        self.assertEqual(list(self.output.iterdir()), [self.output / 'sentinel'])
        self.output = self.root / 'file'
        self.output.write_text('caller file')
        with self.assertRaises(FileExistsError):
            self.package()
        self.assertEqual(self.output.read_text(), 'caller file')
        self.output = self.root / 'link'
        self.output.symlink_to(self.root / 'missing')
        with self.assertRaises(FileExistsError):
            self.package()
        self.assertTrue(self.output.is_symlink())
        self.assertFalse((self.root / 'missing').exists())

    def test_missing_info_executable_and_extension_refused(self):
        (self.app / 'Contents/Info.plist').unlink()
        self.refuse('Info.plist')

    def test_missing_executable_refused(self):
        (self.app / 'Contents/MacOS/Machlin NTFS').unlink()
        self.refuse('Missing executable')

    def test_mismatched_version_refused(self):
        path = self.app / 'Contents/Extensions/NTFSExtension.appex/Contents/Info.plist'
        info = plistlib.loads(path.read_bytes())
        info['CFBundleVersion'] = '2'
        path.write_bytes(plistlib.dumps(info))
        self.refuse('version mismatch')

    def test_bundle_identity_and_fskit_point_validated(self):
        path = self.app / 'Contents/Extensions/NTFSExtension.appex/Contents/Info.plist'
        info = plistlib.loads(path.read_bytes())
        info['EXAppExtensionAttributes']['EXExtensionPointIdentifier'] = 'some.other.extension'
        path.write_bytes(plistlib.dumps(info))
        self.refuse('FSKit extension point')

    def test_executable_mode_refused(self):
        (self.app / 'Contents/MacOS/Machlin NTFS').chmod(0o644)
        self.refuse('executable mode')

    def test_escaping_symlink_refused(self):
        (self.app / 'Contents/Resources/escape').symlink_to('../../../outside')
        (self.root / 'outside').write_text('outside')
        self.refuse('escapes')

    def test_absolute_symlink_refused(self):
        (self.app / 'Contents/Resources/absolute').symlink_to(self.app / 'Contents/Info.plist')
        self.refuse('Unsafe symlink')

    def test_cyclic_symlink_refused(self):
        (self.app / 'Contents/Resources/cycle').symlink_to('cycle')
        self.refuse('cyclic')

    def test_dangling_symlink_refused(self):
        (self.app / 'Contents/Resources/dangling').symlink_to('absent')
        self.refuse('Dangling')

    def test_hardlink_refused(self):
        os.link(self.app / 'Contents/Info.plist', self.app / 'Contents/duplicate')
        self.refuse('Hard-linked')

    def test_fifo_refused_without_blocking(self):
        os.mkfifo(self.app / 'Contents/Resources/fifo')
        self.refuse('Special file')

    def test_special_and_writable_modes_refused(self):
        (self.app / 'Contents/MacOS/Machlin NTFS').chmod(0o4755)
        self.refuse('Special permission')

    def test_case_collision_refused(self):
        (self.app / 'Contents/Resources/Localized').mkdir()
        self.refuse('Case-folding')

    def test_foreign_executable_payload_refused_even_without_exec_mode(self):
        write_file(self.app / 'Contents/Resources/renamed.dat', b'\x7fELFrest')
        self.refuse('Unexpected code')

    def test_profiles_and_codesign_directories_refused(self):
        write_file(self.app / 'Contents/embedded.provisionprofile', b'profile')
        self.refuse('signed/development')

    def test_ad_hoc_does_not_claim_distribution_signature(self):
        write_file(self.app / 'Contents/MacOS/Machlin NTFS', universal(adhoc=True), 0o755)
        result = self.package()
        self.assertEqual(result['bundles'][0]['slices'][0]['signature'], 'ad-hoc; no distribution identity')

    def test_signed_macho_refused(self):
        write_file(self.app / 'Contents/MacOS/Machlin NTFS', universal(signed=True), 0o755)
        self.refuse('Non-ad-hoc')

    def test_non_system_dynamic_dependency_refused(self):
        write_file(self.app / 'Contents/MacOS/Machlin NTFS', universal(dependencies=('/usr/local/lib/libntfs-3g.dylib',)), 0o755)
        self.refuse('Non-system')

    def test_apple_system_dependencies_recorded(self):
        dependency = '/System/Library/Frameworks/FSKit.framework/Versions/A/FSKit'
        write_file(self.app / 'Contents/MacOS/Machlin NTFS', universal(dependencies=(dependency,)), 0o755)
        result = self.package()
        self.assertEqual(result['bundles'][0]['slices'][0]['dependencies'], [dependency])

    def test_thin_or_missing_architecture_refused(self):
        write_file(self.app / 'Contents/MacOS/Machlin NTFS', universal(cpus=(0x0100000c,)), 0o755)
        self.refuse('exactly arm64')

    def test_truncated_and_overlapping_macho_rejected(self):
        with self.assertRaises(ValueError):
            p.inspect_macho(universal()[:-1])
        data = bytearray(universal())
        struct.pack_into('>I', data, 36, 48)
        with self.assertRaisesRegex(ValueError, 'Overlapping'):
            p.inspect_macho(data)

    def test_load_command_and_signature_bounds(self):
        data = bytearray(universal(dependencies=('/usr/lib/libSystem.B.dylib',)))
        first_slice = 48
        struct.pack_into('<I', data, first_slice + 32 + 4, 0)
        with self.assertRaisesRegex(ValueError, 'size'):
            p.inspect_macho(data)
        data = bytearray(universal(adhoc=True))
        struct.pack_into('<I', data, first_slice + 32 + 8, len(data))
        with self.assertRaisesRegex(ValueError, 'signature data range'):
            p.inspect_macho(data)

    def test_total_file_and_entry_budgets_refused(self):
        with patch.object(p, 'MAX_TOTAL_BYTES', 8):
            self.refuse('Total byte')

    def test_file_budget_refused(self):
        with patch.object(p, 'MAX_FILE_BYTES', 8):
            self.refuse('File byte')

    def test_entry_budget_refused(self):
        with patch.object(p, 'MAX_ENTRIES', 3):
            self.refuse('Entry budget')

    def test_failure_during_archive_retains_diagnostics_and_no_completed_product(self):
        with patch.object(p, 'archive_product', side_effect=OSError('injected disk full')):
            self.refuse('disk full')
        self.assertEqual((self.app / 'Contents/Resources/link').read_bytes(), b'original independent resource\n')

    def test_input_change_during_archive_refused(self):
        original = p.archive_product
        def changed(*args):
            original(*args)
            (self.app / 'Contents/Resources/localized/hello.txt').chmod(0o444)
        with patch.object(p, 'archive_product', side_effect=changed):
            self.refuse('changed')

    def test_source_changed_before_publication_records_failure(self):
        with self.assertRaisesRegex(ValueError, 'Source checkout changed'):
            p.package(self.app, self.output, SOURCE, LICENSE, PROVENANCE,
                      revalidate_source=lambda: dict(SOURCE, revision='f' * 40))
        self.assertFalse((self.output / 'unsigned-fskit.tar').exists())
        self.assertEqual(json.loads((self.output / 'report.json').read_text())['status'], 'failed')

    def test_unreviewed_bundle_content_refused(self):
        write_file(self.app / 'Contents/unreviewed.tar', b'not approved')
        self.refuse('explicit product layout')

    def test_resource_symlink_to_executable_refused(self):
        (self.app / 'Contents/Resources/alias').symlink_to('../MacOS/Machlin NTFS')
        self.refuse('Resources directory')

    def test_metadata_symlink_refused(self):
        info = self.app / 'Contents/Info.plist'
        data = info.read_bytes()
        info.unlink()
        write_file(self.app / 'Contents/Resources/info', data)
        info.symlink_to('Resources/info')
        self.refuse('real bundle Info.plist')

    def test_corrupt_archive_verification_refused(self):
        self.package()
        archive = self.output / 'unsigned-fskit.tar'
        with self.assertRaises(ValueError):
            p.verify_archive(archive, [], {}, SOURCE['epoch'])

    def test_unsafe_path_names_rejected(self):
        for name in ('/absolute', '../up', 'double//slash', 'dot/./path', 'line\nfeed', 'windows\\path', 'e\u0301'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                p.safe_name(name)

    @unittest.skipUnless(hasattr(os, 'setxattr'), 'Host lacks xattrs')
    def test_unretained_extended_attribute_refused(self):
        path = self.app / 'Contents/Info.plist'
        os.setxattr(path, 'user.unexpected', b'valuable data')
        self.refuse('extended attributes')


if __name__ == '__main__':
    unittest.main()
