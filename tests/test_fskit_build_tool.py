"""FSKit build CLI/evidence contracts using simulated tools, never native acceptance."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent / 'scripts'
REPOSITORY = next(parent for parent in HERE.parents if (parent / 'AGENTS.md').is_file())
sys.path.insert(0, str(REPOSITORY / 'scripts'))
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(HERE))
import build_fskit as build
import package_unsigned as package
from test_unsigned_package import fixture, SOURCE, LICENSE, PROVENANCE


def build_report(app):
    return {'schema': 1, 'status': 'pass', 'configuration': 'Release', 'signing_mode': 'unsigned-requested',
            'source': dict(SOURCE, role='build-source'), 'source_archive_sha256': 'a' * 64,
            'app_path': str(app),
            'app_payload': package.public_inventory(package.inventory(app)),
            'toolchain': {key: 'synthetic-fixture' for key in
                          ('xcode', 'sdk_path', 'sdk_version', 'xcodegen', 'clang', 'clang_version')}}


class BuildArgumentTests(unittest.TestCase):
    def test_existing_arguments_and_unsigned_default(self):
        args = build.arguments(['--configuration', 'Release', '--build-number', '42', '--clean'])
        command = build.xcode_command(args, Path('/project'), '/selected/clang')
        self.assertIn('CODE_SIGNING_ALLOWED=NO', command)
        self.assertIn('CURRENT_PROJECT_VERSION=42', command)
        self.assertIn('CC=/selected/clang', command)
        self.assertEqual(command[-2:], ['clean', 'build'])
        self.assertNotIn('-allowProvisioningUpdates', command)

    def test_explicit_signing_and_profile_arguments_retained(self):
        args = build.arguments(['--team', 'FIXTURETEAM', '--provision', '--app-profile', 'app',
                                '--extension-profile', 'extension'])
        command = build.xcode_command(args, Path('/project'), '/selected/clang')
        self.assertIn('CODE_SIGN_STYLE=Manual', command)
        self.assertIn('DEVELOPMENT_TEAM=FIXTURETEAM', command)
        self.assertIn('-allowProvisioningUpdates', command)
        self.assertNotIn('CODE_SIGNING_ALLOWED=NO', command)

    def test_invalid_combinations_and_bounds_refuse(self):
        for arguments in (['--provision'], ['--app-profile', 'app'], ['--build-number', '0'],
                          ['--timeout', '0'], ['--timeout', '1801']):
            with self.subTest(arguments=arguments), patch('sys.stderr', new=io.StringIO()), self.assertRaises(SystemExit):
                build.arguments(arguments)

    def test_profile_selection_modifies_only_owned_generated_spec(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = ('        PRODUCT_BUNDLE_IDENTIFIER: org.machlin.ntfs\n'
                      '        PRODUCT_BUNDLE_IDENTIFIER: org.machlin.ntfs.filesystem\n')
            (directory / 'project.yml').write_text(source)
            args = build.arguments(['--team', 'FIXTURETEAM', '--app-profile', 'app "profile"',
                                    '--extension-profile', 'extension'])
            selected = build.selected_spec(args, directory)
            self.assertEqual((directory / 'project.yml').read_text(), source)
            self.assertIn('app \\"profile\\"', selected.read_text())
            with self.assertRaises(FileExistsError):
                build.selected_spec(args, directory)

    def test_wrong_platform_and_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'caller'
            output.mkdir()
            sentinel = output / 'sentinel'
            sentinel.write_text('caller bytes')
            args = build.arguments(['--derived-data', str(output)])
            with patch.object(build.sys, 'platform', 'linux'), self.assertRaisesRegex(ValueError, 'actual macOS'):
                build.build(args)
            with patch.object(build.sys, 'platform', 'darwin'), self.assertRaises(FileExistsError):
                build.build(args)
            self.assertEqual(sentinel.read_text(), 'caller bytes')
            self.assertEqual(list(output.iterdir()), [sentinel])

    def test_build_failure_is_retained_and_does_not_replace_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'new'
            args = build.arguments(['--derived-data', str(output)])
            with patch.object(build.sys, 'platform', 'darwin'), \
                    patch.object(build, 'committed_source', side_effect=ValueError('dirty source')):
                with self.assertRaisesRegex(ValueError, 'dirty source'):
                    build.build(args)
            report = json.loads((output / 'build-report.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertFalse(report['native_installation_qualified'])
            self.assertIn('dirty source', report['error'])


class BuildExecutionContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'new-output'
        self.sdk = self.root / 'sdk'
        self.sdk.mkdir()
        self.clang = self.root / 'clang'
        self.clang.write_text('synthetic tool path only')
        self.calls = []
        self.fail_build = False
        self.args = build.arguments(['--configuration', 'Release', '--derived-data', str(self.output)])

    def fake_command(self, argv, output, name, environment, **kwargs):
        self.calls.append((argv, name, environment, kwargs))
        if name == 'source-archive':
            buffer = io.BytesIO()
            source = b'name: independent synthetic spec\n'
            with tarfile.open(fileobj=buffer, mode='w') as archive:
                entry = tarfile.TarInfo('adapters/fskit/project.yml')
                entry.size = len(source)
                archive.addfile(entry, io.BytesIO(source))
            return buffer.getvalue()
        if name == 'sdk-path':
            return str(self.sdk)
        if name == 'clang-path':
            return str(self.clang)
        if name == 'xcode-build':
            if self.fail_build:
                raise RuntimeError('injected Xcode failure')
            products = output / 'Build/Products/Release'
            products.mkdir(parents=True)
            fixture(products)
            for bundle in ('Machlin NTFS.app.dSYM', 'NTFSExtension.appex.dSYM'):
                directory = products / bundle
                directory.mkdir()
                (directory / 'synthetic-debug-evidence').write_text('Not native debug data')
        if name.endswith('-uuids'):
            return ('UUID: 11111111-2222-3333-4444-555555555555 (arm64) synthetic\n'
                    'UUID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee (x86_64) synthetic\n')
        return 'synthetic-tool-evidence'

    def execute(self, source=None):
        source = source or (lambda root: dict(SOURCE))
        with patch.object(build.sys, 'platform', 'darwin'), \
                patch.object(build, 'committed_source', side_effect=source), \
                patch.object(build, 'command', side_effect=self.fake_command), \
                patch.dict(os.environ, {'TEST_BUILD_SECRET': 'must not enter child environment'}):
            return build.build(self.args, root=self.root)

    def test_successful_simulated_orchestration_binds_actual_emitted_fixture(self):
        result = self.execute()
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['source']['role'], 'build-source')
        self.assertEqual(result['app_payload'], package.public_inventory(
            package.inventory(Path(result['app_path']))))
        self.assertEqual(json.loads((self.output / 'build-report.json').read_text()), result)
        self.assertTrue((self.output / 'SourceSnapshot/adapters/fskit/project.yml').is_file())
        self.assertTrue(all('TEST_BUILD_SECRET' not in environment and
                            kwargs['timeout'] > 0 and kwargs['output_limit'] > 0
                            for _, _, environment, kwargs in self.calls))
        command = next(argv for argv, name, _, _ in self.calls if name == 'xcode-build')
        self.assertIn('ARCHS=arm64 x86_64', command)
        self.assertIn('ONLY_ACTIVE_ARCH=NO', command)
        self.assertIn('CODE_SIGNING_ALLOWED=NO', command)
        self.assertIn(str(self.output / 'SourceSnapshot/adapters/fskit/NTFSFSKit.xcodeproj'), command)
        self.assertFalse((self.root / 'adapters').exists())
        self.assertEqual(len(result['debug_symbols']), 2)
        self.assertTrue(all(set(item['uuids']) == {'arm64', 'x86_64'} and item['payload']
                            for item in result['debug_symbols']))

    def test_mismatched_or_incomplete_debug_symbols_refuse_build_success(self):
        original = self.fake_command
        for corrupt in ('UUID: 00000000-0000-0000-0000-000000000000 (arm64) synthetic\n',
                        'UUID: 00000000-0000-0000-0000-000000000000 (arm64) synthetic\n'
                        'UUID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee (x86_64) synthetic\n',
                        'not UUID evidence\n',
                        'UUID: 11111111-2222-3333-4444-555555555555 (arm64) synthetic\n' * 2):
            with self.subTest(corrupt=corrupt):
                self.output = self.root / ('bad-debug-' + str(len(self.calls)))
                self.args.derived_data = self.output
                def command(*args, **kwargs):
                    return corrupt if args[2] == 'app-debug-uuids' else original(*args, **kwargs)
                with patch.object(self, 'fake_command', side_effect=command), self.assertRaises(ValueError):
                    self.execute()
                self.assertEqual(json.loads((self.output / 'build-report.json').read_text())['status'], 'failed')

    def test_simulated_xcode_failure_retains_failed_report(self):
        self.fail_build = True
        with self.assertRaisesRegex(RuntimeError, 'injected Xcode failure'):
            self.execute()
        result = json.loads((self.output / 'build-report.json').read_text())
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['native_installation_qualified'])
        self.assertTrue((self.output / 'SourceSnapshot').is_dir())

    def test_source_changed_during_simulated_build_refuses_success(self):
        values = iter([dict(SOURCE), dict(SOURCE, revision='f' * 40)])
        with self.assertRaisesRegex(ValueError, 'Source checkout changed'):
            self.execute(lambda root: next(values))
        result = json.loads((self.output / 'build-report.json').read_text())
        self.assertEqual(result['status'], 'failed')
        self.assertIn('Source checkout changed', result['error'])


class BuildBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.app = fixture(self.root)
        self.report = build_report(self.app)

    def package(self, report):
        return package.package(self.app, self.root / 'package', SOURCE, LICENSE, PROVENANCE,
                               build_report_bytes=package.json_bytes(report))

    def test_bound_report_is_retained_and_verified(self):
        report = self.package(self.report)
        self.assertIn('exact app inventory', report['build_source_binding'])
        self.assertEqual(len(report['build_report_sha256']), 64)
        with tarfile.open(self.root / 'package/unsigned-fskit.tar') as archive:
            self.assertEqual(json.load(archive.extractfile('build-report.json')), self.report)
            manifest = json.load(archive.extractfile('manifest.json'))
            self.assertEqual(manifest['build_report_sha256'], report['build_report_sha256'])

    def test_failed_debug_signed_wrong_source_and_changed_payload_refused(self):
        changes = ({'status': 'failed'}, {'configuration': 'Debug'}, {'signing_mode': 'development-requested'},
                   {'source': dict(SOURCE, role='build-source', tree='2' * 40)},
                   {'app_payload': []}, {'toolchain': {}}, {'source_archive_sha256': ''})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                package.verified_build(dict(self.report, **change), SOURCE, package.inventory(self.app))

    def compare(self, other, other_report):
        return package.package(self.app, self.root / 'comparison', SOURCE, LICENSE, PROVENANCE,
                               build_report_bytes=package.json_bytes(self.report), comparison_app=other,
                               comparison_report_bytes=package.json_bytes(other_report))

    def test_two_distinct_bound_builds_compare_complete_inventory(self):
        other_root = self.root / 'second'
        other_root.mkdir()
        other = fixture(other_root)
        result = self.compare(other, build_report(other))
        self.assertEqual(result['app_build_reproducibility']['status'], 'pass')
        self.assertEqual(result['app_build_reproducibility']['different_paths'], [])
        with tarfile.open(self.root / 'comparison/unsigned-fskit.tar') as archive:
            self.assertEqual(json.load(archive.extractfile('comparison-build-report.json')), build_report(other))

    def test_different_independent_app_keeps_exact_difference_and_no_complete_archive(self):
        other_root = self.root / 'second'
        other_root.mkdir()
        other = fixture(other_root)
        resource = other / 'Contents/Resources/localized/hello.txt'
        resource.chmod(0o640)
        with self.assertRaisesRegex(ValueError, 'payloads differ'):
            self.compare(other, build_report(other))
        result = json.loads((self.root / 'comparison/report.json').read_text())
        self.assertEqual(result['app_build_reproducibility']['different_paths'],
                         ['Machlin NTFS.app/Contents/Resources/localized/hello.txt'])
        self.assertFalse((self.root / 'comparison/unsigned-fskit.tar').exists())

    def test_repeated_same_app_is_not_independent_build_reproducibility(self):
        with self.assertRaisesRegex(ValueError, 'distinct build outputs'):
            self.compare(self.app, self.report)

    def test_mismatched_toolchain_is_not_app_reproducibility(self):
        other_root = self.root / 'second'
        other_root.mkdir()
        other = fixture(other_root)
        report = build_report(other)
        report['toolchain']['sdk_version'] = 'different-sdk'
        with self.assertRaisesRegex(ValueError, 'same toolchain'):
            self.compare(other, report)

    def test_changed_app_bytes_do_not_inherit_build_verdict(self):
        resource = self.app / 'Contents/Resources/localized/hello.txt'
        resource.chmod(0o644)
        resource.write_text('different content')
        resource.chmod(0o440)
        with self.assertRaisesRegex(ValueError, 'no longer matches'):
            self.package(self.report)
        self.assertFalse((self.root / 'package/unsigned-fskit.tar').exists())
        self.assertEqual(json.loads((self.root / 'package/report.json').read_text())['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
