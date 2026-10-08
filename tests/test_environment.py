"""Ensure ambient credentials cannot enter Meson reports through our launchers."""
from pathlib import Path
import os
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from environment import selected_toolchain, tool_environment
from build import verify_compiler
import build as builder

class EnvironmentTests(unittest.TestCase):
    def test_allowlist(self):
        with patch.dict(os.environ, {'PATH': '/usr/bin', 'HOME': '/tmp/test-user',
                                     'API_KEY': 'test-value', 'AWS_SECRET_ACCESS_KEY': 'test-value',
                                     'UNFAMILIAR_CREDENTIAL': 'test-value', 'CC': 'untrusted-compiler'}, clear=True):
            clean = tool_environment()
        self.assertEqual(clean['PATH'], '/usr/bin')
        self.assertEqual(clean['HOME'], '/tmp/test-user')
        self.assertNotIn('API_KEY', clean)
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', clean)
        self.assertNotIn('UNFAMILIAR_CREDENTIAL', clean)
        self.assertNotIn('CC', clean)

    def test_explicit_compiler_survives_isolation(self):
        with patch.dict(os.environ, {'PATH': '/usr/bin', 'CC': 'untrusted-compiler',
                                     'CFLAGS': '-DNDEBUG', 'SDKROOT': '/ambient-sdk',
                                     'API_KEY': 'synthetic-secret'}, clear=True), \
                patch('environment.sys.platform', 'linux'), \
                patch('environment.shutil.which', return_value='/explicit/gcc') as which:
            clean = selected_toolchain('gcc')
        which.assert_called_once_with('gcc', path='/usr/bin')
        self.assertEqual(clean['CC'], '/explicit/gcc')
        self.assertNotIn('API_KEY', clean)
        self.assertNotIn('CFLAGS', clean)
        self.assertNotIn('SDKROOT', clean)

    def test_default_compiler_does_not_use_ambient_cc(self):
        with patch.dict(os.environ, {'PATH': '/usr/bin', 'CC': 'untrusted'}, clear=True), \
                patch('environment.sys.platform', 'linux'), \
                patch('environment.shutil.which', return_value='/explicit/cc') as which:
            self.assertEqual(selected_toolchain()['CC'], '/explicit/cc')
        which.assert_called_once_with('cc', path='/usr/bin')

    def test_missing_compiler_is_an_error(self):
        with patch('environment.sys.platform', 'linux'), \
                patch('environment.shutil.which', return_value=None):
            with self.assertRaisesRegex(ValueError, 'not found'):
                selected_toolchain('not-a-compiler')

    def test_darwin_override_keeps_selected_sdk(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch('environment.sys.platform', 'darwin'), \
                patch('environment.shutil.which', return_value='/explicit/clang'), \
                patch('environment.subprocess.check_output', return_value=directory + '\n') as query:
            clean = selected_toolchain('/explicit/clang')
            self.assertEqual(clean['SDKROOT'], directory)
            self.assertEqual(clean['CC'], '/explicit/clang')
            query.assert_called_once()
            self.assertEqual(query.call_args.args[0], ['xcrun', '--show-sdk-path'])
            self.assertNotIn('CC', query.call_args.kwargs['env'])
            self.assertGreater(query.call_args.kwargs['timeout'], 0)

    def test_darwin_default_queries_xcode(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch('environment.sys.platform', 'darwin'), \
                patch('environment.shutil.which', return_value='/selected/clang'), \
                patch('environment.subprocess.check_output', side_effect=['/selected/clang\n', directory + '\n']) as query:
            self.assertEqual(selected_toolchain()['CC'], '/selected/clang')
            self.assertEqual(query.call_args_list[0].args[0], ['xcrun', '--find', 'clang'])

    def test_cached_compiler_must_match(self):
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            inventory = build / 'meson-info/intro-compilers.json'
            inventory.parent.mkdir()
            inventory.write_text(json.dumps({'host': {'c': {'exelist': ['/compiler/gcc']}}}))
            verify_compiler(build, '/compiler/gcc')
            with self.assertRaisesRegex(ValueError, 'another compiler'):
                verify_compiler(build, '/compiler/clang')
            inventory.write_text(json.dumps({'host': {'c': {'exelist': ['ccache', '/compiler/gcc']}}}))
            with self.assertRaisesRegex(ValueError, 'another compiler'):
                verify_compiler(build, '/compiler/gcc')

    def test_reconfigure_reasserts_requested_sanitizers_and_assertions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'build.ninja').touch()
            inventory = root / 'meson-info/intro-compilers.json'
            inventory.parent.mkdir()
            inventory.write_text(json.dumps({'host': {'c': {'exelist': ['/compiler/gcc']}}}))
            for release in (False, True):
                argv = ['build.py', directory, '--compiler', 'gcc', *(['--release'] if release else [])]
                with self.subTest(release=release), patch.object(sys, 'argv', argv), \
                        patch.object(builder, 'selected_toolchain', return_value={'CC': '/compiler/gcc'}), \
                        patch.object(builder.subprocess, 'run') as run:
                    builder.main()
                    setup = run.call_args_list[0].args[0]
                    self.assertIn('--reconfigure', setup)
                    self.assertIn('-Db_ndebug=false', setup)
                    self.assertIn('-Db_sanitize=' + ('none' if release else 'address,undefined'), setup)
                    self.assertEqual(len(run.call_args_list), 2)

    def test_cached_mismatch_stops_before_any_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'build.ninja').touch()
            inventory = root / 'meson-info/intro-compilers.json'
            inventory.parent.mkdir()
            inventory.write_text(json.dumps({'host': {'c': {'exelist': ['/compiler/clang']}}}))
            with patch.object(sys, 'argv', ['build.py', directory, '--compiler', 'gcc']), \
                    patch.object(builder, 'selected_toolchain', return_value={'CC': '/compiler/gcc'}), \
                    patch.object(builder.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'another compiler'):
                    builder.main()
                run.assert_not_called()

if __name__ == '__main__':
    unittest.main()
