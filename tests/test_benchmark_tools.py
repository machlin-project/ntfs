"""Portable flags, compiler-context distinctions and retained benchmark evidence."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import benchmark_toolchain as tools
import benchmark_cpu
import benchmark_core
import check_cpu
from environment import tool_environment


class BenchmarkToolTests(unittest.TestCase):
    def test_linux_flags_do_not_use_xcode(self):
        with patch.object(tools.sys, 'platform', 'linux'):
            self.assertEqual(tools.sdk_flags({'SDKROOT': '/ignored'}), [])
            self.assertIn('-D_POSIX_C_SOURCE=200809L', tools.host_flags())
            self.assertIn('-D_DEFAULT_SOURCE', tools.host_flags())
            self.assertEqual(tools.linker_flags(), ['-Wl,--gc-sections'])
            self.assertIn('-ffunction-sections', tools.section_flags())

    def test_darwin_flags_keep_selected_sdk(self):
        with patch.object(tools.sys, 'platform', 'darwin'):
            self.assertEqual(tools.sdk_flags({'SDKROOT': '/selected-sdk'}),
                             ['-isysroot', '/selected-sdk'])
            self.assertEqual(tools.host_flags(), [])
            self.assertEqual(tools.linker_flags(), ['-Wl,-dead_strip'])

    def test_explicit_compiler_is_forwarded(self):
        with patch.object(tools.sys, 'platform', 'linux'), \
                patch.object(tools.platform, 'machine', return_value='x86_64'), \
                patch.object(tools, 'selected_toolchain', return_value={'CC': '/chosen/gcc'}) as choose:
            self.assertEqual(tools.select('/chosen/gcc'), {'CC': '/chosen/gcc'})
            choose.assert_called_once_with('/chosen/gcc')

    def test_unsupported_host_is_not_a_pass(self):
        with patch.object(tools.sys, 'platform', 'win32'):
            with self.assertRaisesRegex(ValueError, 'macOS and Linux'):
                tools.select()
        with patch.object(tools.sys, 'platform', 'linux'), \
                patch.object(tools, 'selected_toolchain', return_value={}), \
                patch.object(tools.platform, 'machine', return_value='riscv64'):
            with self.assertRaisesRegex(ValueError, 'ARM64 or x86_64'):
                tools.select()

    def test_linux_identity_has_no_sdk_queries(self):
        with patch.object(tools.sys, 'platform', 'linux'), \
                patch.object(tools.platform, 'processor', return_value='test-cpu'), \
                patch.object(tools.platform, 'platform', return_value='test-linux'), \
                patch.object(tools.subprocess, 'check_output', side_effect=['compiler 1\n', 'x86_64-linux\n']) as query:
            value = tools.identity({'CC': '/selected/gcc'})
        self.assertEqual(value['compiler_path'], '/selected/gcc')
        self.assertIsNone(value['sdk_path'])
        self.assertIsNone(value['sdk_version'])
        self.assertEqual(query.call_count, 2)
        self.assertTrue(all(call.kwargs['timeout'] > 0 for call in query.call_args_list))
        self.assertEqual(value['profiles'], tools.PROFILES)

    def test_every_toolchain_change_is_refused(self):
        identity = dict(compiler_path='cc', compiler_version='1', compiler_target='native',
                        sdk_path=None, sdk_version=None, platform='linux', machine='x86_64',
                        host='runner', processor='cpu', profiles=tools.PROFILES)
        tools.matching({'toolchain': identity}, dict(identity))
        for field in identity:
            with self.subTest(field=field), self.assertRaises(ValueError):
                tools.matching({'toolchain': identity}, {**identity, field: 'changed'})
        with self.assertRaises(ValueError):
            tools.matching({}, identity)

    def test_comparison_bounds(self):
        tools.validate_comparison('candidate', 5)
        tools.validate_comparison('candidate', 100)
        for name, repetitions in (('', 9), ('.', 9), ('..', 9), ('a/b', 9),
                                  ('/absolute', 9), ('case', 4), ('case', 101)):
            with self.subTest(name=name, repetitions=repetitions), self.assertRaises(ValueError):
                tools.validate_comparison(name, repetitions)

    def test_retained_binary_and_input_integrity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, fixture = root / 'before', root / 'input'
            binary.write_bytes(b'compiled baseline')
            fixture.write_bytes(b'independent expected bytes')
            hashes = tools.retained_hashes(root, (binary, fixture))
            tools.verify_hashes(root, hashes)
            binary.write_bytes(b'replaced executable')
            with self.assertRaisesRegex(ValueError, 'changed'):
                tools.verify_hashes(root, hashes)
            with self.assertRaises(ValueError):
                tools.verify_hashes(root, {})
            outside = root / 'nested'
            outside.mkdir()
            with self.assertRaises(ValueError):
                tools.verify_hashes(outside, {'../before': tools.digest(binary)})

    def test_cpu_build_uses_elf_sections_and_explicit_compiler(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(tools.sys, 'platform', 'linux'), \
                patch.object(benchmark_cpu, 'command') as run:
            root = Path(temporary)
            binary, argv = benchmark_cpu.build(root, root, root / 'harness.c', [], 'before',
                                              '/chosen/clang', {'CC': '/chosen/clang'})
        self.assertEqual(argv[0], '/chosen/clang')
        self.assertIn('-ffunction-sections', argv)
        self.assertIn('-Wl,--gc-sections', argv)
        self.assertIn('-UNDEBUG', argv)
        self.assertNotIn('-isysroot', argv)
        self.assertEqual(binary.name, 'before')
        run.assert_called_once()

    def test_core_build_has_posix_declarations_on_linux(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(tools.sys, 'platform', 'linux'), \
                patch.object(benchmark_core, 'command'):
            root = Path(temporary)
            _, argv = benchmark_core.build(root, root, root / 'harness.c', [], 'before',
                                           '/chosen/gcc', None, {'CC': '/chosen/gcc'})
        self.assertIn('-D_POSIX_C_SOURCE=200809L', argv)
        self.assertIn('-UNDEBUG', argv)
        self.assertNotIn('-isysroot', argv)

    def test_linux_restriction_is_not_kernel_sdk_qualification(self):
        with patch.object(check_cpu.sys, 'platform', 'linux'), \
                patch.object(check_cpu.platform, 'machine', return_value='x86_64'):
            contexts = check_cpu.object_contexts({})
        self.assertEqual([item['name'] for item in contexts], ['userspace', 'general-registers'])
        self.assertNotIn('-mkernel', contexts[1]['flags'])
        self.assertIn('-mgeneral-regs-only', contexts[1]['flags'])
        self.assertTrue(contexts[1]['restricted'])

    def test_darwin_kernel_contexts_remain_separate(self):
        with patch.object(check_cpu.sys, 'platform', 'darwin'):
            contexts = check_cpu.object_contexts({'SDKROOT': '/selected-sdk'})
        self.assertEqual(len(contexts), 4)
        self.assertEqual([(row['name'], row['arch']) for row in contexts[-2:]],
                         [('kernel', 'arm64e'), ('kernel', 'x86_64')])
        self.assertIn('-mkernel', contexts[2]['flags'])
        self.assertIn('/selected-sdk/System/Library/Frameworks/Kernel.framework/Headers', contexts[2]['flags'])

    def test_register_matchers(self):
        for value in ('movdqu %xmm1, (%rax)', 'vpxor %ymm2, %ymm3, %ymm4', 'fld %st(0)'):
            self.assertIsNotNone(check_cpu.FORBIDDEN_X86.search(value))
        self.assertIsNone(check_cpu.FORBIDDEN_X86.search('mov %rdi, %rax'))
        for value in ('ldr q0, [x1]', 'fmov d3, d1', 'orr v15.16b, v0.16b, v1.16b'):
            self.assertIsNotNone(check_cpu.FORBIDDEN_ARM.search(value))
        self.assertIsNone(check_cpu.FORBIDDEN_ARM.search('ldr x0, [x1]'))

    def test_command_retains_success_and_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = tools.command([sys.executable, '-c', "print('checked')"], root,
                                  'good', tool_environment())
            self.assertEqual(value, 'checked\n')
            self.assertEqual(json.loads((root / 'good.command.json').read_text())['status'], 'pass')
            with self.assertRaises(RuntimeError):
                tools.command([sys.executable, '-c', "import sys; print('retained', file=sys.stderr); sys.exit(3)"],
                              root, 'bad', tool_environment())
            self.assertIn('retained', (root / 'bad.stderr').read_text())
            self.assertEqual(json.loads((root / 'bad.command.json').read_text())['status'], 'failed')

    def test_command_deadline_retains_partial_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(TimeoutError):
                tools.command([sys.executable, '-c', "import time; print('started', flush=True); time.sleep(10)"],
                              root, 'timeout', tool_environment(), timeout=0.5)
            self.assertEqual((root / 'timeout.stdout').read_text(), 'started\n')
            self.assertEqual(json.loads((root / 'timeout.command.json').read_text())['status'], 'failed')

    def test_command_working_directory_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            working = root / 'working'
            working.mkdir()
            output = tools.command([sys.executable, '-c', "import os; print(os.getcwd())"],
                                   root, 'cwd', tool_environment(), cwd=working)
            self.assertEqual(output.strip(), str(working))
            before = {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()}
            with self.assertRaises(FileExistsError):
                tools.command([sys.executable, '-c', "print('replacement')"], root,
                              'cwd', tool_environment())
            self.assertEqual(before, {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()})

    def test_command_binary_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = tools.command([sys.executable, '-c', "import sys; sys.stdout.buffer.write(bytes((0, 255, 128)))"],
                                  root, 'binary', tool_environment(), text=False)
            self.assertEqual(value, bytes((0, 255, 128)))

    def test_command_output_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, 'log budget'):
                tools.command([sys.executable, '-c', "print('x' * 4096)"], root,
                              'overflow', tool_environment(), output_limit=32)
            self.assertEqual((root / 'overflow.stdout').stat().st_size, 32)


if __name__ == '__main__':
    unittest.main()
