#!/usr/bin/env python3
"""Compile/run FSKit adapter component tests without installing an extension."""
from pathlib import Path
from environment import tool_environment
import subprocess

root = Path(__file__).resolve().parents[1]
output = root / 'artifacts/fskit-component'
output.mkdir(parents=True, exist_ok=True)
env = tool_environment()
for key in ('CC', 'CXX', 'CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS', 'SDKROOT'):
    env.pop(key, None)
clang = subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip()
sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
adapter = root / 'adapters/fskit'
executable = output / 'ntfs-fskit-test'
command = [clang, '-isysroot', sdk, '-mmacosx-version-min=26.5', '-fobjc-arc', '-fblocks', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra', '-Werror', '-Wdeclaration-after-statement', '-Wno-deprecated-declarations', '-I', str(root / 'include'), '-I', str(adapter), '-framework', 'Foundation', '-framework', 'FSKit', str(root / 'tests/fskit.m')]
command += [str(adapter / name) for name in ('NTFSResource.m', 'NTFSVolume.m', 'NTFSLegacyVolume.m', 'NTFSModernVolume.m')]
command += [str(root / '.build/libntfs.a'), '-o', str(executable)]
subprocess.run(command, cwd=root, env=env, check=True)
subprocess.run([str(executable), str(root / '.build/fixtures/standard.img')], cwd=root, env=env, check=True)
