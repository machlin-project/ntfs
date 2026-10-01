#!/usr/bin/env python3
"""Build the FSKit container app; installation is a separate VM operation."""
from pathlib import Path
import argparse
from environment import tool_environment
import subprocess

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--configuration', choices=('Debug', 'Release'), default='Debug')
parser.add_argument('--team', help='Explicit personal development team; unsigned when omitted')
parser.add_argument('--provision', action='store_true', help='Allow fetching profiles for the explicit team')
args = parser.parse_args()
if args.provision and not args.team:
    parser.error('--provision requires --team')
env = tool_environment()
for key in ('CC', 'CXX', 'CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS', 'SDKROOT'):
    env.pop(key, None)
project = root / 'adapters/fskit'
subprocess.run(['xcodegen', 'generate', '--spec', str(project / 'project.yml'), '--project', str(project)], cwd=root, env=env, check=True)
clang = subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip()
command = ['xcodebuild', '-project', str(project / 'NTFSFSKit.xcodeproj'), '-scheme', 'NTFSApp', '-configuration', args.configuration, '-sdk', 'macosx', '-destination', 'generic/platform=macOS', '-derivedDataPath', str(root / 'artifacts/fskit/DerivedData'), '-jobs', '4', 'CLANG_ENABLE_EXPLICIT_MODULES=NO', f'CC={clang}']
if args.team:
    command += [f'DEVELOPMENT_TEAM={args.team}', 'CODE_SIGN_STYLE=Automatic', 'CODE_SIGN_IDENTITY=Apple Development']
    if args.provision:
        command += ['-allowProvisioningUpdates']
else:
    command += ['CODE_SIGNING_ALLOWED=NO']
subprocess.run(command + ['build'], cwd=root, env=env, check=True)
