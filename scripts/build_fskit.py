#!/usr/bin/env python3
"""Build the FSKit container app; installation is a separate VM operation."""
from pathlib import Path
import argparse
import json
from environment import tool_environment
import subprocess

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--configuration', choices=('Debug', 'Release'), default='Debug')
parser.add_argument('--team', help='Explicit personal development team; unsigned when omitted')
parser.add_argument('--provision', action='store_true', help='Allow fetching profiles for the explicit team')
parser.add_argument('--build-number', type=int, help='Positive app/extension version for installed acceptance')
parser.add_argument('--derived-data', type=Path, default=root / 'artifacts/fskit/DerivedData')
parser.add_argument('--clean', action='store_true', help='Clean before changing signing profiles or configuration')
parser.add_argument('--app-profile', help='Explicit provisioned app profile, paired with --extension-profile')
parser.add_argument('--extension-profile', help='Explicit profile authorizing the FSKit extension and test Mac')
args = parser.parse_args()
if args.provision and not args.team:
    parser.error('--provision requires --team')
if args.build_number is not None and args.build_number <= 0:
    parser.error('--build-number must be positive')
if bool(args.app_profile) != bool(args.extension_profile) or (args.app_profile and not args.team):
    parser.error('explicit profiles require --team and both profile arguments')
env = tool_environment()
for key in ('CC', 'CXX', 'CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS', 'SDKROOT'):
    env.pop(key, None)
project = root / 'adapters/fskit'
spec = project / 'project.yml'
if args.app_profile:
    # Keep profile selection per target and retain the source-relative spec root.
    # The generated spec is ignored; the versioned source remains unchanged.
    text = spec.read_text()
    for identifier, profile in (('org.machlin.ntfs', args.app_profile), ('org.machlin.ntfs.filesystem', args.extension_profile)):
        field = f'        PRODUCT_BUNDLE_IDENTIFIER: {identifier}\n'
        if text.count(field) != 1:
            raise SystemExit('Expected unique app/extension bundle identifier in project.yml')
        text = text.replace(field, field + f'        PROVISIONING_PROFILE_SPECIFIER: {json.dumps(profile)}\n')
    spec = project / '.project-signed.yml'
    spec.write_text(text)
subprocess.run(['xcodegen', 'generate', '--spec', str(spec), '--project', str(project)], cwd=root, env=env, check=True)
clang = subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip()
command = ['xcodebuild', '-project', str(project / 'NTFSFSKit.xcodeproj'), '-scheme', 'NTFSApp', '-configuration', args.configuration, '-sdk', 'macosx', '-destination', 'generic/platform=macOS', '-derivedDataPath', str(args.derived_data.resolve()), '-jobs', '4', 'CLANG_ENABLE_EXPLICIT_MODULES=NO', f'CC={clang}']
if args.build_number is not None:
    command += [f'CURRENT_PROJECT_VERSION={args.build_number}']
if args.team:
    command += [f'DEVELOPMENT_TEAM={args.team}', 'CODE_SIGN_STYLE=' + ('Manual' if args.app_profile else 'Automatic'), 'CODE_SIGN_IDENTITY=Apple Development']
    if args.provision:
        command += ['-allowProvisioningUpdates']
else:
    command += ['CODE_SIGNING_ALLOWED=NO']
subprocess.run(command + (['clean', 'build'] if args.clean else ['build']), cwd=root, env=env, check=True)
