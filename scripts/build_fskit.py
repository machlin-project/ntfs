#!/usr/bin/env python3
"""Build the FSKit container app from a clean committed snapshot, never install it.

Every invocation owns a new DerivedData directory. Bounded Xcode/XcodeGen logs,
source/toolchain identity and the actual app inventory remain there on failure.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from benchmark_toolchain import command
from check_reproducible import export_sources, MAX_SOURCE_ARCHIVE_BYTES
from environment import tool_environment
from package_unsigned import (APP_NAME, committed_source, inventory, json_bytes,
                              public_inventory, require)

ROOT = Path(__file__).resolve().parents[1]
QUERY_SECONDS = 30
DEFAULT_BUILD_SECONDS = 1200
MAX_BUILD_SECONDS = 1800
UUID_LINE = re.compile(r'UUID: ([0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}) '
                       r'\((arm64|x86_64)\) .+')


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configuration', choices=('Debug', 'Release'), default='Debug')
    parser.add_argument('--team', help='Explicit personal development team; unsigned when omitted')
    parser.add_argument('--provision', action='store_true', help='Allow fetching profiles for the explicit team')
    parser.add_argument('--build-number', type=int, help='Positive app/extension version for installed acceptance')
    parser.add_argument('--derived-data', type=Path, default=ROOT / 'artifacts/fskit/DerivedData',
                        help='New owned output directory; existing outputs are refused')
    parser.add_argument('--clean', action='store_true', help='Run Xcode clean before building the fresh snapshot')
    parser.add_argument('--app-profile', help='Explicit provisioned app profile, paired with --extension-profile')
    parser.add_argument('--extension-profile', help='Explicit profile authorizing the FSKit extension and test Mac')
    parser.add_argument('--timeout', type=int, default=DEFAULT_BUILD_SECONDS,
                        help='Xcode build deadline in seconds, at most 1800')
    args = parser.parse_args(argv)
    if args.provision and not args.team:
        parser.error('--provision requires --team')
    if args.build_number is not None and args.build_number <= 0:
        parser.error('--build-number must be positive')
    if bool(args.app_profile) != bool(args.extension_profile) or (args.app_profile and not args.team):
        parser.error('explicit profiles require --team and both profile arguments')
    if not 1 <= args.timeout <= MAX_BUILD_SECONDS:
        parser.error('--timeout must be between 1 and 1800 seconds')
    return args


def xcode_command(args, project, clang):
    argv = ['xcodebuild', '-project', str(project / 'NTFSFSKit.xcodeproj'),
            '-scheme', 'NTFSApp', '-configuration', args.configuration, '-sdk', 'macosx',
            '-destination', 'generic/platform=macOS', '-derivedDataPath', str(args.derived_data),
            '-jobs', '4', 'CLANG_ENABLE_EXPLICIT_MODULES=NO', f'CC={clang}']
    if args.configuration == 'Release':
        argv += ['ARCHS=arm64 x86_64', 'ONLY_ACTIVE_ARCH=NO']
    if args.build_number is not None:
        argv += [f'CURRENT_PROJECT_VERSION={args.build_number}']
    if args.team:
        argv += [f'DEVELOPMENT_TEAM={args.team}',
                 'CODE_SIGN_STYLE=' + ('Manual' if args.app_profile else 'Automatic'),
                 'CODE_SIGN_IDENTITY=Apple Development']
        if args.provision:
            argv += ['-allowProvisioningUpdates']
    else:
        argv += ['CODE_SIGNING_ALLOWED=NO']
    return argv + (['clean', 'build'] if args.clean else ['build'])


def selected_spec(args, project):
    spec = project / 'project.yml'
    if args.app_profile:
        text = spec.read_text()
        for identifier, profile in (('org.machlin.ntfs', args.app_profile),
                                    ('org.machlin.ntfs.filesystem', args.extension_profile)):
            field = f'        PRODUCT_BUNDLE_IDENTIFIER: {identifier}\n'
            require(text.count(field) == 1, 'Expected unique app/extension bundle identifier in project.yml')
            text = text.replace(field, field + f'        PROVISIONING_PROFILE_SPECIFIER: {json.dumps(profile)}\n')
        spec = project / '.project-signed.yml'
        with spec.open('x') as destination:
            destination.write(text)
    return spec


def release_debug_symbols(app, products, run):
    """Bind each separate dSYM to both architectures of the completed executable."""
    def uuids(path, name):
        result = {}
        for line in run(['xcrun', 'dwarfdump', '--uuid', str(path)], name).splitlines():
            match = UUID_LINE.fullmatch(line)
            require(match is not None, 'Unexpected dSYM UUID output')
            value, architecture = match.groups()
            require(architecture not in result, 'Duplicate debug-symbol architecture')
            result[architecture] = value.lower()
        require(set(result) == {'arm64', 'x86_64'}, 'Incomplete universal debug-symbol UUIDs')
        return result

    result = []
    for label, binary, symbols in (
            ('app', app / 'Contents/MacOS/Machlin NTFS', products / 'Machlin NTFS.app.dSYM'),
            ('extension', app / 'Contents/Extensions/NTFSExtension.appex/Contents/MacOS/NTFSExtension',
             products / 'NTFSExtension.appex.dSYM')):
        binary_uuids = uuids(binary, label + '-binary-uuids')
        symbol_uuids = uuids(symbols, label + '-debug-uuids')
        require(binary_uuids == symbol_uuids, 'Executable and separate debug-symbol UUIDs differ')
        result.append({'binary': binary.relative_to(app).as_posix(), 'path': str(symbols),
                       'uuids': binary_uuids, 'payload': public_inventory(inventory(symbols))})
    return result


def build(args, *, root=ROOT):
    require(sys.platform == 'darwin', 'FSKit builds require an actual macOS Xcode/SDK environment')
    args.derived_data = args.derived_data.absolute()
    args.derived_data.mkdir(parents=True, exist_ok=False)
    output = args.derived_data
    report_path = output / 'build-report.json'
    report = {'schema': 1, 'status': 'running', 'configuration': args.configuration,
              'signing_mode': 'development-requested' if args.team else 'unsigned-requested',
              'native_installation_qualified': False, 'distribution_ready': False,
              'scope': 'actual Xcode app build from committed source snapshot; no installation'}
    try:
        report_path.write_bytes(json_bytes(report))
        source = committed_source(root)
        source['role'] = 'build-source'
        report['source'] = source
        environment = tool_environment()
        for key in ('CC', 'CXX', 'CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS', 'SDKROOT'):
            environment.pop(key, None)
        def run(argv, name, *, timeout=QUERY_SECONDS, limit=65536, cwd=root, text=True):
            return command(argv, output, name, environment, timeout=timeout,
                           output_limit=limit, cwd=cwd, text=text)
        archive = run(['git', '-C', str(root), 'archive', '--format=tar', source['revision']],
                      'source-archive', limit=MAX_SOURCE_ARCHIVE_BYTES, text=False)
        report['source_archive_sha256'] = hashlib.sha256(archive).hexdigest()
        snapshot = output / 'SourceSnapshot'
        export_sources(archive, snapshot)
        report['toolchain'] = {
            'xcode': run(['xcodebuild', '-version'], 'xcode-version').strip(),
            'sdk_path': run(['xcrun', '--show-sdk-path'], 'sdk-path').strip(),
            'sdk_version': run(['xcrun', '--show-sdk-version'], 'sdk-version').strip(),
            'xcodegen': run(['xcodegen', '--version'], 'xcodegen-version').strip(),
            'clang': run(['xcrun', '--find', 'clang'], 'clang-path').strip(),
        }
        require(Path(report['toolchain']['sdk_path']).is_dir(), 'Selected SDK directory is absent')
        require(Path(report['toolchain']['clang']).is_file(), 'Selected clang executable is absent')
        report['toolchain']['clang_version'] = run([report['toolchain']['clang'], '--version'], 'clang-version').strip()
        project = snapshot / 'adapters/fskit'
        spec = selected_spec(args, project)
        run(['xcodegen', 'generate', '--spec', str(spec), '--project', str(project)],
            'xcodegen', timeout=120, cwd=snapshot)
        argv = xcode_command(args, project, report['toolchain']['clang'])
        report['command'] = argv
        report_path.write_bytes(json_bytes(report))
        run(argv, 'xcode-build', timeout=args.timeout, limit=32 * 1024 * 1024, cwd=snapshot)
        app = output / 'Build/Products' / args.configuration / APP_NAME
        report['app_path'] = str(app)
        report['app_payload'] = public_inventory(inventory(app))
        if args.configuration == 'Release':
            report['debug_symbols'] = release_debug_symbols(app, app.parent, run)
        after = committed_source(root)
        after['role'] = 'build-source'
        require(after == source, 'Source checkout changed during build')
        report['status'] = 'pass'
        report_path.write_bytes(json_bytes(report))
        return report
    except BaseException as error:
        report.update(status='failed', error=f'{type(error).__name__}: {error}')
        report_path.write_bytes(json_bytes(report))
        raise


def main():
    args = arguments()
    try:
        report = build(args)
    except (ValueError, OSError, RuntimeError) as error:
        raise SystemExit(f'FSKit build failed: {error}') from error
    print(f"PASS: {report['configuration']} app build; {args.derived_data / 'build-report.json'}")


if __name__ == '__main__':
    main()
