#!/usr/bin/env python3
"""Validate and retain an unsigned FSKit app as a reproducible transport archive.

This never builds, installs, signs, notarizes, mounts, or executes the app. Linker
ad-hoc CodeDirectories are recorded and allowed, but distribution signatures,
profiles, unexpected executables, and non-system dynamic dependencies are not.
"""
import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import struct
import subprocess
import sys
import tarfile
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
APP_NAME = 'Machlin NTFS.app'
EXTENSION = 'Contents/Extensions/NTFSExtension.appex'
BUNDLES = (('', 'org.machlin.ntfs', 'APPL'),
           (EXTENSION, 'org.machlin.ntfs.filesystem', 'XPC!'))
MAX_ENTRIES = 4096
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_PLIST_BYTES = 1024 * 1024
MAX_LOAD_COMMANDS = 4096
MAX_PATH_BYTES = 1024
IO_BYTES = 1024 * 1024
FAT_MAGIC = b'\xca\xfe\xba\xbe'
MACH_MAGIC = 0xfeedfacf
CPU_TYPES = {0x01000007: 'x86_64', 0x0100000c: 'arm64'}
MH_EXECUTE = 2
LC_CODE_SIGNATURE = 0x1d
DYLIB_COMMANDS = {0xc, 0x20, 0x80000018, 0x8000001f, 0x80000023}
UNSUPPORTED_LINKAGE_COMMANDS = {0x6, 0x7, 0x10, 0x27}
LC_LOAD_DYLINKER = 0xe
CS_SUPERBLOB = 0xfade0cc0
CS_CODEDIRECTORY = 0xfade0c02
CS_ADHOC = 2
CODEDIRECTORY_SLOTS = {0, 0x1000, 0x1001, 0x1002, 0x1003, 0x1004}
NOTICE = '''Machlin NTFS unsigned engineering artifact

Proprietary. LICENSE retains the owner's existing terms; this package grants no
new rights. Only the repository's original app/extension and linked original core
are intended product payloads. Apple system libraries remain external platform
dependencies. No standalone NTFS-3G, QEMU, wimlib, test oracle, or vendor tool may
be bundled. Format research and dependency context are retained in PROVENANCE.md.
This content inventory is not legal distribution clearance or a source audit.

This archive is an unsigned development transport, not an installer or release.
Linker ad-hoc signatures, where present, provide no distribution identity.
Packaging does not qualify app compilation, installed FSKit, permissions, native
mounts, notarization, upgrade/uninstall, power loss, or commercial readiness.
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fingerprint(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)


def safe_name(name):
    require(bool(name) and len(name.encode('utf-8')) <= MAX_PATH_BYTES,
            'Empty or oversized package path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and all(part not in ('', '.', '..') for part in name.split('/')),
            'Unsafe package path')
    require('\\' not in name and all(ord(ch) >= 32 and ord(ch) != 127 for ch in name),
            'Control character or backslash in package path')
    require(unicodedata.normalize('NFC', name) == name, 'Noncanonical Unicode package path')


@contextmanager
def regular_reader(path, expected=None):
    """Do not dereference a replaced leaf or admit a FIFO/device while reading."""
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'Expected a private regular file')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        opened = os.fstat(source.fileno())
        require(fingerprint(before) == fingerprint(opened), 'Input changed while opening')
        if expected is not None:
            require(fingerprint(opened) == expected, 'Input changed after inventory')
        yield source
        require(fingerprint(os.fstat(source.fileno())) == fingerprint(opened) and
                fingerprint(path.lstat()) == fingerprint(opened), 'Input changed while reading')


def read_bytes(path, limit):
    with regular_reader(path) as source:
        data = source.read(limit + 1)
        require(len(data) <= limit, 'Input exceeds its byte budget')
        return data


def digest(path):
    value = hashlib.sha256()
    with regular_reader(path) as source:
        for block in iter(lambda: source.read(IO_BYTES), b''):
            value.update(block)
    return value.hexdigest()


def inventory(app):
    require(not app.is_symlink() and app.is_dir(), 'App must be a real directory')
    result = []
    names = set()
    total = 0
    pending = [app]
    while pending:
        path = pending.pop()
        relative = path.relative_to(app).as_posix()
        name = app.name if relative == '.' else f'{app.name}/{relative}'
        safe_name(name)
        key = name.casefold()
        require(key not in names, 'Case-folding path collision')
        names.add(key)
        value = path.lstat()
        mode = stat.S_IMODE(value.st_mode)
        require(not mode & 0o7000, 'Special permission bits are forbidden')
        entry = {'path': name, 'mode': mode}
        if stat.S_ISLNK(value.st_mode):
            target = os.readlink(path)
            require(target and not os.path.isabs(target) and '\\' not in target and
                    len(target.encode()) <= MAX_PATH_BYTES and
                    all(ord(ch) >= 32 and ord(ch) != 127 for ch in target), 'Unsafe symlink target')
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise ValueError('Dangling or cyclic symlink') from error
            require(resolved.is_relative_to(app.resolve()), 'Symlink escapes app')
            entry.update(type='symlink', target=target)
        elif stat.S_ISDIR(value.st_mode):
            require(not mode & 0o022, 'Group/world-writable directory')
            entry.update(type='directory')
            children = []
            for child in path.iterdir():
                children.append(child)
                require(len(names) + len(pending) + len(children) <= MAX_ENTRIES, 'Entry budget exceeded')
            pending.extend(sorted(children, reverse=True))
        elif stat.S_ISREG(value.st_mode):
            require(value.st_nlink == 1, 'Hard-linked payload is forbidden')
            require(not mode & 0o022, 'Group/world-writable file')
            require(value.st_size <= MAX_FILE_BYTES, 'File byte budget exceeded')
            total += value.st_size
            require(total <= MAX_TOTAL_BYTES, 'Total byte budget exceeded')
            entry.update(type='file', bytes=value.st_size, sha256=digest(path))
        else:
            raise ValueError('Special file in app payload')
        if hasattr(os, 'listxattr'):
            attributes = os.listxattr(path, follow_symlinks=False)
            require(all(item == 'com.apple.xcode.CreatedByBuildSystem' for item in attributes),
                    'Unretained extended attributes in app payload')
        entry['_fingerprint'] = fingerprint(value)
        result.append(entry)
        require(len(result) <= MAX_ENTRIES, 'Entry budget exceeded')
    return sorted(result, key=lambda entry: entry['path'])


def adhoc_signature(data):
    require(len(data) >= 12, 'Truncated signature envelope')
    magic, length, count = struct.unpack_from('>III', data)
    require(magic == CS_SUPERBLOB and length <= len(data) and 1 <= count <= 32 and
            12 + count * 8 <= length, 'Unsupported signature envelope')
    intervals = []
    slots = set()
    for index in range(count):
        slot, offset = struct.unpack_from('>II', data, 12 + index * 8)
        require(slot in CODEDIRECTORY_SLOTS and slot not in slots,
                'Only linker ad-hoc CodeDirectories are allowed; distribution signature/entitlements refused')
        slots.add(slot)
        require(12 + count * 8 <= offset <= length - 16, 'Invalid CodeDirectory range')
        blob_magic, blob_length, version, flags = struct.unpack_from('>IIII', data, offset)
        require(blob_magic == CS_CODEDIRECTORY and 44 <= blob_length <= length - offset and
                flags & CS_ADHOC, 'Non-ad-hoc or malformed CodeDirectory')
        interval = (offset, offset + blob_length)
        require(all(interval[1] <= left or interval[0] >= right for left, right in intervals),
                'Overlapping CodeDirectories')
        intervals.append(interval)
    require(0 in slots, 'Missing primary ad-hoc CodeDirectory')
    return 'ad-hoc; no distribution identity'


def inspect_slice(data, expected_cpu):
    require(len(data) >= 32, 'Truncated Mach-O header')
    magic, cpu, subtype, kind, count, command_bytes, flags, reserved = struct.unpack_from('<8I', data)
    require(magic == MACH_MAGIC and cpu == expected_cpu and kind == MH_EXECUTE,
            'Expected supported 64-bit executable Mach-O slice')
    require(count <= MAX_LOAD_COMMANDS and command_bytes <= len(data) - 32,
            'Mach-O load-command budget/range exceeded')
    cursor = 32
    end = cursor + command_bytes
    signature = 'absent'
    dependencies = []
    for _ in range(count):
        require(cursor <= end - 8, 'Truncated Mach-O load command')
        command, size = struct.unpack_from('<II', data, cursor)
        require(size >= 8 and size % 8 == 0 and size <= end - cursor, 'Invalid Mach-O load-command size')
        require(command not in UNSUPPORTED_LINKAGE_COMMANDS, 'Unsupported linkage/environment command')
        if command == LC_LOAD_DYLINKER:
            require(size >= 16, 'Truncated dynamic-linker command')
            offset = struct.unpack_from('<I', data, cursor + 8)[0]
            require(12 <= offset < size and
                    data[cursor + offset:cursor + size].split(b'\0', 1)[0] == b'/usr/lib/dyld' and
                    b'\0' in data[cursor + offset:cursor + size], 'Unexpected dynamic linker')
        if command == LC_CODE_SIGNATURE:
            require(size == 16 and signature == 'absent', 'Duplicate or invalid signature command')
            offset, length = struct.unpack_from('<II', data, cursor + 8)
            require(offset >= end and length <= len(data) - offset, 'Invalid signature data range')
            signature = adhoc_signature(data[offset:offset + length])
        if command in DYLIB_COMMANDS:
            require(size >= 24, 'Truncated dylib command')
            offset = struct.unpack_from('<I', data, cursor + 8)[0]
            require(24 <= offset < size, 'Invalid dependency string offset')
            raw = data[cursor + offset:cursor + size]
            require(b'\0' in raw, 'Unterminated dependency string')
            name = raw.split(b'\0', 1)[0].decode('utf-8')
            require(name.startswith(('/System/Library/', '/usr/lib/')) and
                    '..' not in PurePosixPath(name).parts and
                    all(ord(ch) >= 32 and ord(ch) != 127 for ch in name),
                    'Non-system dynamic dependency')
            dependencies.append(name)
        cursor += size
    require(cursor == end, 'Trailing Mach-O load-command bytes')
    return {'architecture': CPU_TYPES[cpu], 'signature': signature, 'dependencies': sorted(set(dependencies))}


def inspect_macho(data):
    require(len(data) >= 8 and data[:4] == FAT_MAGIC, 'Expected universal Mach-O, not a thin/foreign executable')
    count = struct.unpack_from('>I', data, 4)[0]
    require(count == 2 and len(data) >= 8 + count * 20, 'Expected exactly arm64 and x86_64 slices')
    cpus = set()
    intervals = []
    slices = []
    for index in range(count):
        cpu, subtype, offset, size, alignment = struct.unpack_from('>5I', data, 8 + index * 20)
        require(cpu in CPU_TYPES and cpu not in cpus and alignment <= 30 and
                offset % (1 << alignment) == 0 and offset >= 8 + count * 20 and
                32 <= size <= len(data) - offset, 'Invalid universal slice')
        cpus.add(cpu)
        require(all(offset + size <= left or offset >= right for left, right in intervals),
                'Overlapping universal slices')
        intervals.append((offset, offset + size))
        slices.append(inspect_slice(data[offset:offset + size], cpu))
    return sorted(slices, key=lambda item: item['architecture'])


def validate_bundle(app, entries):
    indexed = {entry['path']: entry for entry in entries}
    executables = set()
    bundles = []
    for subpath, identifier, package_type in BUNDLES:
        bundle = app / subpath
        plist_path = bundle / 'Contents/Info.plist'
        name = plist_path.relative_to(app.parent).as_posix()
        require(name in indexed and indexed[name]['type'] == 'file', 'Missing real bundle Info.plist')
        info = plistlib.loads(read_bytes(plist_path, MAX_PLIST_BYTES))
        require(isinstance(info, dict) and info.get('CFBundleIdentifier') == identifier and
                info.get('CFBundlePackageType') == package_type, 'Unexpected bundle identity or type')
        executable = info.get('CFBundleExecutable')
        require(isinstance(executable, str) and executable not in ('', '.', '..') and
                '/' not in executable and '\\' not in executable, 'Invalid bundle executable')
        path = bundle / 'Contents/MacOS' / executable
        key = path.relative_to(app.parent).as_posix()
        require(key in indexed and indexed[key]['type'] == 'file' and indexed[key]['mode'] & 0o111,
                'Missing executable or executable mode')
        executables.add(key)
        version, build = info.get('CFBundleShortVersionString'), info.get('CFBundleVersion')
        require(isinstance(version, str) and version and isinstance(build, str) and build,
                'Missing bundle version/build')
        if subpath:
            attributes = info.get('EXAppExtensionAttributes', {})
            require(isinstance(attributes, dict) and
                    attributes.get('EXExtensionPointIdentifier') == 'com.apple.fskit.fsmodule',
                    'Expected FSKit extension point')
        bundles.append({'identifier': identifier, 'version': version, 'build': build,
                        'executable': key, 'slices': inspect_macho(read_bytes(path, MAX_FILE_BYTES))})
    require(len({(item['version'], item['build']) for item in bundles}) == 1,
            'App/extension version mismatch')
    for entry in entries:
        relative = PurePosixPath(entry['path']).relative_to(app.name)
        parts = relative.parts
        require(not any(part in ('_CodeSignature', 'embedded.provisionprofile', 'embedded.mobileprovision',
                                  '.git', 'vendor', 'Frameworks', 'PlugIns') for part in parts),
                'Unexpected signed/development/embedded-code payload')
        allowed = False
        for subpath, _, _ in BUNDLES:
            prefix = PurePosixPath(subpath) if subpath else PurePosixPath('.')
            try:
                local = relative.relative_to(prefix)
            except ValueError:
                continue
            local_name = str(local)
            if local_name in ('.', 'Contents', 'Contents/Info.plist', 'Contents/PkgInfo',
                              'Contents/MacOS', 'Contents/Resources'):
                allowed = True
            if local_name.startswith('Contents/Resources/') or entry['path'] in executables:
                allowed = True
        if str(relative) == 'Contents/Extensions':
            allowed = True
        require(allowed, 'Unreviewed bundle path outside the explicit product layout')
        if entry['type'] == 'symlink':
            path = app.parent / entry['path']
            resource_roots = [app / subpath / 'Contents/Resources' for subpath, _, _ in BUNDLES]
            require(any(path.is_relative_to(root) and path.resolve().is_relative_to(root.resolve())
                        for root in resource_roots), 'Symlink must remain inside its Resources directory')
        if entry['type'] == 'file' and entry['path'] not in executables:
            require(not entry['mode'] & 0o111, 'Unexpected executable payload')
            path = app.parent / entry['path']
            with regular_reader(path) as source:
                prefix = source.read(8)
            require(prefix[:4] not in (FAT_MAGIC, b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\x7fELF') and
                    not prefix.startswith((b'MZ', b'#!', b'!<arch>')), 'Unexpected code payload')
        if entry['type'] == 'directory' and relative.suffix in ('.app', '.appex', '.framework', '.bundle'):
            require(str(relative) == EXTENSION, 'Unexpected nested code bundle')
    return bundles


def public_inventory(entries):
    return [{key: value for key, value in entry.items() if not key.startswith('_')} for entry in entries]


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def archive_product(destination, app, entries, documents, epoch):
    with tarfile.open(destination, 'x', format=tarfile.PAX_FORMAT) as archive:
        for name, entry, data in sorted(
                [(entry['path'], entry, None) for entry in entries] +
                [(name, {'type': 'file', 'mode': 0o644, 'bytes': len(data)}, data)
                 for name, data in documents.items()], key=lambda item: item[0]):
            member = tarfile.TarInfo(name)
            member.mode, member.mtime = entry['mode'], epoch
            member.uid = member.gid = 0
            member.uname = member.gname = ''
            if entry['type'] == 'directory':
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            elif entry['type'] == 'symlink':
                member.type, member.linkname = tarfile.SYMTYPE, entry['target']
                archive.addfile(member)
            elif data is not None:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            else:
                member.size = entry['bytes']
                with regular_reader(app.parent / entry['path'], entry['_fingerprint']) as source:
                    archive.addfile(member, source)


def verify_archive(path, entries, documents, epoch):
    expected = {entry['path']: entry for entry in entries}
    expected.update({name: {'type': 'file', 'mode': 0o644, 'bytes': len(data),
                            'sha256': hashlib.sha256(data).hexdigest()} for name, data in documents.items()})
    with tarfile.open(path, 'r:') as archive:
        members = archive.getmembers()
        require([member.name for member in members] == sorted(expected), 'Archive members differ from inventory')
        for member in members:
            entry = expected[member.name]
            kind = 'file' if member.isfile() else 'directory' if member.isdir() else 'symlink' if member.issym() else 'other'
            require(kind == entry['type'] and member.mode == entry['mode'] and member.mtime == epoch and
                    member.uid == member.gid == 0 and member.uname == member.gname == '', 'Archive metadata mismatch')
            if kind == 'symlink':
                require(member.linkname == entry['target'], 'Archive symlink mismatch')
            if kind == 'file':
                require(member.size == entry['bytes'], 'Archive size mismatch')
                value = hashlib.sha256()
                with archive.extractfile(member) as source:
                    for block in iter(lambda: source.read(IO_BYTES), b''):
                        value.update(block)
                require(value.hexdigest() == entry['sha256'], 'Archive data mismatch')


def verified_build(build_report, source, entries):
    """Bind retained build evidence to this complete app, never just its filename."""
    require(isinstance(build_report, dict) and build_report.get('schema') == 1 and
            build_report.get('status') == 'pass' and build_report.get('configuration') == 'Release' and
            build_report.get('signing_mode') == 'unsigned-requested',
            'Expected a successful unsigned Release build report')
    build_source = build_report.get('source', {})
    require(isinstance(build_source, dict) and build_source.get('role') == 'build-source' and
            all(build_source.get(field) == source.get(field) for field in ('revision', 'tree', 'epoch')),
            'Build source does not match packaging checkout')
    require(build_report.get('app_payload') == public_inventory(entries),
            'Actual app no longer matches retained build inventory')
    require(isinstance(build_report.get('toolchain'), dict) and
            all(build_report['toolchain'].get(key) for key in
                ('xcode', 'sdk_path', 'sdk_version', 'xcodegen', 'clang', 'clang_version')),
            'Build report lacks actual toolchain identity')
    require(isinstance(build_report.get('source_archive_sha256'), str) and
            re.fullmatch(r'[0-9a-f]{64}', build_report['source_archive_sha256']),
            'Build report lacks committed source archive identity')


def package(app, output, source, license_bytes, provenance_bytes, *, revalidate_source=None,
            build_report_bytes=None, comparison_app=None, comparison_report_bytes=None):
    """Caller owns app; output must not exist. Failed new outputs retain a report."""
    app = Path(os.path.abspath(app))
    output = Path(os.path.abspath(output))
    require(app.name == APP_NAME, 'Unexpected app directory name')
    require(not output.resolve().is_relative_to(app.resolve()), 'Output must be outside app')
    if comparison_app is not None:
        require(not output.resolve().is_relative_to(Path(comparison_app).resolve()),
                'Output must be outside comparison app')
    require(source.get('role') == 'packaging-checkout' and type(source.get('epoch')) is int and
            0 <= source['epoch'] < 2**32, 'Invalid packaging provenance')
    require(all(isinstance(source.get(field), str) and
                re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', source[field]) for field in ('revision', 'tree')),
            'Invalid source revision/tree identity')
    require(license_bytes and provenance_bytes, 'Required license/provenance notice is empty')
    output.mkdir(parents=False, exist_ok=False)
    report = {'schema': 1, 'status': 'running', 'scope': 'unsigned engineering transport only',
              'build_source_binding': 'not established by packaging; pair with same-job build evidence',
              'native_installation_qualified': False, 'distribution_ready': False, 'source': source,
              'app_build_reproducibility': {'status': 'unexecuted'}}
    report_path = output / 'report.json'
    try:
        report_path.write_bytes(json_bytes(report))
        entries = inventory(app)
        bundles = validate_bundle(app, entries)
        if build_report_bytes is not None:
            build_report = json.loads(build_report_bytes)
            verified_build(build_report, source, entries)
            report['build_source_binding'] = 'retained same-revision Xcode build report and exact app inventory'
            report['build_report_sha256'] = hashlib.sha256(build_report_bytes).hexdigest()
        comparison_entries = None
        require((comparison_app is None) == (comparison_report_bytes is None),
                'App comparison requires both app and build report')
        if comparison_app is not None:
            require(build_report_bytes is not None, 'App comparison requires both original build reports')
            comparison_app = Path(os.path.abspath(comparison_app))
            require(comparison_app.name == APP_NAME and comparison_app.resolve() != app.resolve(),
                    'App comparison requires distinct build outputs')
            comparison_entries = inventory(comparison_app)
            validate_bundle(comparison_app, comparison_entries)
            comparison_report = json.loads(comparison_report_bytes)
            verified_build(comparison_report, source, comparison_entries)
            require(build_report.get('app_path') and comparison_report.get('app_path') and
                    build_report['app_path'] != comparison_report['app_path'],
                    'Build reports must identify distinct original build output paths')
            require(build_report['toolchain'] == comparison_report['toolchain'],
                    'App comparison requires the same toolchain/SDK')
            first_entries = {entry['path']: entry for entry in public_inventory(entries)}
            second_entries = {entry['path']: entry for entry in public_inventory(comparison_entries)}
            differences = [name for name in sorted(first_entries.keys() | second_entries.keys())
                           if first_entries.get(name) != second_entries.get(name)]
            report['app_build_reproducibility'] = {
                'status': 'failed' if differences else 'pass', 'different_paths': differences,
                'first_build_report_sha256': report['build_report_sha256'],
                'second_build_report_sha256': hashlib.sha256(comparison_report_bytes).hexdigest(),
                'scope': 'two retained same-source/toolchain build reports; exact full app inventories'}
            require(not differences, 'Independently built app payloads differ; see different_paths')
        manifest = {'schema': 1, 'source': source, 'scope': report['scope'], 'bundles': bundles,
                    'payload': public_inventory(entries),
                    'metadata_policy': 'preserve file modes and symlinks; normalize uid/gid/time; '
                                       'omit only Xcode CreatedByBuildSystem xattr',
                    'notices': {name: hashlib.sha256(data).hexdigest() for name, data in
                                [('LICENSE', license_bytes), ('PROVENANCE.md', provenance_bytes),
                                 ('NOTICE.txt', NOTICE.encode())]}}
        documents = {'LICENSE': license_bytes, 'PROVENANCE.md': provenance_bytes,
                     'NOTICE.txt': NOTICE.encode(), 'manifest.json': json_bytes(manifest)}
        if build_report_bytes is not None:
            manifest['build_report_sha256'] = report['build_report_sha256']
            documents['build-report.json'] = build_report_bytes
            if comparison_report_bytes is not None:
                manifest['app_build_reproducibility'] = report['app_build_reproducibility']
                documents['comparison-build-report.json'] = comparison_report_bytes
            documents['manifest.json'] = json_bytes(manifest)
        first, second = output / 'unsigned.tar.partial', output / 'comparison.tar.partial'
        archive_product(first, app, entries, documents, source['epoch'])
        verify_archive(first, entries, documents, source['epoch'])
        archive_product(second, app, entries, documents, source['epoch'])
        verify_archive(second, entries, documents, source['epoch'])
        require(digest(first) == digest(second), 'Repeated package bytes differ')
        require(inventory(app) == entries, 'App changed during packaging')
        if comparison_entries is not None:
            require(inventory(comparison_app) == comparison_entries, 'Comparison app changed during packaging')
        if revalidate_source is not None:
            require(revalidate_source() == source, 'Source checkout changed during packaging')
        archive = output / 'unsigned-fskit.tar'
        first.rename(archive)
        second.unlink()
        report.update(status='pass', package=archive.name, bytes=archive.stat().st_size,
                      sha256=digest(archive), same_input_packaging_reproducible=True,
                      bundles=bundles,
                      payload_entries=len(entries))
        (output / 'manifest.json').write_bytes(documents['manifest.json'])
        report_path.write_bytes(json_bytes(report))
        return report
    except Exception as error:
        report.update(status='failed', error=f'{type(error).__name__}: {error}')
        report_path.write_bytes(json_bytes(report))
        raise


def committed_source(root):
    # Existing bounded subprocess runner isolates the environment and byte/deadline budgets.
    from bounded_tool import run_tool
    def git(*arguments):
        return run_tool(['git', '-C', str(root), *arguments], timeout=20,
                        output_limit=MAX_PLIST_BYTES).decode('utf-8').strip()
    require(not git('status', '--porcelain', '--untracked-files=normal'), 'Commit source changes before packaging')
    return {'role': 'packaging-checkout', 'revision': git('rev-parse', 'HEAD'),
            'tree': git('rev-parse', 'HEAD^{tree}'), 'epoch': int(git('show', '-s', '--format=%ct', 'HEAD'))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True, help='Fresh unsigned Release Machlin NTFS.app')
    parser.add_argument('--output', type=Path, required=True, help='New artifact directory; parent must exist')
    parser.add_argument('--source', type=Path, default=ROOT, help='Clean committed source checkout')
    parser.add_argument('--build-report', type=Path, required=True,
                        help='Successful same-source build_fskit.py build-report.json bound to the app')
    parser.add_argument('--compare-app', type=Path, help='Optional second independent app build')
    parser.add_argument('--compare-build-report', type=Path, help='The second independent build report')
    args = parser.parse_args()
    if bool(args.compare_app) != bool(args.compare_build_report):
        parser.error('App comparison requires both --compare-app and --compare-build-report')
    try:
        before = committed_source(args.source)
        result = package(args.app, args.output, before,
                         read_bytes(args.source / 'LICENSE', MAX_PLIST_BYTES),
                         read_bytes(args.source / 'docs/PROVENANCE.md', MAX_PLIST_BYTES),
                         revalidate_source=lambda: committed_source(args.source),
                         build_report_bytes=read_bytes(args.build_report, 8 * MAX_PLIST_BYTES),
                         comparison_app=args.compare_app,
                         comparison_report_bytes=(read_bytes(args.compare_build_report, 8 * MAX_PLIST_BYTES)
                                                  if args.compare_build_report else None))
        print(f"PASS: unsigned transport retained; {result['payload_entries']} payload entries; "
              f"{args.output / result['package']}")
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError, plistlib.InvalidFileException) as error:
        parser.exit(1, f'Packaging failed: {error}\n')


if __name__ == '__main__':
    main()
