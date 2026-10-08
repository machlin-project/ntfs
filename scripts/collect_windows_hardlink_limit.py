#!/usr/bin/env python3
"""Observe native Windows hard-link count limits in a new, owned NTFS TEMP directory.

No administrator rights, VHD, pre-existing files or machine settings are used.
The synthetic contract tests exercise reporting only and cannot produce a native
verdict. This observer does not admit the C hard-link writer or inspect disk WAL.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
from datetime import datetime, timezone

MAX_ADDITIONAL_LINKS = 1023
ERROR_TOO_MANY_LINKS = 1142
CHECKPOINTS = (1, 2, 31, 255, 511, 1022, 1023)
SOURCE_NAME = 'origin.bin'
REFUSED_NAME = 'refused-extra.bin'
ADS_NAME = 'witness'
PAYLOAD = b'Original native hard-link count payload.\x00\xff\x17' * 7
ADS_PAYLOAD = b'Independent alternate stream preservation witness.\x00\xfe' * 3
DIRECTORY_PREFIX = 'machlin-hardlink-limit-'
WINDOWS_PATH_UNITS = 32768
FILE_READ_ATTRIBUTES = 0x80
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
FILE_SHARE_DELETE = 4
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80

DWORD = ctypes.c_uint32
BOOL = ctypes.c_int32
HANDLE = ctypes.c_void_p


class FileTime(ctypes.Structure):
    _fields_ = [('low', DWORD), ('high', DWORD)]


class FileInformation(ctypes.Structure):
    _fields_ = [('attributes', DWORD), ('creation', FileTime), ('access', FileTime),
                ('write', FileTime), ('volume_serial', DWORD), ('size_high', DWORD),
                ('size_low', DWORD), ('links', DWORD), ('file_index_high', DWORD),
                ('file_index_low', DWORD)]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def link_name(ordinal):
    if not 1 <= ordinal <= MAX_ADDITIONAL_LINKS:
        raise ValueError('Link ordinal outside the bounded case')
    return f'link-{ordinal:04d}.bin'


def stable(snapshot):
    """The unchanged-state oracle; API read-access timestamps are retained separately."""
    return {key: snapshot[key] for key in (
        'volume_serial', 'file_id', 'links', 'size', 'attributes',
        'payload_sha256', 'ads_sha256')}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def collect(provider, report):
    """Bounded observation with provider-owned fresh storage; no native claim here."""
    provider.create(SOURCE_NAME, PAYLOAD, ADS_PAYLOAD)
    original = provider.observe(SOURCE_NAME)
    report['original'] = original
    report['checkpoints'] = []
    report['calls'] = []
    require(original['links'] == 1, 'Fresh original did not have exactly one link')
    require(original['size'] == len(PAYLOAD), 'Original logical size differs')
    require(original['payload_sha256'] == sha256(PAYLOAD), 'Original payload differs')
    require(original['ads_sha256'] == sha256(ADS_PAYLOAD), 'Original ADS differs')
    expected_names = {SOURCE_NAME}
    require(provider.names() == expected_names, 'Fresh directory contains unexpected names')
    for ordinal in range(1, MAX_ADDITIONAL_LINKS + 1):
        name = link_name(ordinal)
        success, error = provider.link(name, SOURCE_NAME)
        report['calls'].append(dict(additional=ordinal, name=name, success=success,
                                    win32_error=error))
        if not success:
            report['early_failure_state'] = provider.observe(SOURCE_NAME)
            report['early_failure_names'] = sorted(provider.names())
            raise RuntimeError(f'CreateHardLinkW failed early at additional link {ordinal}: {error}')
        expected_names.add(name)
        if ordinal in CHECKPOINTS:
            source, alias = provider.observe(SOURCE_NAME), provider.observe(name)
            report['checkpoints'].append(dict(additional=ordinal, source=source, alias=alias))
            expected = dict(stable(original), links=ordinal + 1)
            require(stable(source) == expected, f'Source preservation/count failed at {ordinal}')
            require(stable(alias) == expected, f'Alias preservation/identity failed at {ordinal}')
            require(provider.names() == expected_names, f'Namespace differs at {ordinal}')
    before = provider.observe(SOURCE_NAME)
    before_names = provider.names()
    success, error = provider.link(REFUSED_NAME, SOURCE_NAME)
    after = provider.observe(SOURCE_NAME)
    after_names = provider.names()
    report['limit_attempt'] = dict(additional=MAX_ADDITIONAL_LINKS + 1,
        name=REFUSED_NAME, success=success, win32_error=error,
        before=before, after=after, before_names=sorted(before_names),
        after_names=sorted(after_names))
    require(not success, 'The next CreateHardLinkW unexpectedly succeeded')
    require(error == ERROR_TOO_MANY_LINKS, f'Unexpected limit error: {error}')
    require(before['links'] == MAX_ADDITIONAL_LINKS + 1, 'Pre-limit count differs')
    require(stable(before) == stable(after), 'Failed call changed identity/count/data/ADS/attributes')
    require(before_names == expected_names and after_names == before_names,
            'Failed call changed the namespace')
    report['observed_maximum_total_links'] = before['links']
    report['observed_additional_links'] = len(report['calls'])
    report['checks_complete'] = True


class WindowsNTFSProvider:
    def __init__(self, root):
        if sys.platform != 'win32':
            raise RuntimeError('Native collection requires Windows')
        self.root = Path(root)
        require(self.root.name.startswith(DIRECTORY_PREFIX) and self.root.is_dir(),
                'Root is not this observer\'s freshly allocated TEMP directory')
        require(not any(self.root.iterdir()), 'Owned TEMP directory is not empty')
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.GetVolumePathNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, DWORD]
        self.kernel.GetVolumePathNameW.restype = BOOL
        self.kernel.GetVolumeInformationW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p,
            DWORD, ctypes.POINTER(DWORD), ctypes.POINTER(DWORD), ctypes.POINTER(DWORD),
            ctypes.c_wchar_p, DWORD]
        self.kernel.GetVolumeInformationW.restype = BOOL
        self.kernel.CreateHardLinkW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]
        self.kernel.CreateHardLinkW.restype = BOOL
        self.kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, DWORD, DWORD, ctypes.c_void_p,
                                           DWORD, DWORD, HANDLE]
        self.kernel.CreateFileW.restype = HANDLE
        self.kernel.GetFileInformationByHandle.argtypes = [HANDLE, ctypes.POINTER(FileInformation)]
        self.kernel.GetFileInformationByHandle.restype = BOOL
        self.kernel.CloseHandle.argtypes = [HANDLE]
        self.kernel.CloseHandle.restype = BOOL
        require(ctypes.sizeof(FileInformation) == 52, 'BY_HANDLE_FILE_INFORMATION layout differs')
        volume = ctypes.create_unicode_buffer(WINDOWS_PATH_UNITS)
        if not self.kernel.GetVolumePathNameW(str(self.root), volume, len(volume)):
            raise ctypes.WinError(ctypes.get_last_error())
        filesystem = ctypes.create_unicode_buffer(WINDOWS_PATH_UNITS)
        serial, maximum_component, flags = DWORD(), DWORD(), DWORD()
        if not self.kernel.GetVolumeInformationW(volume.value, None, 0,
                ctypes.byref(serial), ctypes.byref(maximum_component), ctypes.byref(flags),
                filesystem, len(filesystem)):
            raise ctypes.WinError(ctypes.get_last_error())
        require(filesystem.value.upper() == 'NTFS', f'TEMP filesystem is {filesystem.value}, not NTFS')
        self.volume = dict(filesystem=filesystem.value, volume_path=volume.value,
                           volume_serial=serial.value, flags=flags.value,
                           maximum_component_length=maximum_component.value)

    def path(self, name):
        if name not in (SOURCE_NAME, REFUSED_NAME) and name not in {
                link_name(ordinal) for ordinal in range(1, MAX_ADDITIONAL_LINKS + 1)}:
            raise ValueError('Unexpected filename outside the bounded owned set')
        return self.root / name

    def create(self, name, payload, ads):
        path = self.path(name)
        with path.open('xb') as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        with Path(str(path) + ':' + ADS_NAME).open('xb') as handle:
            handle.write(ads)
            handle.flush()
            os.fsync(handle.fileno())

    def link(self, name, source):
        ctypes.set_last_error(0)
        success = bool(self.kernel.CreateHardLinkW(str(self.path(name)),
                                                   str(self.path(source)), None))
        error = ctypes.get_last_error()
        return success, 0 if success else error

    def observe(self, name):
        path = self.path(name)
        payload = path.read_bytes()
        ads = Path(str(path) + ':' + ADS_NAME).read_bytes()
        handle = self.kernel.CreateFileW(str(path), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, None,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            info = FileInformation()
            if not self.kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            require(info.volume_serial == self.volume['volume_serial'], 'File moved to another volume')
            return dict(volume_serial=info.volume_serial,
                file_id=(info.file_index_high << 32) | info.file_index_low,
                links=info.links, size=(info.size_high << 32) | info.size_low,
                attributes=info.attributes, payload_sha256=sha256(payload), ads_sha256=sha256(ads),
                raw_file_information_hex=bytes(info).hex())
        finally:
            if not self.kernel.CloseHandle(handle):
                raise ctypes.WinError(ctypes.get_last_error())

    def names(self):
        return {path.name for path in self.root.iterdir()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True,
                        help='New report directory; existing evidence is never overwritten')
    args = parser.parse_args(argv)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = dict(schema=1, native=False, complete=False, checks_complete=False,
        scope='Native API count/identity/payload/ADS only; no C writer or recovery admission',
        started_utc=datetime.now(timezone.utc).isoformat(), platform=platform.platform(),
        python=sys.version, runner_image=dict(os=os.environ.get('ImageOS'),
                                            version=os.environ.get('ImageVersion')),
        script_sha256=sha256(Path(__file__).read_bytes()),
        expected_additional_links=MAX_ADDITIONAL_LINKS,
        expected_limit_error=ERROR_TOO_MANY_LINKS,
        preservation_fields=['names', 'volume_serial', 'file_id', 'links', 'size',
                             'attributes', 'payload_sha256', 'ads_sha256'])
    root = None
    try:
        require(sys.platform == 'win32', 'Native collection requires Windows')
        temp = os.environ.get('TEMP')
        require(temp is not None and Path(temp).is_dir(), 'Existing runner TEMP directory is required')
        root = Path(tempfile.mkdtemp(prefix=DIRECTORY_PREFIX, dir=temp))
        report['owned_temp_directory'] = str(root)
        provider = WindowsNTFSProvider(root)
        report['volume'] = provider.volume
        report['native'] = True
        (output / 'expected-payload.bin').write_bytes(PAYLOAD)
        (output / 'expected-witness.ads.bin').write_bytes(ADS_PAYLOAD)
        collect(provider, report)
        report['complete'] = True
    except Exception as error:
        report['error'] = dict(type=type(error).__name__, message=str(error),
                               win32_error=getattr(error, 'winerror', None))
    finally:
        # Keep the uniquely owned native source intact for same-run diagnosis;
        # hosted-runner teardown reclaims it. Reports retain actual bytes too.
        if root is not None:
            for name, path in (('observed-payload.bin', root / SOURCE_NAME),
                    ('observed-witness.ads.bin', Path(str(root / SOURCE_NAME) + ':' + ADS_NAME))):
                try:
                    if path.is_file():
                        data = path.read_bytes()
                        (output / name).write_bytes(data)
                        report.setdefault('retained_files', {})[name] = dict(
                            bytes=len(data), sha256=sha256(data))
                    elif 'original' in report:
                        report.setdefault('retention_errors', []).append(
                            f'Original evidence disappeared before retention: {name}')
                except OSError as error:
                    report.setdefault('retention_errors', []).append(str(error))
            if report.get('retention_errors'):
                report['complete'] = False
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(native=report['native'], complete=report['complete'],
                         report=str(output / 'report.json'))))
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
