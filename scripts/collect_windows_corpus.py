#!/usr/bin/env python3
"""Capture native observations and a raw image of a read-only Windows NTFS volume.

The caller prepares a dedicated test volume and mounts it read-only. This program
never formats, mounts, changes attributes, follows links, or modifies the source.
Output is new regular files on a different volume. Native API declarations follow
the Windows SDK; references and UTF-16 units are preserved without JSON rounding.
"""
import argparse
import base64
import ctypes as ct
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import struct
import sys

SCHEMA_VERSION = 1
COPY_BYTES = 1024 * 1024
DEFAULT_IMAGE_LIMIT = 1024 * 1024 * 1024
DEFAULT_STREAM_LIMIT = 256 * 1024 * 1024
DEFAULT_ENTRY_LIMIT = 100000
MAX_SECURITY_BYTES = 1024 * 1024
REPARSE_MAX_BYTES = 16 * 1024
WIN32_MAX_PATH = 260
WIN32_STREAM_TYPE_SUFFIX_UNITS = 36
DWORD_BITS = 32
FILE_READ_ATTRIBUTES = 0x0080
READ_CONTROL = 0x00020000
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_ENCRYPTED = 0x00004000
FILE_READ_ONLY_VOLUME = 0x00080000
FILE_BASIC_INFO_CLASS = 0
FILE_CASE_SENSITIVE_INFO_CLASS = 23
FILE_CS_FLAG_CASE_SENSITIVE_DIR = 0x00000001
OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
DACL_SECURITY_INFORMATION = 0x00000004
ERROR_HANDLE_EOF = 38
ERROR_NO_MORE_FILES = 18
ERROR_INSUFFICIENT_BUFFER = 122
FILE_DEVICE_FILE_SYSTEM = 0x00000009
IOCTL_DEVICE_SHIFT = 16
IOCTL_FUNCTION_SHIFT = 2
FSCTL_GET_NTFS_VOLUME_DATA_FUNCTION = 25
FSCTL_ALLOW_EXTENDED_DASD_IO_FUNCTION = 32
FSCTL_GET_REPARSE_POINT_FUNCTION = 42
METHOD_NEITHER = 3
FSCTL_GET_NTFS_VOLUME_DATA = ((FILE_DEVICE_FILE_SYSTEM << IOCTL_DEVICE_SHIFT) |
                             (FSCTL_GET_NTFS_VOLUME_DATA_FUNCTION << IOCTL_FUNCTION_SHIFT))
FSCTL_GET_REPARSE_POINT = ((FILE_DEVICE_FILE_SYSTEM << IOCTL_DEVICE_SHIFT) |
                         (FSCTL_GET_REPARSE_POINT_FUNCTION << IOCTL_FUNCTION_SHIFT))
FSCTL_ALLOW_EXTENDED_DASD_IO = ((FILE_DEVICE_FILE_SYSTEM << IOCTL_DEVICE_SHIFT) |
                              (FSCTL_ALLOW_EXTENDED_DASD_IO_FUNCTION << IOCTL_FUNCTION_SHIFT) |
                              METHOD_NEITHER)
REPARSE_TAG_SYMLINK = 0xA000000C
REPARSE_TAG_MOUNT_POINT = 0xA0000003
REPARSE_TAG_WOF = 0x80000017
REPARSE_HEADER = struct.Struct('<IHH')
REPARSE_NAMES = struct.Struct('<HHHH')
REPARSE_FLAGS = struct.Struct('<I')

# Use fixed widths even when imported on a Unix host for contract tests. Win32
# WCHAR arrays are uint16_t here; ctypes.c_wchar is four bytes on some hosts.
DWORD = ct.c_uint32
WORD = ct.c_uint16
HANDLE = ct.c_void_p
BOOL = ct.c_int32


class FileTime(ct.Structure):
    _fields_ = [('low', DWORD), ('high', DWORD)]

    def ticks(self):
        return (self.high << DWORD_BITS) | self.low


class FileInformation(ct.Structure):
    _fields_ = [('attributes', DWORD), ('created', FileTime), ('accessed', FileTime),
                ('modified', FileTime), ('volume_serial', DWORD), ('size_high', DWORD),
                ('size_low', DWORD), ('links', DWORD), ('index_high', DWORD),
                ('index_low', DWORD)]


class StreamInformation(ct.Structure):
    _fields_ = [('size', ct.c_int64),
                ('name', WORD * (WIN32_MAX_PATH + WIN32_STREAM_TYPE_SUFFIX_UNITS))]


class BasicInformation(ct.Structure):
    _fields_ = [('created', ct.c_int64), ('accessed', ct.c_int64),
                ('modified', ct.c_int64), ('changed', ct.c_int64), ('attributes', DWORD)]


class VolumeInformation(ct.Structure):
    _fields_ = [('serial', ct.c_uint64), ('sectors', ct.c_int64),
                ('clusters', ct.c_int64), ('free_clusters', ct.c_int64),
                ('reserved_clusters', ct.c_int64), ('sector_bytes', DWORD),
                ('cluster_bytes', DWORD), ('record_bytes', DWORD),
                ('clusters_per_record', DWORD), ('mft_valid_bytes', ct.c_int64),
                ('mft_lcn', ct.c_int64), ('mirror_lcn', ct.c_int64),
                ('mft_zone_start', ct.c_int64), ('mft_zone_end', ct.c_int64)]


def utf16_units(text):
    encoded = text.encode('utf-16-le', errors='surrogatepass')
    return list(struct.unpack(f'<{len(encoded) // ct.sizeof(WORD)}H', encoded))


def units_text(units):
    return struct.pack(f'<{len(units)}H', *units).decode('utf-16-le', errors='surrogatepass')


def payload_name(reference, stream_units):
    # Original names live in the manifest. Fixed-size payload components also
    # support maximum-length ADS names without exceeding native filename limits.
    encoded = struct.pack(f'<{len(stream_units)}H', *stream_units)
    return 'payloads/' + reference + '-' + hashlib.sha256(encoded).hexdigest() + '.bin'


def reparse_observation(data):
    if len(data) < REPARSE_HEADER.size:
        raise ValueError('Windows returned a truncated reparse header')
    tag, length, _ = REPARSE_HEADER.unpack_from(data)
    result = {'tag': tag, 'raw_base64': base64.b64encode(data).decode('ascii')}
    if tag not in (REPARSE_TAG_SYMLINK, REPARSE_TAG_MOUNT_POINT):
        return result
    payload = data[REPARSE_HEADER.size:]
    if len(payload) != length or len(payload) < REPARSE_NAMES.size:
        raise ValueError('Windows returned invalid link framing')
    substitute_offset, substitute_bytes, print_offset, print_bytes = REPARSE_NAMES.unpack_from(payload)
    path_offset = REPARSE_NAMES.size
    if tag == REPARSE_TAG_SYMLINK:
        result['flags'], = REPARSE_FLAGS.unpack_from(payload, path_offset)
        path_offset += REPARSE_FLAGS.size
    else:
        result['flags'] = 0
    paths = payload[path_offset:]
    for field, offset, size in (('substitute_utf16', substitute_offset, substitute_bytes),
                                ('print_utf16', print_offset, print_bytes)):
        if offset % ct.sizeof(WORD) or size % ct.sizeof(WORD) or offset > len(paths) or size > len(paths) - offset:
            raise ValueError('Windows returned an invalid link name span')
        result[field] = list(struct.unpack(f'<{size // ct.sizeof(WORD)}H', paths[offset:offset + size]))
    return result


class WindowsAPI:
    def __init__(self):
        if sys.platform != 'win32':
            raise RuntimeError('Native collection requires Windows; use windows_corpus.py for offline verification')
        self.kernel = ct.WinDLL('kernel32', use_last_error=True)
        self.advapi = ct.WinDLL('advapi32', use_last_error=True)
        self.invalid_handle = HANDLE(-1).value
        self._declare(self.kernel.CreateFileW, HANDLE,
                      [ct.c_wchar_p, DWORD, DWORD, HANDLE, DWORD, DWORD, HANDLE])
        self._declare(self.kernel.CloseHandle, BOOL, [HANDLE])
        self._declare(self.kernel.GetFileInformationByHandle, BOOL,
                      [HANDLE, ct.POINTER(FileInformation)])
        self._declare(self.kernel.GetFileInformationByHandleEx, BOOL,
                      [HANDLE, ct.c_int, ct.c_void_p, DWORD])
        self._declare(self.kernel.GetVolumeInformationW, BOOL,
                      [ct.c_wchar_p, ct.c_wchar_p, DWORD, ct.POINTER(DWORD),
                       ct.POINTER(DWORD), ct.POINTER(DWORD), ct.c_wchar_p, DWORD])
        self._declare(self.kernel.DeviceIoControl, BOOL,
                      [HANDLE, DWORD, ct.c_void_p, DWORD, ct.c_void_p, DWORD,
                       ct.POINTER(DWORD), HANDLE])
        self._declare(self.kernel.ReadFile, BOOL,
                      [HANDLE, ct.c_void_p, DWORD, ct.POINTER(DWORD), HANDLE])
        self._declare(self.kernel.FindFirstStreamW, HANDLE,
                      [ct.c_wchar_p, ct.c_int, ct.POINTER(StreamInformation), DWORD])
        self._declare(self.kernel.FindNextStreamW, BOOL,
                      [HANDLE, ct.POINTER(StreamInformation)])
        self._declare(self.kernel.FindClose, BOOL, [HANDLE])
        self._declare(self.advapi.GetKernelObjectSecurity, BOOL,
                      [HANDLE, DWORD, ct.c_void_p, DWORD, ct.POINTER(DWORD)])

    @staticmethod
    def _declare(function, result, arguments):
        function.restype, function.argtypes = result, arguments

    @staticmethod
    def error():
        return ct.WinError(ct.get_last_error())

    @contextmanager
    def open(self, path, access=FILE_READ_ATTRIBUTES):
        handle = self.kernel.CreateFileW(str(path), access,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        None, OPEN_EXISTING,
                                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None)
        if handle == self.invalid_handle:
            raise self.error()
        try:
            yield handle
        finally:
            self.kernel.CloseHandle(handle)

    def volume(self, root):
        flags, serial, component = DWORD(), DWORD(), DWORD()
        filesystem = ct.create_unicode_buffer(WIN32_MAX_PATH + 1)
        if not self.kernel.GetVolumeInformationW(root, None, 0, ct.byref(serial),
                                                ct.byref(component), ct.byref(flags),
                                                filesystem, len(filesystem)):
            raise self.error()
        if filesystem.value != 'NTFS' or not flags.value & FILE_READ_ONLY_VOLUME:
            raise ValueError('Source must be a read-only NTFS volume according to Windows')
        with self.open('\\\\.\\' + root[:2], GENERIC_READ) as handle:
            data = VolumeInformation()
            returned = DWORD()
            if not self.kernel.DeviceIoControl(handle, FSCTL_GET_NTFS_VOLUME_DATA, None, 0,
                                               ct.byref(data), ct.sizeof(data), ct.byref(returned), None):
                raise self.error()
            if returned.value < ct.sizeof(data) or data.sectors <= 0 or data.sector_bytes == 0:
                raise ValueError('Invalid native volume geometry')
        return {'serial': f'{data.serial:016x}', 'size_bytes': str(data.sectors * data.sector_bytes),
                'sector_size': data.sector_bytes, 'cluster_size': data.cluster_bytes,
                'record_size': data.record_bytes, 'cluster_count': str(data.clusters),
                'native_flags': flags.value}

    def metadata(self, path):
        with self.open(path) as handle:
            data = FileInformation()
            if not self.kernel.GetFileInformationByHandle(handle, ct.byref(data)):
                raise self.error()
            reference = (data.index_high << DWORD_BITS) | data.index_low
            stat = {'directory': bool(data.attributes & FILE_ATTRIBUTE_DIRECTORY),
                    'reparse': bool(data.attributes & FILE_ATTRIBUTE_REPARSE_POINT),
                    'links': data.links, 'file_attributes': data.attributes,
                    'size': str((data.size_high << DWORD_BITS) | data.size_low),
                    'created_ticks': str(data.created.ticks()),
                    'modified_ticks': str(data.modified.ticks()),
                    'accessed_ticks': str(data.accessed.ticks())}
            basic = BasicInformation()
            if not self.kernel.GetFileInformationByHandleEx(handle, FILE_BASIC_INFO_CLASS,
                                                           ct.byref(basic), ct.sizeof(basic)):
                raise self.error()
            stat['changed_ticks'] = str(basic.changed)
            observations = {}
            if stat['directory'] and not stat['reparse']:
                case_flags = DWORD()
                if self.kernel.GetFileInformationByHandleEx(handle, FILE_CASE_SENSITIVE_INFO_CLASS,
                                                           ct.byref(case_flags), ct.sizeof(case_flags)):
                    observations['case_sensitive'] = bool(case_flags.value & FILE_CS_FLAG_CASE_SENSITIVE_DIR)
                    observations['case_flags'] = case_flags.value
                else:
                    observations['case_query_error'] = ct.get_last_error()
            if stat['reparse']:
                buffer = ct.create_string_buffer(REPARSE_MAX_BYTES)
                returned = DWORD()
                if not self.kernel.DeviceIoControl(handle, FSCTL_GET_REPARSE_POINT, None, 0,
                                                   buffer, len(buffer), ct.byref(returned), None):
                    raise self.error()
                if returned.value > len(buffer):
                    raise ValueError('Invalid native reparse byte count')
                observations['reparse'] = reparse_observation(buffer.raw[:returned.value])
        return {'reference': f'{reference:016x}', 'stat': stat, **observations}

    def security(self, path):
        with self.open(path, READ_CONTROL) as handle:
            needed = DWORD()
            flags = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
            if self.advapi.GetKernelObjectSecurity(handle, flags, None, 0, ct.byref(needed)):
                raise ValueError('Unexpected empty native security descriptor')
            if ct.get_last_error() != ERROR_INSUFFICIENT_BUFFER or not 0 < needed.value <= MAX_SECURITY_BYTES:
                raise self.error()
            buffer = ct.create_string_buffer(needed.value)
            if not self.advapi.GetKernelObjectSecurity(handle, flags, buffer, len(buffer), ct.byref(needed)):
                raise self.error()
            if needed.value > len(buffer):
                raise ValueError('Native security descriptor grew unexpectedly')
            return base64.b64encode(buffer.raw[:needed.value]).decode('ascii')

    def streams(self, path):
        data = StreamInformation()
        handle = self.kernel.FindFirstStreamW(str(path), 0, ct.byref(data), 0)
        if handle == self.invalid_handle:
            if ct.get_last_error() == ERROR_HANDLE_EOF:
                return []
            raise self.error()
        streams = []
        try:
            while True:
                units = list(data.name)
                units = units[:units.index(0)]
                name = units_text(units)
                if not name.startswith(':') or not name.endswith(':$DATA') or data.size < 0:
                    raise ValueError('Unexpected native stream type or size')
                streams.append({'name_utf16': utf16_units(name[1:-len(':$DATA')]), 'size': str(data.size)})
                if not self.kernel.FindNextStreamW(handle, ct.byref(data)):
                    if ct.get_last_error() not in (ERROR_HANDLE_EOF, ERROR_NO_MORE_FILES):
                        raise self.error()
                    break
        finally:
            self.kernel.FindClose(handle)
        return streams

    def copy(self, source, destination, expected, *, volume_sector_bytes=None):
        if type(expected) is not int or expected < 0:
            raise ValueError('Invalid native acquisition length')
        if volume_sector_bytes is not None:
            if (type(volume_sector_bytes) is not int or volume_sector_bytes <= 0 or
                    COPY_BYTES % volume_sector_bytes or expected == 0 or expected % volume_sector_bytes or
                    not re.fullmatch(r'\\\\\.\\[A-Z]:', str(source))):
                raise ValueError('Raw volume acquisition requires its exact sector-aligned extent and drive handle')
        checksum = hashlib.sha256()
        buffer = ct.create_string_buffer(COPY_BYTES)
        done = 0
        with self.open(source, GENERIC_READ) as handle, destination.open('xb') as output:
            if volume_sector_bytes is not None:
                # Windows otherwise clips DASD reads to complete filesystem
                # clusters. This handle-only control admits the exact observed
                # trailing sectors; GENERIC_READ and the declared length remain
                # unchanged. Device-driver partition bounds still apply.
                returned = DWORD()
                if not self.kernel.DeviceIoControl(handle, FSCTL_ALLOW_EXTENDED_DASD_IO,
                                                   None, 0, None, 0, ct.byref(returned), None):
                    raise self.error()
            while done < expected:
                amount = min(COPY_BYTES, expected - done)
                returned = DWORD()
                if not self.kernel.ReadFile(handle, buffer, amount, ct.byref(returned), None):
                    raise self.error()
                if returned.value == 0 or returned.value > amount:
                    raise ValueError(f'Short or invalid native read before expected EOF: '
                                     f'{returned.value} of {amount} bytes at {done}/{expected}')
                chunk = buffer.raw[:returned.value]
                output.write(chunk)
                checksum.update(chunk)
                done += returned.value
            output.flush()
            os.fsync(output.fileno())
        return checksum.hexdigest()


def collect(args):
    api = WindowsAPI()
    root = args.volume.upper()
    if not re.fullmatch(r'[A-Z]:\\', root):
        raise ValueError('--volume must name an assigned drive root, for example R:\\')
    volume = api.volume(root)
    if int(volume['size_bytes']) > args.max_image_bytes:
        raise ValueError('Volume exceeds --max-image-bytes; choose an explicit larger acquisition budget')
    scope = Path(os.path.abspath(Path(root) / args.tree))
    if not scope.is_relative_to(Path(root)):
        raise ValueError('--tree must remain inside the source volume')
    # Resolve no reparse component, including the acquisition scope itself.
    prefix = Path(root)
    for component in scope.relative_to(Path(root)).parts:
        prefix /= component
        if api.metadata(prefix)['stat']['reparse']:
            raise ValueError('--tree must contain no reparse components')
    output = args.output.resolve()
    if output.drive.upper() == Path(root).drive.upper():
        raise ValueError('Output must be on a different volume from the read-only source')
    output.mkdir(parents=True, exist_ok=False)
    (output / 'payloads').mkdir()
    report = {'schema_version': SCHEMA_VERSION, 'provenance': 'Windows native NTFS API',
              'acquisition_status': 'running', 'platform': platform.platform(),
              'windows_version': list(platform.win32_ver()), 'volume': volume,
              'scope_utf16': [utf16_units(part) for part in scope.relative_to(Path(root)).parts],
              'limits': {'image_bytes': args.max_image_bytes, 'stream_bytes': args.max_stream_bytes,
                         'entries': args.max_entries}, 'entries': [], 'observation_errors': []}
    manifest = output / 'manifest.json'
    try:
        root_info = api.metadata(root)
        report['volume']['root_reference'] = root_info['reference']
        pending = [scope]
        copied = {}
        while pending:
            path = pending.pop()
            if len(report['entries']) >= args.max_entries:
                raise ValueError('Corpus exceeds --max-entries')
            observation = api.metadata(path)
            relative = path.relative_to(Path(root))
            observation['path_utf16'] = [utf16_units(part) for part in relative.parts]
            observation['name_utf16'] = utf16_units(path.name) if relative.parts else []
            observation['parent_reference'] = (api.metadata(path.parent)['reference']
                                                if relative.parts else None)
            try:
                observation['security_descriptor_base64'] = api.security(path)
            except OSError as error:
                observation['security_query_error'] = error.winerror
                report['observation_errors'].append({'reference': observation['reference'],
                                                     'operation': 'security', 'winerror': error.winerror})
            if 'case_query_error' in observation:
                report['observation_errors'].append({'reference': observation['reference'],
                                                     'operation': 'case-sensitivity',
                                                     'winerror': observation['case_query_error']})
            stat = observation['stat']
            if not stat['reparse'] or observation['reparse']['tag'] == REPARSE_TAG_WOF:
                observation['streams'] = api.streams(path)
                for stream in observation['streams']:
                    size = int(stream['size'])
                    if size > args.max_stream_bytes:
                        raise ValueError('Stream exceeds --max-stream-bytes')
                    key = (observation['reference'], tuple(stream['name_utf16']))
                    payload = payload_name(key[0], key[1])
                    if key not in copied:
                        suffix = ':' + units_text(key[1]) + ':$DATA' if key[1] else ''
                        copied[key] = api.copy(str(path) + suffix, output / payload, size)
                    stream.update({'sha256': copied[key], 'payload': payload})
            else:
                # Avoid link traversal, cloud hydration and unknown filter I/O.
                observation['content_contract'] = 'provider-required'
            if stat['directory'] and not stat['reparse']:
                children = []
                with os.scandir(path) as iterator:
                    for child in iterator:
                        if len(report['entries']) + len(pending) + len(children) + 1 >= args.max_entries:
                            raise ValueError('Directory children exceed --max-entries')
                        children.append(Path(child.path))
                children.sort(key=lambda child: utf16_units(child.name))
                observation['children_complete'] = True
                pending.extend(reversed(children))
            report['entries'].append(observation)
        if api.volume(root) != {key: value for key, value in volume.items() if key != 'root_reference'}:
            raise ValueError('Native volume geometry changed during collection')
        image = output / 'volume.img'
        checksum = api.copy('\\\\.\\' + root[:2], image, int(volume['size_bytes']),
                            volume_sector_bytes=volume['sector_size'])
        report['image'] = {'file': image.name, 'size': str(image.stat().st_size), 'sha256': checksum}
        report['raw_volume_io'] = {'extended_dasd_read': True, 'write_access': False,
                                  'declared_bytes': volume['size_bytes']}
        report['acquisition_status'] = 'partial' if report['observation_errors'] else 'complete'
    except BaseException:
        report['acquisition_status'] = 'failed'
        raise
    finally:
        manifest.write_text(json.dumps(report, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--volume', required=True, help='Read-only NTFS drive root, for example R:\\')
    parser.add_argument('--tree', default='corpus', help='Test tree relative to the volume root')
    parser.add_argument('--output', required=True, type=Path, help='New directory on another volume')
    parser.add_argument('--max-image-bytes', type=int, default=DEFAULT_IMAGE_LIMIT)
    parser.add_argument('--max-stream-bytes', type=int, default=DEFAULT_STREAM_LIMIT)
    parser.add_argument('--max-entries', type=int, default=DEFAULT_ENTRY_LIMIT)
    args = parser.parse_args()
    if min(args.max_image_bytes, args.max_stream_bytes, args.max_entries) <= 0:
        parser.error('Acquisition budgets must be positive')
    report = collect(args)
    print(json.dumps({'status': report['acquisition_status'], 'entries': len(report['entries'])}))
    return 0 if report['acquisition_status'] == 'complete' else 1


if __name__ == '__main__':
    sys.exit(main())
