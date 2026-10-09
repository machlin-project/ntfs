#!/usr/bin/env python3
"""Observe native metadata on the wrapper's exact fresh copied scratch volume.

Native API contracts and acquired bytes are retained separately from any later
SI/FILE_NAME/I30 cache interpretation. No policy or privilege setting is changed.
"""
import argparse
from contextlib import contextmanager
import ctypes as ct
import hashlib
import json
import os
from pathlib import Path
import re

from collect_windows_corpus import (WindowsAPI, DWORD, HANDLE, BOOL, FileTime,
    FileInformation, BasicInformation, VolumeInformation, FILE_BASIC_INFO_CLASS,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    GENERIC_READ, FSCTL_GET_NTFS_VOLUME_DATA, FILE_READ_ONLY_VOLUME)

FILE_WRITE_ATTRIBUTES = 0x0100
FILE_ATTRIBUTE_READONLY = 0x0001
FILE_ATTRIBUTE_HIDDEN = 0x0002
FILE_ATTRIBUTE_SYSTEM = 0x0004
FILE_ATTRIBUTE_ARCHIVE = 0x0020
FILE_ATTRIBUTE_NORMAL = 0x0080
FSCTL_GET_NTFS_FILE_RECORD = (9 << 16) | (26 << 2)
REFERENCE_RECORD_BITS = 48
REFERENCE_RECORD_MASK = (1 << REFERENCE_RECORD_BITS) - 1


class FileRecordOutput(ct.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('reference', ct.c_uint64), ('length', DWORD)]


class FileHeader(ct.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('magic', ct.c_uint8 * 4), ('usa_offset', ct.c_uint16),
                ('usa_count', ct.c_uint16), ('lsn', ct.c_uint64),
                ('sequence', ct.c_uint16), ('links', ct.c_uint16),
                ('attributes_offset', ct.c_uint16), ('flags', ct.c_uint16),
                ('used_bytes', DWORD), ('allocated_bytes', DWORD),
                ('base_reference', ct.c_uint64), ('next_attribute', ct.c_uint16),
                ('reserved', ct.c_uint16), ('record_number', DWORD)]


RECORD_OUTPUT_BYTES = ct.sizeof(FileRecordOutput)
FILE_SEQUENCE_OFFSET = FileHeader.sequence.offset
FILE_FLAGS_OFFSET = FileHeader.flags.offset
FILE_BASE_REFERENCE_OFFSET = FileHeader.base_reference.offset
FILE_NUMBER_OFFSET = FileHeader.record_number.offset
FILE_RECORD_IN_USE = 1
PROBE_SECTOR_BYTES = 512
PROBE_CLUSTER_BYTES = 4096
PROBE_RECORD_BYTES = 1024
PAYLOAD = b'Machlin native metadata observation\r\n'
CREATED = 132539328123456789
ACCESSED = 132626592234567890
MODIFIED = 132713856345678901
DOS_ATTRIBUTES = (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN |
                  FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE)
PHASES = ('initialize', 'times', 'dos-flags', 'normal')
SOURCES = [
    'https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime',
    'https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileattributesw',
    'https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times',
    'https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_ntfs_file_record',
    'https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-ntfs_file_record_output_buffer']


def records_before_path_handles(read_records, read_held_handle, read_path_handles, include_paths):
    read_records()
    read_held_handle()
    if include_paths:
        read_path_handles()


def observe_mutation_handle(open_handle, verify_handle, mutate, snapshot):
    with open_handle() as handle:
        verify_handle(handle)
        snapshot('before-api-handle-open', handle, True)
        mutate(handle)
        snapshot('after-api-handle-open', handle, True)
        snapshot('after-observer-close-handle-open', handle, False)
    snapshot('after-handle-close', None, True)


def verify_record(reference, raw, record_bytes):
    if (type(reference) is not int or not 0 < reference < 1 << 64 or
            reference >> REFERENCE_RECORD_BITS == 0 or record_bytes != PROBE_RECORD_BYTES or
            len(raw) < RECORD_OUTPUT_BYTES):
        raise ValueError('Truncated native record output')
    output = FileRecordOutput.from_buffer_copy(raw[:RECORD_OUTPUT_BYTES])
    returned, length = output.reference, output.length
    ordinal, sequence = reference & REFERENCE_RECORD_MASK, reference >> REFERENCE_RECORD_BITS
    if (length != record_bytes or len(raw) < RECORD_OUTPUT_BYTES + length or
            len(raw) > RECORD_OUTPUT_BYTES + length + ct.sizeof(DWORD) or
            returned & REFERENCE_RECORD_MASK != ordinal or
            returned >> REFERENCE_RECORD_BITS not in (0, sequence)):
        raise ValueError('Native record output did not return the exact requested identity')
    record = raw[RECORD_OUTPUT_BYTES:RECORD_OUTPUT_BYTES + length]
    if len(record) < ct.sizeof(FileHeader):
        raise ValueError('Truncated native FILE header')
    header = FileHeader.from_buffer_copy(record[:ct.sizeof(FileHeader)])
    if (bytes(header.magic) != b'FILE' or header.sequence != sequence or
            not header.flags & FILE_RECORD_IN_USE or header.base_reference != 0 or
            header.record_number != ordinal):
        raise ValueError('Native FILE header number/sequence does not bind the exact Win32 file ID')
    return {'requested_reference': f'{reference:016x}', 'returned_reference': f'{returned:016x}',
            'record_number': str(ordinal), 'sequence': sequence, 'record_bytes': length}


class ProbeAPI(WindowsAPI):
    def __init__(self, baseline):
        super().__init__()
        self.baseline = baseline
        self._declare(self.kernel.GetVolumeNameForVolumeMountPointW, BOOL,
                      [ct.c_wchar_p, ct.c_wchar_p, DWORD])
        self._declare(self.kernel.CreateHardLinkW, BOOL, [ct.c_wchar_p, ct.c_wchar_p, HANDLE])
        self._declare(self.kernel.SetFileTime, BOOL,
                      [HANDLE, ct.POINTER(FileTime), ct.POINTER(FileTime), ct.POINTER(FileTime)])
        self._declare(self.kernel.SetFileAttributesW, BOOL, [ct.c_wchar_p, DWORD])

    @contextmanager
    def open(self, path, access=FILE_READ_ATTRIBUTES):
        handle = self.kernel.CreateFileW(str(path), access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, None, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None)
        if handle == self.invalid_handle:
            raise self.error()
        try:
            yield handle
        finally:
            if not self.kernel.CloseHandle(handle):
                raise self.error()

    def guard(self):
        identity = ct.create_unicode_buffer(261)
        if not self.kernel.GetVolumeNameForVolumeMountPointW('R:\\', identity, len(identity)):
            raise self.error()
        if identity.value.casefold() != self.baseline['volume']['UniqueId'].casefold():
            raise ValueError('Scratch volume GUID changed')
        flags, serial, component = DWORD(), DWORD(), DWORD()
        label, filesystem = ct.create_unicode_buffer(261), ct.create_unicode_buffer(261)
        if not self.kernel.GetVolumeInformationW('R:\\', label, len(label), ct.byref(serial),
                ct.byref(component), ct.byref(flags), filesystem, len(filesystem)):
            raise self.error()
        if filesystem.value != 'NTFS' or label.value != 'MachlinCloudNTFS' or flags.value & FILE_READ_ONLY_VOLUME:
            raise ValueError('Scratch volume is not the admitted writable NTFS copy')
        with self.open('\\\\.\\R:', GENERIC_READ) as handle:
            data, returned = VolumeInformation(), DWORD()
            if not self.kernel.DeviceIoControl(handle, FSCTL_GET_NTFS_VOLUME_DATA, None, 0,
                    ct.byref(data), ct.sizeof(data), ct.byref(returned), None):
                raise self.error()
        expected = self.baseline['native_volume']
        actual = {'serial': f'{data.serial:016x}', 'size_bytes': str(data.sectors * data.sector_bytes),
                  'sector_size': data.sector_bytes, 'cluster_size': data.cluster_bytes,
                  'record_size': data.record_bytes}
        if returned.value < ct.sizeof(data) or any(actual[key] != expected[key] for key in actual):
            raise ValueError('Scratch native volume serial or geometry changed')
        if ((data.sector_bytes, data.cluster_bytes, data.record_bytes) !=
                (PROBE_SECTOR_BYTES, PROBE_CLUSTER_BYTES, PROBE_RECORD_BYTES) or
                not 0 < data.sectors * data.sector_bytes <= self.baseline['partition']['Size']):
            raise ValueError('Scratch volume exceeds the bounded observation profile')
        return actual

    def basic(self, handle):
        info, basic = FileInformation(), BasicInformation()
        if not self.kernel.GetFileInformationByHandle(handle, ct.byref(info)):
            raise self.error()
        if not self.kernel.GetFileInformationByHandleEx(handle, FILE_BASIC_INFO_CLASS,
                ct.byref(basic), ct.sizeof(basic)):
            raise self.error()
        return {'reference': f'{(info.index_high << 32) | info.index_low:016x}',
                'created_ticks': str(basic.created), 'accessed_ticks': str(basic.accessed),
                'modified_ticks': str(basic.modified), 'changed_ticks': str(basic.changed),
                'file_attributes': basic.attributes, 'links': info.links}

    def record(self, reference, record_bytes):
        wanted = ct.c_int64(reference & REFERENCE_RECORD_MASK)
        buffer = ct.create_string_buffer(RECORD_OUTPUT_BYTES + record_bytes + ct.sizeof(DWORD))
        returned = DWORD()
        with self.open('\\\\.\\R:', GENERIC_READ) as handle:
            if not self.kernel.DeviceIoControl(handle, FSCTL_GET_NTFS_FILE_RECORD,
                    ct.byref(wanted), ct.sizeof(wanted), buffer, len(buffer), ct.byref(returned), None):
                raise self.error()
        if returned.value > len(buffer):
            raise ValueError('Native record acquisition exceeded its buffer')
        return buffer.raw[:returned.value]


def run(args):
    baseline = json.loads(args.bootstrap.read_text(encoding='utf-8-sig'))
    if (baseline['acquisition_status'] != 'complete' or not baseline['vhd']['detached'] or
            not re.fullmatch(r'MachlinCloudNTFS-[0-9a-f]{32}', baseline['root_name'])):
        raise ValueError('A complete immutable native bootstrap is required')
    corpus_path = args.bootstrap.parent / baseline['corpus']['file']
    if hashlib.sha256(corpus_path.read_bytes()).hexdigest() != baseline['corpus']['sha256']:
        raise ValueError('Original native geometry manifest changed')
    baseline['native_volume'] = json.loads(corpus_path.read_text())['volume']
    output = args.output.resolve()
    temporary = Path(os.environ['RUNNER_TEMP']).resolve()
    if (not output.is_relative_to(temporary) or output.drive.casefold() == 'r:' or
            not re.fullmatch(r'MachlinNTFSMetadata-[A-Za-z0-9-]{1,64}', output.relative_to(temporary).parts[0])):
        raise ValueError('Output must stay in the wrapper scratch directory on another volume')
    task = temporary / output.relative_to(temporary).parts[0]
    if (args.bootstrap.resolve() != task / 'MachlinNTFSCloud-baseline' / 'bootstrap.json' or
            args.identities.resolve() != task / 'evidence' / 'object-identities.json' or
            output != task / 'evidence' / args.phase / 'live'):
        raise ValueError('Inputs and outputs must use the exact wrapper-owned task layout')
    output.mkdir(parents=True, exist_ok=False)
    api = ProbeAPI(baseline)
    root = Path('R:/') / baseline['root_name']
    scope = root / 'metadata-observation'
    paths = {'parent_a': scope / 'first-parent', 'parent_b': scope / 'second-parent',
             'link_a': scope / 'first-parent' / 'long-primary-metadata-name.txt',
             'link_b': scope / 'second-parent' / 'long-secondary-metadata-name.txt'}
    report = {'schema_version': 2, 'status': 'running', 'phase': args.phase,
              'provenance': 'Windows native metadata APIs on a guarded copied scratch VHD',
              'cache_semantics_qualified': False, 'primary_sources': SOURCES,
              'snapshots': [], 'operations': [], 'errors': []}
    manifest = output / 'report.json'
    def save():
        manifest.write_text(json.dumps(report, indent=2) + '\n')
    def guard(identities=None):
        geometry = api.guard()
        for path in (Path('R:/'), root):
            if api.metadata(path)['stat']['reparse']:
                raise ValueError('Scratch scope has a reparse ancestor')
        if identities is not None:
            if api.metadata(scope)['stat']['reparse']:
                raise ValueError('Observation scope became a reparse point')
            for key, path in paths.items():
                data = api.metadata(path)
                if data['stat']['reparse'] or data['reference'] != identities[key]:
                    raise ValueError('Observation path identity changed')
        return geometry
    def snapshot(name, identities, held=None, include_paths=True):
        # Mutation identity admission remains in guard(identities), immediately
        # before the mutation. Observation uses only those already verified IDs
        # until all raw records have been retained; no fresh path handle comes first.
        geometry = api.guard()
        directory = output / name
        directory.mkdir()
        row = {'name': name, 'metadata': {}, 'records': {},
               'observation_order': ['exact-id-raw-records', 'held-handle-basic'],
               'new_path_observers': include_paths}
        if include_paths:
            row['observation_order'].append('path-basic-handles-open-query-close')
        report['snapshots'].append(row)
        def read_records():
            for key in ('link_a', 'parent_a', 'parent_b'):
                reference = int(identities[key], 16)
                raw = api.record(reference, geometry['record_size'])
                filename = key + '.fsctl-output.bin'
                (directory / filename).write_bytes(raw)
                row['records'][key] = dict(file=filename, sha256=hashlib.sha256(raw).hexdigest(),
                                           requested_reference=identities[key], identity_verified=False)
                save()
                row['records'][key].update(verify_record(reference, raw, geometry['record_size']),
                                           identity_verified=True)
        def read_held_handle():
            if held is not None:
                row['held_handle'] = api.basic(held)
        def read_path_handles():
            for key, path in paths.items():
                with api.open(path) as handle:
                    row['metadata'][key] = api.basic(handle)
                    if row['metadata'][key]['reference'] != identities[key]:
                        raise ValueError('Path observer identity changed')
        records_before_path_handles(read_records, read_held_handle, read_path_handles, include_paths)
        save()
        return row
    save()
    try:
        guard()
        if args.phase == 'initialize':
            if args.identities.exists():
                raise ValueError('Do not replace an observation identity manifest')
            for path in (scope, paths['parent_a'], paths['parent_b']):
                guard()
                path.mkdir()
            guard()
            with paths['link_a'].open('xb') as stream:
                stream.write(PAYLOAD)
                stream.flush()
                os.fsync(stream.fileno())
            guard()
            if not api.kernel.CreateHardLinkW(str(paths['link_b']), str(paths['link_a']), None):
                raise api.error()
            identities = {key: api.metadata(path)['reference'] for key, path in paths.items()}
            if identities['link_a'] != identities['link_b'] or api.metadata(paths['link_a'])['stat']['links'] != 2:
                raise ValueError('Native two-link identity was not established')
            with args.identities.open('x') as stream:
                json.dump(identities, stream, indent=2)
                stream.write('\n')
            snapshot('initialized-closed', identities)
        else:
            identities = json.loads(args.identities.read_text())
            if set(identities) != set(paths):
                raise ValueError('Unexpected observation identity set')
            guard(identities)
            key = 'link_a' if args.phase == 'times' else 'link_b'
            def verify_handle(handle):
                if api.basic(handle)['reference'] != identities[key]:
                    raise ValueError('Mutation handle identity changed')
            def mutate(handle):
                guard(identities)
                if args.phase == 'times':
                    times = [FileTime(value & 0xffffffff, value >> 32) for value in (CREATED, ACCESSED, MODIFIED)]
                    if not api.kernel.SetFileTime(handle, *(ct.byref(value) for value in times)):
                        raise api.error()
                    report['operations'].append({'api': 'SetFileTime', 'path': key,
                        'requested': {'created_ticks': str(CREATED), 'accessed_ticks': str(ACCESSED),
                                      'modified_ticks': str(MODIFIED)}})
                else:
                    attributes = DOS_ATTRIBUTES if args.phase == 'dos-flags' else FILE_ATTRIBUTE_NORMAL
                    if not api.kernel.SetFileAttributesW(str(paths[key]), attributes):
                        raise api.error()
                    report['operations'].append({'api': 'SetFileAttributesW', 'path': key,
                        'requested_attributes': attributes,
                        'held_handle_role': 'additional attributes handle; path API owns its internal handle'})
            observe_mutation_handle(
                lambda: api.open(paths[key], FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES),
                verify_handle, mutate,
                lambda name, handle, include_paths: snapshot(name, identities, handle, include_paths))
        guard(identities)
        report['status'] = 'complete'
    except BaseException as error:
        report['status'] = 'failed'
        report['errors'].append(f'{type(error).__name__}: {error}')
        raise
    finally:
        save()
    print(json.dumps({'status': report['status'], 'phase': args.phase, 'snapshots': len(report['snapshots'])}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap', type=Path, required=True)
    parser.add_argument('--identities', type=Path, required=True)
    parser.add_argument('--phase', choices=PHASES, required=True)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args())
