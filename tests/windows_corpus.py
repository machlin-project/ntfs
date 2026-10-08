#!/usr/bin/env python3
"""Verify a captured corpus through references/UTF-16 without mounting its image.

Reports keep unsupported operations as failures and preserve the declared corpus
provenance. Synthetic fixtures exercise this harness, not Windows qualification.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import sanitizer_environment

SCHEMA_VERSION = 1
MANIFEST_BYTE_LIMIT = 32 * 1024 * 1024
METADATA_BYTE_LIMIT = 32 * 1024 * 1024
ENTRY_LIMIT = 100000
NAME_UNITS_LIMIT = 255
STREAMS_PER_ENTRY_LIMIT = 65536
IO_BYTES = 1024 * 1024
TOOL_TIMEOUT_SECONDS = 120
FILETIME_EPOCH = 116444736000000000
FILETIME_TICKS_PER_SECOND = 10000000
NANOSECONDS_PER_FILETIME_TICK = 100
U64_MAX = (1 << 64) - 1
FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_SYSTEM = 0x00000004
FILE_ATTRIBUTE_ARCHIVE = 0x00000020
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
SI_PRESENTATION_ATTRIBUTES = (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN |
                              FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE |
                              FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
NAMESPACE_DOS = 2
FILE_CS_FLAG_CASE_SENSITIVE_DIR = 0x00000001
REFERENCE = re.compile(r'[0-9a-f]{16}')
DECIMAL = re.compile(r'0|[1-9][0-9]*')
SHA256 = re.compile(r'[0-9a-f]{64}')


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for data in iter(lambda: source.read(IO_BYTES), b''):
            digest.update(data)
    return digest.hexdigest()


def contained_file(directory, name):
    if not isinstance(name, str):
        raise ValueError('Artifact name must be a string')
    relative = Path(name)
    if relative.is_absolute() or not relative.parts or '..' in relative.parts:
        raise ValueError('Artifact name must be a contained relative path')
    path = (directory / relative).resolve(strict=True)
    if not path.is_relative_to(directory.resolve()) or not path.is_file():
        raise ValueError('Artifact escapes the corpus or is not a regular file')
    return path


def units(value, allow_empty=True):
    if (not isinstance(value, list) or len(value) > NAME_UNITS_LIMIT or
            (not allow_empty and not value) or
            any(type(unit) is not int or not 0 <= unit <= 0xffff for unit in value)):
        raise ValueError('Invalid UTF-16 code-unit array')
    return tuple(value)


def reference(value):
    if not isinstance(value, str) or REFERENCE.fullmatch(value) is None or int(value, 16) >> 48 == 0:
        raise ValueError('Invalid sequence-bearing file reference')
    return value


def size_value(value):
    if not isinstance(value, str) or DECIMAL.fullmatch(value) is None or int(value) > U64_MAX:
        raise ValueError('Invalid unsigned size')
    return int(value)


def validate_manifest(path):
    if path.stat().st_size > MANIFEST_BYTE_LIMIT:
        raise ValueError('Manifest exceeds the validator byte budget')
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('schema_version') != SCHEMA_VERSION or data.get('acquisition_status') not in ('complete', 'partial'):
        raise ValueError('Unsupported or incomplete acquisition manifest')
    if not isinstance(data.get('provenance'), str) or not data['provenance']:
        raise ValueError('Missing corpus provenance')
    reference(data['volume']['root_reference'])
    if not isinstance(data.get('entries'), list) or not 0 < len(data['entries']) <= ENTRY_LIMIT:
        raise ValueError('Invalid corpus entry count')
    image = contained_file(path.parent, data['image']['file'])
    if image.stat().st_size != size_value(data['image']['size']) or SHA256.fullmatch(data['image']['sha256']) is None:
        raise ValueError('Invalid image identity')
    paths = set()
    for entry in data['entries']:
        reference(entry['reference'])
        name = units(entry['name_utf16'])
        components = entry['path_utf16']
        if not isinstance(components, list):
            raise ValueError('Invalid component path')
        key = tuple(units(component, False) for component in components)
        if key in paths or (key and key[-1] != name) or (not key and name):
            raise ValueError('Duplicate path or inconsistent stored name')
        paths.add(key)
        if key:
            reference(entry['parent_reference'])
        stat = entry['stat']
        if any(type(stat[field]) is not bool for field in ('directory', 'reparse')):
            raise ValueError('Invalid object-kind observation')
        if 'case_sensitive' in entry or 'case_flags' in entry:
            if (not stat['directory'] or stat['reparse'] or
                    type(entry.get('case_sensitive')) is not bool or
                    type(entry.get('case_flags')) is not int or
                    not 0 <= entry['case_flags'] <= 0xffffffff or
                    entry['case_sensitive'] != bool(entry['case_flags'] & FILE_CS_FLAG_CASE_SENSITIVE_DIR)):
                raise ValueError('Invalid native directory case-policy observation')
        size_value(stat['size'])
        if type(stat['links']) is not int or not 0 <= stat['links'] <= U64_MAX:
            raise ValueError('Invalid link count')
        streams = entry.get('streams', [])
        if not isinstance(streams, list) or len(streams) > STREAMS_PER_ENTRY_LIMIT:
            raise ValueError('Invalid stream count')
        seen = set()
        for stream in streams:
            stream_name = units(stream['name_utf16'])
            if stream_name in seen:
                raise ValueError('Duplicate named stream')
            seen.add(stream_name)
            payload = contained_file(path.parent, stream['payload'])
            if payload.stat().st_size != size_value(stream['size']) or SHA256.fullmatch(stream['sha256']) is None:
                raise ValueError('Invalid expected stream identity')
    return data, image


def tool(reader, image, command, *arguments, content_bytes=None):
    """Drain bounded output with a deadline; retain no full file-data response."""
    argv = [str(reader), str(image), command, *arguments]
    deadline = time.monotonic() + TOOL_TIMEOUT_SECONDS
    limit = METADATA_BYTE_LIMIT if content_bytes is None else content_bytes
    data, digest, count = bytearray(), hashlib.sha256(), 0
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=errors,
                                   cwd=ROOT, env=sanitizer_environment())
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError(f'{command} exceeded the operation deadline')
                    ready = selector.select(remaining)
                    if not ready:
                        raise TimeoutError(f'{command} exceeded the operation deadline')
                    for key, _ in ready:
                        chunk = os.read(key.fileobj.fileno(), IO_BYTES)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        count += len(chunk)
                        if count > limit:
                            raise ValueError(f'{command} exceeded its expected output budget')
                        if content_bytes is None:
                            data.extend(chunk)
                        else:
                            digest.update(chunk)
            process.wait(timeout=max(0, deadline - time.monotonic()))
            errors.seek(0)
            diagnostic = errors.read(IO_BYTES).decode('utf-8', errors='replace').strip()
            if process.returncode != 0:
                raise RuntimeError(f'{command}: {diagnostic or "tool failure"}')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
    if content_bytes is not None:
        if count != content_bytes:
            raise ValueError(f'{command} returned {count} bytes, expected {content_bytes}')
        return digest.hexdigest()
    return bytes(data)


def decoded_json(data):
    return json.loads(data.decode('utf-8'))


def verify(manifest_path, reader, report_path):
    manifest, image = validate_manifest(manifest_path)
    expected_hash = manifest['image']['sha256']
    report = {'status': 'running', 'corpus_provenance': manifest['provenance'],
              'acquisition_status': manifest['acquisition_status'], 'checks': [],
              'scope': ['volume geometry', 'file references and stat', 'directory names and lookups',
                        'directory case policy', 'stream bytes', 'reparse metadata', 'read-only image identity'],
              'remaining_contracts': ['security descriptors and ACL enforcement',
                                      'native FSKit mount'],
              'missing_case_observations': [entry['reference'] for entry in manifest['entries']
                  if entry['stat']['directory'] and not entry['stat']['reparse'] and 'case_sensitive' not in entry]}
    report_path.parent.mkdir(parents=True, exist_ok=True)
    if report['missing_case_observations']:
        report['remaining_contracts'].append('unobserved directory case policies')

    def check(operation, subject, action):
        try:
            action()
            report['checks'].append({'operation': operation, 'subject': subject, 'status': 'pass'})
        except (ValueError, RuntimeError, OSError, TimeoutError, subprocess.TimeoutExpired) as error:
            report['checks'].append({'operation': operation, 'subject': subject,
                                     'status': 'fail', 'error': str(error)})

    def equal(actual, expected):
        if actual != expected:
            raise ValueError(f'Expected {expected!r}, observed {actual!r}')

    try:
        equal(file_hash(image), expected_hash)
        info = decoded_json(tool(reader, image, 'info-json'))
        for field in ('serial', 'size_bytes', 'sector_size', 'cluster_size', 'record_size', 'root_reference'):
            if field in manifest['volume']:
                check('volume-' + field, 'volume',
                      lambda field=field: equal(info[field], manifest['volume'][field]))
        children = defaultdict(list)
        for entry in manifest['entries']:
            if entry['parent_reference'] is not None:
                children[entry['parent_reference']].append(entry)
        checked_payloads = {}
        for entry in manifest['entries']:
            ref, expected = entry['reference'], entry['stat']

            def stat_check():
                actual = decoded_json(tool(reader, image, 'stat-ref', ref))
                for field in ('directory', 'reparse', 'links'):
                    equal(actual[field], expected[field])
                equal(actual['reference'], ref)
                equal(actual['file_attributes'] & SI_PRESENTATION_ATTRIBUTES,
                      expected['file_attributes'] & SI_PRESENTATION_ATTRIBUTES)
                if not expected['directory'] and not expected['reparse']:
                    equal(actual['size'], expected['size'])
                for field in ('created', 'modified', 'changed', 'accessed'):
                    if field + '_ticks' in expected:
                        ticks = int(expected[field + '_ticks']) - FILETIME_EPOCH
                        seconds, remainder = divmod(ticks, FILETIME_TICKS_PER_SECOND)
                        equal(actual[field], {'seconds': str(seconds),
                                              'nanoseconds': remainder * NANOSECONDS_PER_FILETIME_TICK})

            check('stat', ref, stat_check)
            if 'case_sensitive' in entry:
                def case_check():
                    if entry['case_flags'] & ~FILE_CS_FLAG_CASE_SENSITIVE_DIR:
                        raise ValueError('Unsupported native case-policy flags')
                    actual = decoded_json(tool(reader, image, 'stat-ref', ref))
                    equal(actual['case_sensitive'], entry['case_sensitive'])

                check('directory-case-policy', ref, case_check)
            if entry['parent_reference'] is not None:
                name_hex = ''.join(f'{unit:04x}' for unit in entry['name_utf16'])

                def lookup_check():
                    actual = decoded_json(tool(reader, image, 'lookup-ref', entry['parent_reference'], name_hex))
                    equal(actual['reference'], ref)
                    equal(actual['name_utf16'], entry['name_utf16'])
                    equal(actual['parent_reference'], entry['parent_reference'])

                check('lookup-stored-name', {'reference': ref, 'name_utf16': entry['name_utf16']}, lookup_check)
            if entry.get('children_complete'):

                def directory_check():
                    actual = [decoded_json(line) for line in tool(reader, image, 'ls-ref', ref).splitlines()]
                    actual_keys = [(child['reference'], tuple(child['name_utf16'])) for child in actual
                                   if child['namespace'] != NAMESPACE_DOS and
                                   child['name_utf16'] != [ord('.')]]
                    expected_keys = [(child['reference'], tuple(child['name_utf16'])) for child in children[ref]]
                    equal(sorted(actual_keys), sorted(expected_keys))
                    for child in actual:
                        equal(child['parent_reference'], ref)

                check('directory-completeness', ref, directory_check)
            if 'reparse' in entry:

                def reparse_check():
                    actual = decoded_json(tool(reader, image, 'reparse-ref', ref))
                    for field in ('tag', 'flags', 'substitute_utf16', 'print_utf16'):
                        if field in entry['reparse']:
                            equal(actual[field], entry['reparse'][field])

                check('reparse-metadata', ref, reparse_check)
            for stream in entry.get('streams', []):
                key = (ref, tuple(stream['name_utf16']))
                identity = (stream['size'], stream['sha256'], stream['payload'])
                if key in checked_payloads:
                    check('hard-link-stream-consistency', {'reference': ref, 'name_utf16': stream['name_utf16']},
                          lambda: equal(identity, checked_payloads[key]))
                    continue
                checked_payloads[key] = identity

                def stream_check():
                    payload = contained_file(manifest_path.parent, stream['payload'])
                    equal(file_hash(payload), stream['sha256'])
                    stream_hex = ''.join(f'{unit:04x}' for unit in stream['name_utf16'])
                    equal(tool(reader, image, 'cat-ref', ref, stream_hex,
                               content_bytes=int(stream['size'])), stream['sha256'])

                check('stream-bytes', {'reference': ref, 'name_utf16': stream['name_utf16']}, stream_check)
        check('image-unchanged', 'volume', lambda: equal(file_hash(image), expected_hash))
        if any(check['status'] == 'fail' for check in report['checks']):
            report['status'] = 'fail'
        else:
            report['status'] = 'pass' if manifest['acquisition_status'] == 'complete' else 'partial'
    except (ValueError, RuntimeError, OSError, TimeoutError, subprocess.TimeoutExpired) as error:
        report['status'] = 'fail'
        report['error'] = str(error)
    finally:
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--reader', type=Path, default=ROOT / '.build/ntfs-inspect')
    parser.add_argument('--report', type=Path, default=ROOT / 'artifacts/windows-corpus/report.json')
    args = parser.parse_args()
    report = verify(args.manifest.resolve(), args.reader.resolve(), args.report.resolve())
    counts = {status: sum(check['status'] == status for check in report['checks']) for status in ('pass', 'fail')}
    print(json.dumps({'status': report['status'], 'checks': counts,
                      'corpus_provenance': report['corpus_provenance']}))
    return 0 if report['status'] == 'pass' else 1


if __name__ == '__main__':
    sys.exit(main())
