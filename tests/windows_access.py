#!/usr/bin/env python3
"""Compare original AccessCheck observations with the freestanding DACL evaluator.

Unrun/failed acquisition, unsupported core decisions and out-of-plane observations
remain visible. A synthetic provider can verify the harness, never Windows behavior.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import access_transport as wire
import collect_windows_access as collector
from bounded_tool import bounded_read, run_tool, DEFAULT_TIMEOUT_SECONDS

MANIFEST_BYTES_MAX = 16 * 1024 * 1024
CASES_MAX = 512
CONTEXTS_MAX = 16
REPORT_SECONDS_MAX = 120
ERROR_TEXT_BYTES_MAX = 4096
NTFS_LAST_RESULT = 15  # NTFS_BUSY, the last declared public result code.
SHA256 = re.compile(r'[0-9a-f]{64}')
IDENTIFIER = re.compile(r'[a-z][a-z0-9/-]{0,95}')
CORE_OUTPUT_FIELDS = {'schema_version', 'code', 'result', 'allowed', 'requested',
                      'granted', 'sid_comparisons'}


def identity(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError('Invalid observation identifier')
    return value


def unique_json(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError('Duplicate JSON field')
        data[key] = value
    return data


def decoded_json(data):
    return json.loads(data, object_pairs_hook=unique_json)


def validate_privileges(value):
    if not isinstance(value, list) or len(value) > collector.PRIVILEGES_MAX:
        raise ValueError('Invalid native privilege vector')
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {'luid_low', 'luid_high', 'attributes'}:
            raise ValueError('Invalid native privilege')
        wire.unsigned(entry['luid_low'])
        wire.unsigned(entry['attributes'])
        if type(entry['luid_high']) is not int or not -(1 << 31) <= entry['luid_high'] < (1 << 31):
            raise ValueError('Invalid native LUID high part')


def validate_context(context):
    identity(context['id'])
    wire.validate_token(context['token'])
    native = context['native']
    wire.group(native['user'])
    for name in ('groups', 'restricting'):
        if not isinstance(native[name], list) or len(native[name]) > wire.SID_COUNT_MAX:
            raise ValueError('Invalid original native SID vector')
        for entry in native[name]:
            wire.group(entry)
    validate_privileges(native['privileges'])
    projected = collector.projected_token(native['user'], native['groups'], native['restricting'],
                                          native['is_restricted'])
    if projected != context['token']:
        raise ValueError('Core token projection disagrees with original native fields')


def validate_observation(value):
    if not isinstance(value, dict) or set(value) != {'api_success', 'error', 'mapped', 'allowed',
                                                   'granted', 'privileges_used'}:
        raise ValueError('Invalid AccessCheck observation fields')
    wire.boolean(value['api_success'])
    wire.unsigned(value['error'])
    wire.unsigned(value['mapped'])
    if value['api_success']:
        if value['error'] != collector.ERROR_SUCCESS:
            raise ValueError('Successful AccessCheck contains an API error')
        wire.boolean(value['allowed'])
        wire.unsigned(value['granted'])
        validate_privileges(value['privileges_used'])
        if not value['allowed'] and value['granted'] != 0:
            raise ValueError('A native denial contains a partial grant')
    elif (value['error'] == collector.ERROR_SUCCESS or value['allowed'] is not None or
          value['granted'] is not None or value['privileges_used'] is not None):
        raise ValueError('API failure must retain an error and no access-decision outputs')


def validate_manifest(path):
    path = Path(path)
    raw = bounded_read(path, MANIFEST_BYTES_MAX)
    data = decoded_json(raw)
    if (not isinstance(data, dict) or type(data.get('schema_version')) is not int or
            data['schema_version'] != wire.SCHEMA_VERSION or
            data.get('vector_set') not in (collector.LEGACY_VECTOR_SET, collector.VECTOR_SET) or
            data.get('acquisition_status') not in ('complete', 'partial') or
            data.get('provenance') not in (collector.NATIVE_PROVENANCE, collector.SYNTHETIC_PROVENANCE) or
            data.get('context_plan') != list(collector.CONTEXT_IDS)):
        raise ValueError('Unsupported access observation manifest')
    contexts, cases, errors = data['contexts'], data['cases'], data['errors']
    if not isinstance(contexts, list) or len(contexts) > CONTEXTS_MAX:
        raise ValueError('Access context count exceeds the budget')
    if not isinstance(cases, list) or len(cases) > CASES_MAX:
        raise ValueError('Access observation count exceeds the budget')
    if not isinstance(errors, list) or len(errors) > CASES_MAX:
        raise ValueError('Invalid acquisition error list')
    for error in errors:
        identity(error['context'])
        if not isinstance(error['error'], str) or not error['error'] or len(error['error']) > ERROR_TEXT_BYTES_MAX:
            raise ValueError('Invalid acquisition error')
    for name in ('probe_group', 'probe_owner_group'):
        if data[name] is not None:
            wire.sid_packet(data[name])
    context_map, planned, seen = {}, {}, set()
    for context in contexts:
        validate_context(context)
        name = context['id']
        if name in context_map or name not in collector.CONTEXT_IDS:
            raise ValueError('Duplicate or unexpected access context')
        context_map[name] = context
        for vector in collector.vectors(context['token'], data['probe_group'], data['probe_owner_group'],
                                        vector_set=data['vector_set']):
            planned[name + '/' + vector['name']] = vector
    if 'base' in context_map:
        enabled = [entry for entry in context_map['base']['token']['groups']
                   if entry['attributes'] & wire.GROUP_ENABLED and
                   not entry['attributes'] & wire.GROUP_DENY_ONLY]
        probe = enabled[0]['sid'] if enabled else None
        owner = next((entry['sid'] for entry in enabled if entry['attributes'] & wire.GROUP_OWNER), None)
        if data['probe_group'] != probe or data['probe_owner_group'] != owner:
            raise ValueError('Probe SID selection disagrees with the original base token')
        user = context_map['base']['token']['user']
        constructions = {'base': ([], []), 'deny-user': ([user], []), 'deny-group': ([probe], []),
                         'restrict-user': ([], [user]), 'restrict-world': ([], [wire.WORLD]),
                         'restrict-duplicates': ([], [wire.WORLD, wire.WORLD])}
        for name, context in context_map.items():
            disabled, restricting = constructions[name]
            expected = {'source': 'caller-copy' if name == 'base' else 'base',
                        'flags': collector.DISABLE_MAX_PRIVILEGE,
                        'disable': disabled, 'restricting': restricting}
            if context.get('construction') != expected or (name == 'deny-group' and probe is None):
                raise ValueError('Token construction disagrees with its declared variant')
    elif context_map:
        raise ValueError('Token variants have no captured base context')
    platform = data['platform']
    if (not isinstance(platform, dict) or platform.get('pointer_bytes') not in (4, 8) or
            any(not isinstance(platform.get(name), str) or not platform[name] for name in
                ('system', 'version', 'machine')) or
            (data['provenance'] == collector.NATIVE_PROVENANCE and platform['system'] != 'Windows')):
        raise ValueError('Invalid acquisition platform or native provenance')
    for case in cases:
        name = identity(case['id'])
        if name in seen or name not in planned or case['context'] != name.split('/')[0]:
            raise ValueError('Duplicate or unexpected access observation')
        seen.add(name)
        expected = planned[name]
        wire.unsigned(case['desired'])
        if (case['desired'] != expected['desired'] or case['scope'] != expected['scope'] or
                not isinstance(case['descriptor_base64'], str) or
                len(case['descriptor_base64']) > ((wire.DESCRIPTOR_BYTES_MAX + 2) // 3) * 4 or
                not isinstance(case['descriptor_sha256'], str) or not SHA256.fullmatch(case['descriptor_sha256'])):
            raise ValueError('Observation vector disagrees with the acquisition plan')
        packet = base64.b64decode(case['descriptor_base64'], validate=True)
        if packet != expected['descriptor'] or hashlib.sha256(packet).hexdigest() != case['descriptor_sha256']:
            raise ValueError('Original descriptor hash or acquisition vector mismatch')
        validate_observation(case['native'])
    missing = sorted(set(planned) - seen)
    missing_contexts = sorted(set(collector.CONTEXT_IDS) - set(context_map))
    if data['acquisition_status'] == 'complete' and (errors or missing or missing_contexts):
        raise ValueError('Complete acquisition omits planned work or contains acquisition errors')
    return data, context_map, missing, missing_contexts, hashlib.sha256(raw).hexdigest()


def decision(data):
    value = decoded_json(data)
    if not isinstance(value, dict) or set(value) != CORE_OUTPUT_FIELDS:
        raise ValueError('Invalid core decision output')
    if type(value['schema_version']) is not int or value['schema_version'] != wire.SCHEMA_VERSION:
        raise ValueError('Unsupported core output schema')
    wire.unsigned(value['code'], NTFS_LAST_RESULT)
    wire.boolean(value['allowed'])
    for field in ('requested', 'granted', 'sid_comparisons'):
        wire.unsigned(value[field])
    if not isinstance(value['result'], str) or not value['result']:
        raise ValueError('Missing core result')
    if value['code'] != wire.NTFS_OK and any(value[field] for field in
                                            ('allowed', 'requested', 'granted', 'sid_comparisons')):
        raise ValueError('Core error contains a partial decision')
    if value['code'] == wire.NTFS_OK:
        requested, granted = value['requested'], value['granted']
        maximum = bool(requested & wire.MAXIMUM_ALLOWED)
        required = requested & ~wire.MAXIMUM_ALLOWED
        if (requested & ~(wire.FILE_ALL_ACCESS | wire.MAXIMUM_ALLOWED) or
                granted & ~wire.FILE_ALL_ACCESS or
                (not value['allowed'] and granted) or
                (value['allowed'] and (not granted or required & ~granted or
                                      (not maximum and granted != requested)))):
            raise ValueError('Core decision violates the exact or maximum-request contract')
    return value


def verify(path, evaluator, directory):
    if sys.platform == 'win32':
        raise RuntimeError('Offline core comparison uses a POSIX diagnostic build')
    data, contexts, missing, missing_contexts, before = validate_manifest(path)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    deadline = time.monotonic() + REPORT_SECONDS_MAX
    counts = {'passed': 0, 'failed': 0, 'unsupported': 0, 'oracle_errors': 0, 'out_of_plane': 0}
    report = {'schema_version': wire.SCHEMA_VERSION, 'provenance': data['provenance'],
              'manifest_sha256': before, 'acquisition_status': data['acquisition_status'],
              'missing_cases': missing, 'missing_contexts': missing_contexts,
              'acquisition_errors': data['errors'], 'counts': counts, 'cases': [],
              'native_dacl_vectors_verified': False, 'full_authorization_qualified': False}
    with tempfile.TemporaryDirectory(prefix='access-', dir=directory) as temporary:
        request = Path(temporary) / 'request.bin'
        for case in data['cases']:
            item = {'id': case['id'], 'scope': case['scope'], 'native': case['native']}
            report['cases'].append(item)
            native = case['native']
            if not native['api_success']:
                item['status'] = 'oracle_errors'
                item['error'] = f"AccessCheck API error {native['error']}"
            elif case['scope'] == 'boundary' or native['privileges_used']:
                item['status'] = 'out_of_plane'
                item['error'] = 'Mandatory-plane probe or native privilege use is outside the DACL comparison'
            else:
                try:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('Access comparison exceeded its aggregate deadline')
                    packet = base64.b64decode(case['descriptor_base64'], validate=True)
                    encoded = wire.request(contexts[case['context']]['token'], packet, case['desired'])
                    request.write_bytes(encoded)
                    core = decision(run_tool([str(evaluator), str(request)],
                                             timeout=min(remaining, DEFAULT_TIMEOUT_SECONDS)))
                    if bounded_read(request, wire.REQUEST_BYTES_MAX) != encoded:
                        raise ValueError('The diagnostic modified its original access request')
                    item['core'] = core
                    if core['code'] == wire.NTFS_UNSUPPORTED:
                        item['status'] = 'unsupported'
                    elif core['code'] != wire.NTFS_OK:
                        item['status'] = 'failed'
                    else:
                        equal = (core['requested'] == native['mapped'] and core['allowed'] == native['allowed'] and
                                 core['granted'] == native['granted'])
                        item['status'] = 'passed' if equal else 'failed'
                except (ValueError, RuntimeError, TimeoutError, OSError) as error:
                    item['status'], item['error'] = 'failed', str(error)
            counts[item['status']] += 1
    after = hashlib.sha256(bounded_read(path, MANIFEST_BYTES_MAX)).hexdigest()
    report['manifest_unchanged'] = before == after
    report['group_owner_vectors_present'] = data['probe_owner_group'] is not None
    dacl = [case for case in report['cases'] if case['scope'] != 'boundary']
    report['native_dacl_vectors_verified'] = (
        data['provenance'] == collector.NATIVE_PROVENANCE and data['acquisition_status'] == 'complete' and
        before == after and bool(dacl) and all(case['status'] == 'passed' for case in dacl))
    report['status'] = ('matched' if not missing and not missing_contexts and not data['errors'] and
                        before == after and data['acquisition_status'] == 'complete' and
                        counts['failed'] == counts['unsupported'] == counts['oracle_errors'] == counts['out_of_plane'] == 0
                        else 'gaps')
    report['native_dacl_gate_passed'] = native_dacl_gate(report)
    (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def native_dacl_gate(report):
    """All current DACL probes are implemented; mandatory-plane gaps remain."""
    return (report['native_dacl_vectors_verified'] and report['manifest_unchanged'] and
            report['acquisition_status'] == 'complete' and
            not report['missing_cases'] and not report['missing_contexts'] and
            not report['acquisition_errors'] and bool(report['cases']) and
            all(case['status'] == 'passed' or
                (case['scope'] == 'boundary' and case['status'] == 'out_of_plane')
                for case in report['cases']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--evaluator', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='New report directory')
    parser.add_argument('--require-native-dacl', action='store_true',
                        help='Gate native DACL agreement; retain declared probe/boundary gaps')
    args = parser.parse_args()
    try:
        report = verify(args.manifest, args.evaluator.resolve(strict=True), args.output)
    except (ValueError, KeyError, TypeError, OSError, RuntimeError) as error:
        raise SystemExit(f'Access comparison rejected: {error}') from error
    print(json.dumps({key: report[key] for key in ('status', 'counts', 'native_dacl_vectors_verified',
                                                  'full_authorization_qualified', 'native_dacl_gate_passed')}))
    if args.require_native_dacl:
        return 0 if report['native_dacl_gate_passed'] else 1
    return 0 if report['status'] == 'matched' else 1


if __name__ == '__main__':
    raise SystemExit(main())
