#!/usr/bin/env python3
"""Bind first Windows hard-link verdicts, original event XML and detached media.

This offline consumer performs no mount, recovery or retry. Native execution,
complete C/wire witness checks and postimage retention remain distinct evidence.
"""
from collections import Counter
from datetime import datetime
from pathlib import Path
import argparse
import hashlib
import json
import re
import uuid
import xml.etree.ElementTree as ET

MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_VHD_BYTES = 128 * 1024 * 1024
EVENT_FIELDS = ('FileName', 'FileReference', 'BufferOffset', 'TornStructureOffset',
                'BlockIndex', 'ExpectedSequenceNumber', 'ActualSequenceNumber')
PROVIDERS = ('Microsoft-Windows-Ntfs', 'Microsoft-Windows-Wininit', 'Microsoft-Windows-Chkdsk')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pairs(values):
    result = {}
    for name, value in values:
        require(name not in result, 'Duplicate JSON field')
        result[name] = value
    return result


def read(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_JSON_BYTES,
            'A bounded regular JSON report is required')
    return json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=pairs)


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def collector_encoding(path, expected_hash):
    original = path.read_bytes()
    lf = original.replace(b'\r\n', b'\n')
    require(b'\r' not in lf, 'Collector source has unsupported line endings')
    candidates = {'LF': lf, 'CRLF': lf.replace(b'\n', b'\r\n')}
    matched = [name for name, value in candidates.items()
               if hashlib.sha256(value).hexdigest() == expected_hash]
    require(len(matched) == 1, 'Collector revision differs under exact LF/CRLF Git checkout encodings')
    return dict(matchedEncoding=matched[0], nativeCollectorSha256=expected_hash,
                localSourceSha256=hashlib.sha256(original).hexdigest())


def native_id(query):
    require(query['exitCode'] == 0 and isinstance(query['output'], list), 'Native File ID query failed')
    match = re.search(r'0x([0-9a-fA-F]{32})\s*$', '\n'.join(query['output']))
    require(match is not None, 'Native File ID format differs')
    return int(match.group(1), 16)


def timestamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def data_key(data):
    require(all(isinstance(data.get(name), str) for name in EVENT_FIELDS), 'Incomplete torn event')
    return tuple(data[name] for name in EVENT_FIELDS)


def event_review(rows, product, case, complete):
    require(len(rows) == len(PROVIDERS), 'Missing native event provider')
    healthy, journal, metadata = [], [], []
    expected_journal = Counter((r'\$LogFile', '2', row['bufferOffset'], '0', row['blockIndex'],
                                row['expectedSequenceNumber'], row['actualSequenceNumber'])
                               for row in product['expectedTornLogPages'])
    expected_metadata = Counter(data_key(row) for row in product['expectedTornMetadataPages'])
    volume = case['volume']['UniqueId'].rstrip('\\').casefold()
    since = timestamp(case['mountStartedUtc'])
    for provider, row in zip(PROVIDERS, rows):
        require(row['provider'] == provider and row['exitCode'] == 0 and row['parsed'] is True,
                'Original native event query did not succeed')
        require(isinstance(row['output'], list) and all(isinstance(line, str) for line in row['output']),
                'Original event XML is missing')
        root = ET.fromstring('\n'.join(row['output']).replace('\x00', ''))
        events = root.findall('.//{*}Event')
        require(len(events) == row['count'] < 256 and len(row['observedEvents']) == len(events),
                'Original event count differs or reaches the bound')
        require(provider == PROVIDERS[0] or not events, 'Unexpected native repair-provider event')
        observed_healthy, observed_journal, observed_metadata = [], [], []
        for event, saved in zip(events, row['observedEvents']):
            system = event.find('{*}System')
            require(system is not None, 'Missing event system fields')
            event_provider = system.find('{*}Provider')
            created = system.find('{*}TimeCreated')
            require(event_provider is not None and event_provider.attrib['Name'] == provider and
                    created is not None and timestamp(created.attrib['SystemTime']) >= since,
                    'Original event identity or timestamp differs')
            identifier = int(system.findtext('{*}EventID'))
            level = int(system.findtext('{*}Level'))
            fields = pairs([(entry.attrib['Name'], entry.text or '')
                            for entry in event.findall('{*}EventData/{*}Data')])
            require(saved['eventId'] == identifier and saved['level'] == level and
                    saved['fields'] == fields and
                    timestamp(saved['systemTimeUtc']) == timestamp(created.attrib['SystemTime']),
                    'Parsed native event differs from original XML')
            require(identifier != 100, 'Native repair event observed')
            matching = (fields.get('DriveName', '').rstrip('\\').casefold() in ('r:', volume) or
                        fields.get('VolumeName', '').rstrip('\\').casefold() == volume)
            if identifier == 7:
                require(level == 3 and matching, 'Unattributed native torn-write event')
                key = data_key(fields)
                if fields['FileName'] == r'\$LogFile':
                    require(expected_journal[key] == 1, 'Torn journal fields differ from exact input')
                    observed_journal.append(saved)
                    journal.append(key)
                else:
                    require(expected_metadata[key] == 1, 'Torn metadata fields differ from exact input')
                    observed_metadata.append(saved)
                    metadata.append(key)
            elif matching:
                require(identifier == 98 and fields.get('CorruptionActionState') == '0',
                        'Native candidate corruption state')
                observed_healthy.append(saved)
                healthy.append(saved)
            else:
                require(level == 0 or level > 3, 'Unclassified native warning or error')
        require(row['matchingHealthyEvents'] == observed_healthy and
                row['matchingInjectedTornPages'] == observed_journal and
                row['matchingInjectedMetadataPages'] == observed_metadata,
                'Native event classifications differ from original XML')
    if complete:
        require(healthy and Counter(journal) == expected_journal,
                'Missing healthy event or exact predicted journal event')
    return dict(healthyEvents=len(healthy), attributedJournalEvents=len(journal),
                attributedMetadataEvents=len(metadata), expectedMetadataPages=sum(expected_metadata.values()))


def check_case(product, case):
    require(case['case'] == product['case'] and case['success'] is True and case['stage'] == 'complete',
            'Native candidate did not complete')
    require(case['preMountSha256'] == product['expectedVhdSha256'], 'Native input hash changed')
    require(uuid.UUID(case['disk']['Guid'].strip('{}')) == uuid.UUID(product['diskGuid']) and
            uuid.UUID(case['partition']['Guid'].strip('{}')) == uuid.UUID(product['partitionGuid']),
            'Native GPT identity differs')
    checks = case['nativeChecks']
    require(checks['success'] is True and checks['sequence']['success'] is True,
            'Native namespace checks did not complete')
    resident_reference = native_id(product['residentFileId'])
    require(checks['resident']['passed'] is True and
            native_id(checks['resident']['fileId']) == resident_reference and
            checks['resident']['acl'] == product['residentAcl'],
            'Original source identity or baseline ACL changed')
    observed = {row['relativePath']: row for row in checks['sequence']['checks']}
    require(len(observed) == len(checks['sequence']['checks']) == len(product['sequenceObjects']),
            'Native sequence object set differs')
    for expected in product['sequenceObjects']:
        row = observed.get(expected['relativePath'])
        require(row is not None and row['passed'] is True and row['present'] == expected['present'],
                'Native object result differs')
        if expected['present']:
            require(row['reference'] == expected['reference'] and row['directory'] == expected['directory'] and
                    row['lastWriteFileTime'] == expected['lastWriteFileTime'] and row['acl'] == row['expectedAcl'],
                    'Native identity, FILETIME or ACL result differs')
            require(native_id(row['fileId']) == int(expected['reference']),
                    'Native full sequence-bearing File ID differs')
            if int(expected['reference']) == resident_reference:
                require(row['acl'] == row['expectedAcl'] == product['residentAcl'],
                        'Hard-link ACL differs from the original native source policy')
            if not expected['directory']:
                require(row['bytes'] == expected['bytes'] and row['sha256'] == expected['sha256'],
                        'Native payload differs')
    require(checks['namedStream']['passed'] is True and
            checks['namedStream']['bytes'] == product['namedStream']['bytes'] and
            checks['namedStream']['sha256'] == product['namedStream']['sha256'], 'Native ADS differs')
    require(case['dirtyQuery']['exitCode'] == 0 and
            'Volume - R: is NOT Dirty' in '\n'.join(case['dirtyQuery']['output']), 'Native volume is not clean')
    require(case['chkdsk']['exitCode'] == 0 and 'found no problems' in '\n'.join(case['chkdsk']['output']),
            'Read-only chkdsk did not pass')
    attempts = case['nativeEventAttempts']
    require(isinstance(attempts, list) and attempts, 'Missing original native event attempts')
    for attempt in attempts:
        event_review(attempt['observations'], product, case, False)
    require(attempts[-1]['observations'] == case['nativeEvents'], 'Final event query differs')
    return event_review(case['nativeEvents'], product, case, True)


def review(packages, replay, output):
    output.mkdir(parents=True, exist_ok=False)
    report = dict(status='running', nativeMounts=0, automaticRetry=False, cases=[],
                  storageFamily='selected-cache-posix-hardlink', generalOwnerAdmitted=False)
    try:
        expected = read(packages / 'result.json')
        native = read(replay / 'replay.json')
        require(expected['status'] == 'pass' and native['success'] is True and
                native['stage'] == 'complete' and native['automatic_retry'] is False,
                'Native package or replay did not finish')
        require(1 <= len(expected['groups']) == len(native['groups']) <= 16, 'Native group set differs')
        collector = Path(__file__).resolve().parents[1] / 'tests/windows_image_recovery.ps1'
        report['collectorSource'] = collector_encoding(collector, native['collector_sha256'])
        seen = set()
        for index, state in enumerate(native['groups']):
            name = f'group-{index:02d}'
            require(state['name'] == name and state['success'] is True and state['stage'] == 'complete',
                    'Native group failed or changed identity')
            batch = read(packages / name / 'batch.json')
            original = read(replay / name / 'native-report.json')
            require(original['success'] is True and original['stage'] == 'complete' and
                    original['originalBefore']['success'] is True and original['originalAfter']['success'] is True,
                    'Original native report or baseline checks failed')
            require(1 <= len(batch['products']) == len(original['cases']) == len(state['postimages']) <= 8,
                    'Original candidate/postimage count differs')
            posts = {row['case']: row for row in state['postimages']}
            require(len(posts) == len(state['postimages']), 'Duplicate retained postimage')
            for product, case in zip(batch['products'], original['cases']):
                identifier = product['case']
                require(re.fullmatch(r'hardlink-[A-Za-z0-9-]{1,70}', identifier) is not None and identifier not in seen,
                        'Unexpected/repeated hard-link candidate identity')
                seen.add(identifier)
                observation = check_case(product, case)
                post = posts.get(identifier)
                require(post is not None and post['retained'] is True and post['attached'] is False,
                        'Detached postimage missing')
                image = replay / name / (identifier + '.vhd')
                require(image.is_file() and not image.is_symlink() and
                        0 < image.stat().st_size == post['bytes'] <= MAX_VHD_BYTES,
                        'Postimage is not a bounded regular file')
                observed_hash = digest(image)
                require(observed_hash == post['sha256'] == case['postDetachSha256'],
                        'Postimage differs from first native report')
                report['cases'].append(dict(case=identifier, postimageSha256=observed_hash,
                    postimageBytes=post['bytes'], originalReportSha256=digest(replay / name / 'native-report.json'),
                    events=observation, nativeChecks=True, cleanState=True, readOnlyChkdsk=True))
        require(seen == {row['case'] for row in expected['products']}, 'Complete package candidate set differs')
        report.update(status='pass', originalReplaySha256=digest(replay / 'replay.json'))
    except BaseException as error:
        report.update(status='fail', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        (output / 'review.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', type=Path, required=True)
    parser.add_argument('--replay', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = review(args.packages.resolve(strict=True), args.replay.resolve(strict=True), args.output.resolve())
    print(json.dumps(dict(status=result['status'], cases=len(result['cases']), nativeMounts=0)))
