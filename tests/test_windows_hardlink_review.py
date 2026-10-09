#!/usr/bin/env python3
"""Synthetic offline-review contracts; these tests establish no native verdict."""
from pathlib import Path
import copy
import json
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from review_windows_hardlink import PROVIDERS, check_case, collector_encoding, digest, event_review, read, review

TIME = '2026-10-09T00:00:00.0000000Z'
VOLUME = r'\\?\Volume{11111111-1111-1111-1111-111111111111}' + '\\'
REFERENCE = (1 << 48) | 39


def events(extra=()):
    rows = []
    for provider in PROVIDERS:
        root = ET.Element('Events')
        observed = []
        source = [(98, 4, {'VolumeName': VOLUME, 'CorruptionActionState': '0'}), *extra] if provider == PROVIDERS[0] else []
        for identifier, level, data in source:
            event = ET.SubElement(root, 'Event')
            system = ET.SubElement(event, 'System')
            ET.SubElement(system, 'Provider', Name=provider)
            ET.SubElement(system, 'TimeCreated', SystemTime=TIME)
            ET.SubElement(system, 'EventID').text = str(identifier)
            ET.SubElement(system, 'Level').text = str(level)
            fields = ET.SubElement(event, 'EventData')
            for name, value in data.items():
                ET.SubElement(fields, 'Data', Name=name).text = value
            observed.append(dict(eventId=identifier, level=level, fields=data, systemTimeUtc=TIME))
        rows.append(dict(provider=provider, exitCode=0, parsed=True,
            output=[ET.tostring(root, encoding='unicode')], count=len(observed), observedEvents=observed,
            matchingHealthyEvents=[row for row in observed if row['eventId'] == 98],
            matchingInjectedTornPages=[row for row in observed if row['fields'].get('FileName') == r'\$LogFile'],
            matchingInjectedMetadataPages=[]))
    return rows


def candidate():
    product = dict(case='hardlink-test-complete', expectedVhdSha256='a' * 64,
        diskGuid='11111111-1111-1111-1111-111111111111',
        partitionGuid='22222222-2222-2222-2222-222222222222',
        expectedTornLogPages=[], expectedTornMetadataPages=[],
        sequenceObjects=[dict(relativePath='native-growth/sustained-file', present=True,
            directory=False, reference=str(REFERENCE), lastWriteFileTime='123', bytes=0, sha256='b' * 64)],
        namedStream=dict(bytes=29, sha256='c' * 64), residentAcl='D:',
        residentFileId=dict(exitCode=0, output=[f'File ID is 0x{REFERENCE:032x}']))
    row = dict(product['sequenceObjects'][0], passed=True, acl='D:', expectedAcl='D:',
        fileId=dict(exitCode=0, output=[f'File ID is 0x{REFERENCE:032x}']))
    native_events = events()
    case = dict(case=product['case'], stage='complete', success=True,
        preMountSha256=product['expectedVhdSha256'], postDetachSha256='',
        disk=dict(Guid=product['diskGuid']), partition=dict(Guid=product['partitionGuid']),
        volume=dict(UniqueId=VOLUME), mountStartedUtc=TIME,
        nativeChecks=dict(success=True, sequence=dict(success=True, checks=[row]),
                          resident=dict(passed=True, acl='D:', fileId=product['residentFileId']),
                          namedStream=dict(passed=True, bytes=29, sha256='c' * 64)),
        dirtyQuery=dict(exitCode=0, output=['Volume - R: is NOT Dirty']),
        chkdsk=dict(exitCode=0, output=['Windows has scanned the file system and found no problems.']),
        nativeEventAttempts=[dict(observations=native_events)], nativeEvents=native_events)
    return product, case


class NativeReportContracts(unittest.TestCase):
    def test_original_xml_and_metadata(self):
        product, case = candidate()
        self.assertEqual(check_case(product, case)['healthyEvents'], 1)
        changed = copy.deepcopy(case)
        changed['nativeChecks']['sequence']['checks'][0]['fileId']['output'] = ['File ID is 0x' + '0' * 32]
        with self.assertRaises(ValueError):
            check_case(product, changed)
        changed = copy.deepcopy(case)
        changed['nativeEvents'][0]['observedEvents'][0]['fields']['CorruptionActionState'] = '1'
        with self.assertRaises(ValueError):
            check_case(product, changed)
        changed = copy.deepcopy(case)
        changed['nativeChecks']['sequence']['checks'][0].update(acl='D:AI', expectedAcl='D:AI')
        with self.assertRaises(ValueError):
            check_case(product, changed)

    def test_missing_expected_torn_event(self):
        product, case = candidate()
        product['expectedTornLogPages'] = [dict(bufferOffset='8192', blockIndex='0',
            expectedSequenceNumber='2', actualSequenceNumber='1')]
        with self.assertRaises(ValueError):
            event_review(case['nativeEvents'], product, case, True)

    def test_exact_torn_event_and_unrelated_warning(self):
        product, case = candidate()
        product['expectedTornLogPages'] = [dict(bufferOffset='8192', blockIndex='0',
            expectedSequenceNumber='2', actualSequenceNumber='1')]
        fields = dict(DriveName='R:', FileName=r'\$LogFile', FileReference='2', BufferOffset='8192',
            TornStructureOffset='0', BlockIndex='0', ExpectedSequenceNumber='2', ActualSequenceNumber='1')
        rows = events([(7, 3, fields)])
        self.assertEqual(event_review(rows, product, case, True)['attributedJournalEvents'], 1)
        rows = events([(7, 3, dict(fields, BufferOffset='12288'))])
        with self.assertRaises(ValueError):
            event_review(rows, product, case, True)
        rows = events([(999, 3, {'VolumeName': 'another-volume'})])
        with self.assertRaises(ValueError):
            event_review(rows, product, case, False)

    def test_detached_hash_and_exact_case_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages, replay = root / 'packages', root / 'replay'
            (packages / 'group-00').mkdir(parents=True)
            (replay / 'group-00').mkdir(parents=True)
            product, case = candidate()
            postimage = replay / 'group-00' / (product['case'] + '.vhd')
            postimage.write_bytes(b'synthetic detached VHD-shaped bytes; never mounted')
            case['postDetachSha256'] = digest(postimage)
            collector = Path(__file__).resolve().parents[1] / 'tests/windows_image_recovery.ps1'
            package = dict(status='pass', groups=[{}], products=[dict(case=product['case'])])
            native = dict(success=True, stage='complete', automatic_retry=False,
                collector_sha256=digest(collector), groups=[dict(name='group-00', success=True, stage='complete',
                    postimages=[dict(case=product['case'], retained=True, attached=False,
                                    sha256=digest(postimage), bytes=postimage.stat().st_size)])])
            original = dict(success=True, stage='complete', originalBefore=dict(success=True),
                            originalAfter=dict(success=True), cases=[case])
            for path, data in ((packages / 'result.json', package),
                (packages / 'group-00/batch.json', dict(products=[product])),
                (replay / 'replay.json', native), (replay / 'group-00/native-report.json', original)):
                path.write_text(json.dumps(data))
            result = review(packages, replay, root / 'passing')
            self.assertEqual(result['status'], 'pass')
            self.assertEqual(result['nativeMounts'], 0)
            postimage.write_bytes(b'changed retained image')
            with self.assertRaises(ValueError):
                review(packages, replay, root / 'changed')
            self.assertEqual(read(root / 'changed/review.json')['status'], 'fail')

    def test_duplicate_report_fields_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'duplicate.json'
            path.write_text('{"success":false,"success":true}')
            with self.assertRaises(ValueError):
                read(path)

    def test_exact_git_collector_line_endings(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'collector.ps1'
            path.write_bytes(b'one\ntwo\n')
            lf = digest(path)
            self.assertEqual(collector_encoding(path, lf)['matchedEncoding'], 'LF')
            path.write_bytes(b'one\r\ntwo\r\n')
            crlf = digest(path)
            self.assertEqual(collector_encoding(path, crlf)['matchedEncoding'], 'CRLF')
            self.assertEqual(collector_encoding(path, lf)['matchedEncoding'], 'LF')
            path.write_bytes(b'changed\r\ntwo\r\n')
            with self.assertRaises(ValueError):
                collector_encoding(path, crlf)


if __name__ == '__main__':
    unittest.main()
