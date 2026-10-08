#!/usr/bin/env python3
"""Compare frozen FSKit phase images to independent bytes and warm/cold syscall metadata.

Produces the same snapshot envelope as native_directory_batch for VHD packaging.
The input images must already be inactive, exported, read-only and hash-bound by
scripts/test_mounted_directory.py. This observer never opens a VM or writes media.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import sys

import directory_scenarios as scenario
from native_directory_batch import Batch, NATIVE_ROOT, filetime
from native_growth_faults import sha

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from test_mounted_directory import observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mounted', type=Path, required=True, help='Completed test_mounted_directory output')
    parser.add_argument('--baseline-manifest', type=Path, required=True)
    parser.add_argument('--build', type=Path, default=ROOT / '.build')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    mounted = json.loads((args.mounted / 'result.json').read_text())
    assert mounted['status'] == 'pass' and not mounted['guiInputUsed'] and not mounted['vmLifecycleChanged']
    assert [row['phase'] for row in mounted['captures']] == list(scenario.PHASES)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    batch = Batch(output, args.build.resolve(strict=True), None)
    batch.report.update(baselineManifest=str(args.baseline_manifest.resolve(strict=True)),
                        mountedReport=str((args.mounted / 'result.json').resolve()), windowsPostimagesPending=True)
    try:
        for capture in mounted['captures']:
            phase, image = capture['phase'], Path(capture['image'])
            assert image.is_file() and image.stat().st_mode & 0o777 == 0o444 and sha(image) == capture['sha256']
            warm = observations(Path(capture['mutatedReport']).read_bytes())
            cold = observations(Path(capture['remountedReport']).read_bytes())
            wanted = scenario.expected(phase, mounted=True)
            assert warm == cold and set(cold) == set(wanted)
            directory = output / phase
            directory.mkdir()
            validated = batch.json_command(directory, 'validate', [batch.tool('ntfs-validate'), image])
            assert validated['complete'] and validated['result'] == 'success'
            rows, actual = [], set()
            for number, folder in enumerate(scenario.DIRECTORIES):
                metadata = batch.json_command(directory, f'directory-{number}',
                    [batch.tool('ntfs-inspect'), image, 'stat', NATIVE_ROOT + '/' + folder])
                reference = int(metadata['reference'], 16)
                assert metadata['directory']
                descriptor = batch.command(directory, f'security-{number}',
                    [batch.tool('ntfs-inspect'), image, 'security-ref', format(reference, 'x')])
                rows.append(dict(relativePath=folder, directory=True, present=True, reference=str(reference),
                    lastWriteFileTime=str(filetime(metadata['modified'])),
                    securityDescriptor=base64.b64encode(descriptor).decode('ascii')))
                raw = batch.command(directory, f'files-{number}', [batch.tool('ntfs-native-inventory'), image, reference])
                for line in raw.splitlines():
                    entry = json.loads(line)
                    name = folder + '/' + ''.join(chr(unit) for unit in entry['nameUnits'])
                    assert name in wanted and name not in actual
                    actual.add(name)
                    value = bytes.fromhex(entry['dataHex'])
                    syscall = cold[name]
                    assert value == wanted[name] and entry['size'] == syscall['bytes'] == len(value)
                    assert int(entry['reference']) == int(syscall['inode']) and int(entry['parentReference']) == reference
                    assert entry['links'] == 1 and entry['modifiedSeconds'] == syscall['modifiedSeconds']
                    assert entry['modifiedNanoseconds'] == syscall['modifiedNanoseconds']
                    rows.append(dict(relativePath=name.replace('/', '\\'), directory=False, present=True,
                        reference=entry['reference'], bytes=len(value), sha256=hashlib.sha256(wanted[name]).hexdigest(),
                        lastWriteFileTime=str(filetime(dict(seconds=entry['modifiedSeconds'], nanoseconds=entry['modifiedNanoseconds']))),
                        securityDescriptor=base64.b64encode(bytes.fromhex(entry['descriptorHex'])).decode('ascii')))
            assert actual == set(wanted)
            scenario.verify_objects(rows, phase, mounted=True)
            assert sha(image) == capture['sha256']
            (directory / 'objects.json').write_text(json.dumps(rows, indent=2) + '\n')
            batch.report['snapshots'].append(dict(phase=phase, image=str(image), sha256=capture['sha256'],
                objects=str(directory / 'objects.json'), warmColdAndCoreMetadataExact=True,
                independentContentOracle=True))
            batch.save()
        batch.report['status'] = 'pass'
    except BaseException:
        batch.report['status'] = 'fail'
        raise
    finally:
        batch.save()


if __name__ == '__main__':
    main()
