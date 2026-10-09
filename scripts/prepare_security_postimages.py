#!/usr/bin/env python3
"""Read-only qemu conversion of exact original f415c6b security-diagnostic inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

SOURCE_RUN = 37869063560
PACKAGE_ARTIFACT = 11590375707
REPLAY_ARTIFACT = 11589579895
COPY_BYTES = 1024 * 1024
PINS = {
    'batch': ('packages', 'windows-directory-packages/group-00/batch.json',
              'a87e1c035d35d535a692a53f1a2667f1a930aed837cf4f17b7bcd3fb2a986f64'),
    'native': ('replay', 'group-00/native-report.json',
               '5aa861a95fc88afd366cd0742191be24c1e8f108a04d8b2f62363424bb0b0cbe'),
    'replay_report': ('replay', 'replay.json',
                      'bd74c00087446c0dbd8d393ebb0cb6d4b231cb187951a227d60df3da2d9a9e15'),
    'before': ('packages', 'windows-directory-packages/directory-full/input-directory-full.vhd',
               '25802fa343d845b89516524850c35a148c4bac283015a6aff5832c70b8de6ff3'),
    'after': ('replay', 'group-00/directory-full.vhd',
              '4810ae5bf3947c7148ad1445edacd7ec1c0a21142b87e5bb8363963f9c0cddd7')}


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(COPY_BYTES), b''):
            result.update(data)
    return result.hexdigest()


def inputs(packages, replay):
    roots = {'packages': packages.resolve(strict=True), 'replay': replay.resolve(strict=True)}
    paths = {}
    for key, (root, relative, expected) in PINS.items():
        path = roots[root] / relative
        if (not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(roots[root]) or
                not 0 < path.stat().st_size <= 128 * COPY_BYTES):
            raise ValueError('Original input must be a contained plain file')
        parent = path.parent
        while parent != roots[root]:
            if parent.is_symlink():
                raise ValueError('Original input has a symbolic-link ancestor')
            parent = parent.parent
        if digest(path) != expected:
            raise ValueError('Original input differs from its immutable pin: ' + key)
        paths[key] = path
    batch = json.loads(paths['batch'].read_text(encoding='utf-8-sig'))
    native = json.loads(paths['native'].read_text(encoding='utf-8-sig'))
    replay_report = json.loads(paths['replay_report'].read_text(encoding='utf-8-sig'))
    products = [row for row in batch['products'] if row['case'] == 'directory-full']
    if (len(products) != 1 or native['success'] or replay_report['success'] or
            len(native['cases']) != 1 or native['cases'][0]['case'] != 'directory-full' or
            not native['failedCandidateDetached'] or
            products[0]['expectedVhdSha256'] != PINS['before'][2] or
            native['cases'][0]['preMountSha256'] != PINS['before'][2]):
        raise ValueError('Original source/failure identity differs')
    postimages = replay_report['groups'][0]['postimages']
    if (len(postimages) != 1 or postimages[0]['case'] != 'directory-full' or
            postimages[0]['attached'] or not postimages[0]['retained'] or
            postimages[0]['sha256'] != PINS['after'][2]):
        raise ValueError('Original detached postimage identity differs')
    return paths, batch, products[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', type=Path, required=True)
    parser.add_argument('--replay', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    paths, batch, product = inputs(args.packages, args.replay)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'status': 'running', 'source_run': SOURCE_RUN, 'package_artifact': PACKAGE_ARTIFACT,
              'replay_artifact': REPLAY_ARTIFACT, 'scope': 'read-only conversion; no native recovery or ACL changes',
              'original_failed_verdict_replaced': False, 'commands': [], 'images': {}}
    (output / 'original-product.json').write_text(json.dumps(product, indent=2) + '\n')
    def command(name, arguments):
        with (output / (name + '.stdout')).open('xb') as stdout, (output / (name + '.stderr')).open('xb') as stderr:
            process = subprocess.run(list(map(str, arguments)), stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, timeout=120, check=False)
        report['commands'].append({'argv': list(map(str, arguments)), 'exit_code': process.returncode})
        if process.returncode:
            raise RuntimeError('Original conversion command failed: ' + name)
    try:
        first, count, whole_bytes = batch['partitionOffset'], batch['partitionBytes'], batch['diskBytes']
        if not 0 < first < whole_bytes or not 0 < count <= whole_bytes - first:
            raise ValueError('Pinned partition geometry is invalid')
        for label in ('before', 'after'):
            raw = output / (label + '-whole.raw')
            command(label + '-convert', [args.qemu, 'convert', '-f', 'vpc', '-O', 'raw', paths[label], raw])
            if raw.stat().st_size != whole_bytes:
                raise ValueError('Original VHD virtual size differs')
            command(label + '-compare', [args.qemu, 'compare', '-f', 'vpc', '-F', 'raw', paths[label], raw])
            partition = output / (label + '.ntfs')
            with raw.open('rb') as source, partition.open('xb') as target:
                source.seek(first)
                remaining = count
                while remaining:
                    data = source.read(min(COPY_BYTES, remaining))
                    if not data:
                        raise ValueError('Truncated original partition')
                    if data.strip(b'\0'):
                        target.write(data)
                    else:
                        target.seek(len(data), 1)
                    remaining -= len(data)
                target.truncate(count)
            partition.chmod(0o444)
            raw.chmod(0o444)
            report['images'][label] = {'original_vhd_sha256': digest(paths[label]),
                'whole_raw_sha256': digest(raw), 'partition_sha256': digest(partition), 'partition_bytes': count}
            if digest(paths[label]) != PINS[label][2]:
                raise ValueError('Original VHD changed during read-only conversion')
        inputs(args.packages, args.replay)
        report['status'] = 'complete'
    except BaseException as error:
        report['status'] = 'failed'
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'source_run': SOURCE_RUN}))


if __name__ == '__main__':
    main()
