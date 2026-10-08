#!/usr/bin/env python3
"""One CLI-only FSKit directory batch in an already prepared dedicated Tart VM.

Requires the current signed app and test executable to be installed and a fresh
private image already imported by the owner. Does not start/stop a VM, install
software, use sudo or retry failed native operations. On failure retain state.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import re
import subprocess
import time
from urllib.parse import urlsplit, unquote

from environment import tool_environment

ROOT = Path(__file__).resolve().parents[1]
APP = '/Applications/Machlin NTFS.app/Contents/MacOS/Machlin NTFS'
EXTENSION = '/Applications/Machlin NTFS.app/Contents/Extensions/NTFSExtension.appex/Contents/MacOS/NTFSExtension'
TEST_ROOT = '/MachlinWriteCases-native-write-alias-20261006'
PHASES = (('populate', 'full'), ('contract', 'contracted'), ('reuse', 'reused'), ('empty', 'empty'))
MAX_COMPRESSED_BYTES = 256 * 1024 * 1024
COPY_BYTES = 1024 * 1024


def observations(data):
    rows = [json.loads(line) for line in data.decode().splitlines() if line.startswith('{')]
    assert rows and rows[-1] == dict(result='PASS', nativeSyscalls=True, guiInputUsed=False)
    entries = rows[:-1]
    assert all('path' in row for row in entries)
    assert len({row['path'] for row in entries}) == len(entries)
    return {row['path']: row for row in entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm', default='machlin-ntfs-fskit-27.0.1')
    parser.add_argument('--lab', type=Path, default=ROOT.parent / 'lab')
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--guest-image', required=True, help='Exact inactive private app backing path')
    parser.add_argument('--guest-binary', required=True)
    parser.add_argument('--image-sha256', required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--extension-sha256', required=True)
    parser.add_argument('--build-number', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert re.fullmatch('[A-Za-z0-9._-]{1,128}', args.vm)
    assert args.build_number > 19
    assert all(re.fullmatch('[a-f0-9]{64}', value) for value in
               (args.image_sha256, args.binary_sha256, args.extension_sha256))
    assert all(path.startswith('/Users/admin/') and '..' not in Path(path).parts
               for path in (args.guest_image, args.guest_binary))
    output = args.output.resolve()
    assert output.is_relative_to((ROOT / 'artifacts').resolve())
    output.mkdir(parents=True, exist_ok=False)
    report = dict(status='running', vm=args.vm, guiInputUsed=False, vmLifecycleChanged=False,
                  automaticRetry=False, commands=[], captures=[], buildNumber=args.build_number)
    env = tool_environment()

    def save():
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    def guest(label, command, allowed=(0,), timeout=600):
        argv = ['bash', 'scripts/tart.sh', 'exec', args.vm, *map(str, command)]
        item = dict(label=label, argv=argv, status='running')
        report['commands'].append(item)
        save()
        started = time.monotonic()
        with (output / (label + '.stdout')).open('xb') as stdout, (output / (label + '.stderr')).open('xb') as stderr:
            result = subprocess.run(argv, cwd=args.lab.resolve(), env=env, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, timeout=timeout)
        item.update(status='complete', exitCode=result.returncode, seconds=time.monotonic() - started)
        save()
        assert result.returncode in allowed, label
        assert (output / (label + '.stderr')).stat().st_size == 0, label
        return (output / (label + '.stdout')).read_bytes()

    def cli(label, action, *arguments):
        value = json.loads(guest(label, [APP, '--image-command', action, *arguments]))
        assert value['result'] == 'PASS' and value['realUserID'] == value['effectiveUserID'] == 501
        assert str(value['bundleVersion']) == str(args.build_number)
        return value

    def digest(label, path):
        return guest(label, ['/usr/bin/shasum', '-a', '256', path]).decode().split()[0]

    def inactive(label):
        status = cli(label + '-status', 'status')
        assert status['mounts'] == []
        saved = next(row for row in status['images'] if row['id'] == args.image_id)
        assert saved['mounts'] == [] and saved['backingOwnerUserID'] == 501
        assert saved['sourceURL'] == report['savedSourceURL']
        assert not guest(label + '-descriptors', ['/usr/sbin/lsof', '-F', 'pfn', args.guest_image], allowed=(0, 1)).strip()

    def mounted(label):
        value = cli(label, 'mount', args.image_id)
        mount = value['mountURL']
        assert mount.startswith('/Volumes/') and '..' not in Path(mount).parts and str(Path(mount)) == mount
        status = cli(label + '-status', 'status')
        saved = next(row for row in status['images'] if row['id'] == args.image_id)
        assert saved['sourceURL'] == report['savedSourceURL'] and len(saved['mounts']) == 1
        assert saved['mounts'][0]['path'] == mount and not saved['mounts'][0]['readOnly']
        return mount + TEST_ROOT

    try:
        assert digest('test-binary', args.guest_binary) == args.binary_sha256
        assert digest('extension-binary', EXTENSION) == args.extension_sha256
        initial = cli('initial-status', 'status')
        saved = next(row for row in initial['images'] if row['id'] == args.image_id)
        report['savedSourceURL'] = saved['sourceURL']
        # Bind the bookmark to the explicitly provided backing path before any mount.
        source_url = urlsplit(saved['sourceURL'])
        assert source_url.scheme == 'file' and source_url.netloc == ''
        assert unquote(source_url.path) == args.guest_image and not source_url.query and not source_url.fragment
        inactive('initial-inactive')
        assert digest('initial-image', args.guest_image) == args.image_sha256
        identity = guest('backing-identity', ['/usr/bin/stat', '-f', '%d %u %g %Lp %z %l %i', args.guest_image]).decode().split()
        assert identity[1] == '501' and identity[3] == '600' and identity[5] == '1'
        image_bytes = int(identity[4])
        for action, phase in PHASES:
            root = mounted(phase + '-mount')
            if phase == 'full':
                pids = guest('loaded-extension-pid', ['/usr/bin/pgrep', '-x', 'NTFSExtension']).decode().split()
                assert len(pids) == 1 and pids[0].isdigit()
                process = guest('loaded-extension-process', ['/bin/ps', '-p', pids[0], '-o', 'pid=,uid=,comm=']).decode().strip().split(None, 2)
                assert process == [pids[0], '501', EXTENSION]
                loaded = guest('loaded-extension-text', ['/usr/sbin/lsof', '-a', '-p', pids[0], '-d', 'txt', '-F', 'pni']).decode().splitlines()
                inode = guest('installed-extension-inode', ['/usr/bin/stat', '-f', '%i', EXTENSION]).decode().strip()
                position = loaded.index('n' + EXTENSION)
                assert position > 0 and loaded[position - 1] == 'i' + inode
                report['loadedExtension'] = dict(pid=int(pids[0]), inode=inode, sha256=args.extension_sha256)
            warm = guest(phase + '-mutate', [args.guest_binary, action, root])
            expected = observations(warm)
            cli(phase + '-unmount', 'unmount', args.image_id)
            inactive(phase + '-inactive')
            before = digest(phase + '-image', args.guest_image)
            root = mounted(phase + '-remount')
            cold = guest(phase + '-check', [args.guest_binary, 'check', phase, root])
            assert observations(cold) == expected
            cli(phase + '-cold-unmount', 'unmount', args.image_id)
            inactive(phase + '-cold-inactive')
            assert digest(phase + '-cold-image', args.guest_image) == before
            # Binary stdout is redirected to a file, never decoded or emitted.
            label = phase + '-export'
            argv = ['bash', 'scripts/tart.sh', 'exec', args.vm, '/usr/bin/gzip', '-c', '-1', '--', args.guest_image]
            compressed = output / (phase + '.ntfs.gz')
            with compressed.open('xb') as destination, (output / (label + '.stderr')).open('xb') as stderr:
                result = subprocess.run(argv, cwd=args.lab.resolve(), env=env, stdin=subprocess.DEVNULL,
                                        stdout=destination, stderr=stderr, timeout=600)
            report['commands'].append(dict(label=label, argv=argv, exitCode=result.returncode))
            save()
            assert result.returncode == 0 and (output / (label + '.stderr')).stat().st_size == 0
            assert 0 < compressed.stat().st_size <= MAX_COMPRESSED_BYTES
            image = output / (phase + '.ntfs')
            total, sha256 = 0, hashlib.sha256()
            with gzip.open(compressed, 'rb') as source, image.open('xb') as destination:
                while value := source.read(COPY_BYTES):
                    total += len(value)
                    assert total <= image_bytes
                    sha256.update(value)
                    if any(value):
                        destination.write(value)
                    else:
                        destination.seek(len(value), 1)
                destination.truncate(total)
            assert total == image_bytes and sha256.hexdigest() == before
            image.chmod(0o444)
            report['captures'].append(dict(phase=phase, image=str(image), sha256=before,
                mutatedReport=str(output / (phase + '-mutate.stdout')),
                remountedReport=str(output / (phase + '-check.stdout'))))
            save()
        assert digest('final-test-binary', args.guest_binary) == args.binary_sha256
        assert digest('final-extension-binary', EXTENSION) == args.extension_sha256
        assert guest('final-backing-identity', ['/usr/bin/stat', '-f', '%d %u %g %Lp %z %l %i', args.guest_image]).decode().split() == identity
        report['status'] = 'pass'
        report['windowsPostimagesPending'] = True
    except BaseException:
        report['status'] = 'fail'
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
