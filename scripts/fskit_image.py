#!/usr/bin/env python3
"""Run one signed app image command in a dedicated macOS VM without GUI input."""
from pathlib import Path
import argparse
import json
import re
import subprocess
import time

from bounded_tool import bounded_read
from environment import tool_environment

ROOT = Path(__file__).resolve().parents[1]
APPLICATION = '/Applications/Machlin NTFS.app/Contents/MacOS/Machlin NTFS'
OUTPUT_LIMIT_BYTES = 512 * 1024


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm', required=True, help='Exact dedicated Tart VM name')
    parser.add_argument('--lab', type=Path, default=ROOT.parent / 'lab',
                        help='Machlin lab repository containing scripts/tart.sh')
    parser.add_argument('--output', type=Path, required=True,
                        help='New ignored artifact directory for this invocation')
    parser.add_argument('--timeout', type=int, default=120)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('status')
    commands.add_parser('import').add_argument('name', help='File name in the app inbox')
    for action in ('mount', 'unmount'):
        commands.add_parser(action).add_argument('image_id')
    commands.add_parser('unmount-path').add_argument('mount_path')
    args = parser.parse_args()
    if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', args.vm) is None:
        parser.error('Invalid dedicated VM name')
    if not 1 <= args.timeout <= 300:
        parser.error('--timeout must be in [1, 300] seconds')
    args.lab = args.lab.resolve()
    if not (args.lab / 'scripts/tart.sh').is_file():
        parser.error('--lab must contain scripts/tart.sh')
    args.output = args.output.resolve()
    if not args.output.is_relative_to((ROOT / 'artifacts').resolve()):
        parser.error('--output must be under this repository\'s ignored artifacts directory')
    args.output.mkdir(parents=True, exist_ok=False)
    arguments = ['bash', 'scripts/tart.sh', 'exec', args.vm, APPLICATION,
                 '--image-command', args.command]
    if args.command == 'import':
        arguments.append(args.name)
    elif args.command in ('mount', 'unmount'):
        arguments.append(args.image_id)
    elif args.command == 'unmount-path':
        arguments.append(args.mount_path)
    report = {'success': False, 'vm': args.vm, 'command': args.command,
              'argv': arguments, 'cwd': str(args.lab), 'stdinClosed': True,
              'guiInputUsed': False, 'vmLifecycleChanged': False,
              'timeoutSeconds': args.timeout, 'exitCode': None,
              'timedOut': False, 'automaticRetry': False}
    started = time.monotonic()
    try:
        with (args.output / 'stdout').open('xb') as out, (args.output / 'stderr').open('xb') as err:
            done = subprocess.run(arguments, cwd=args.lab, env=tool_environment(),
                                  stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                  timeout=args.timeout)
        report['exitCode'] = done.returncode
        value = json.loads(bounded_read(args.output / 'stdout', OUTPUT_LIMIT_BYTES))
        report['appReply'] = value
        if done.returncode != 0 or value.get('result') != 'PASS':
            raise RuntimeError('The native image command refused or failed; see retained app reply')
        if value.get('command') != args.command:
            raise ValueError('The native reply belongs to a different command')
        report['success'] = True
    except subprocess.TimeoutExpired:
        report['timedOut'] = True
        report['error'] = ('The local transport timed out. A remote operation may still be pending; '
                           'inspect native status before another operation.')
    except Exception as error:
        report['error'] = str(error)
    finally:
        report['elapsedSeconds'] = time.monotonic() - started
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'success': report['success'], 'command': args.command,
                      'report': str(args.output / 'report.json')}))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
