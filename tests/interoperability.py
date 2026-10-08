#!/usr/bin/env python3
"""Independent mkntfs/ntfscp images; bounded reads compare ntfscat and authored bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from benchmark_toolchain import command
from environment import sanitizer_environment

BYTE_VALUES = 256
LARGE_FILE_BYTES = 2 * 1024 * 1024 + BYTE_VALUES
INDEX_EXTRA_FILES = 96
IMAGE_BYTES = 64 * 1024 * 1024
GEOMETRIES = ((512, 1024), (512, 4096), (4096, 4096), (512, 65536))
COMMAND_SECONDS = 120
RUN_SECONDS = 1800
OUTPUT_BYTES = 8 * 1024 * 1024


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def verify(args):
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    report = dict(profiles=[], status='running', windows_acceptance='not run', commands=[],
                  errors=[], sanitizer_fatal=True, automatic_retry=False)
    report_path = output / 'report.json'
    environment = sanitizer_environment()
    deadline = time.monotonic() + RUN_SECONDS

    def save():
        report_path.write_text(json.dumps(report, indent=2) + '\n')

    save()
    try:
        reader = args.reader.resolve(strict=True)
        tools = {name: args.tools.resolve(strict=True) / ('sbin' if name in ('mkntfs', 'ntfscp') else 'bin') / name
                 for name in ('mkntfs', 'ntfscp', 'ntfscat', 'ntfsls')}
        for path in (*tools.values(), reader):
            if not path.is_file():
                raise ValueError(f'Required executable missing: {path}')
        provenance_path = args.tool_provenance or args.tools / 'source-provenance.json'
        if provenance_path.is_symlink() or not provenance_path.is_file() or provenance_path.stat().st_size > OUTPUT_BYTES:
            raise ValueError('Missing bounded test-tool source provenance; run bootstrap_test_tools.py first')
        provenance = json.loads(provenance_path.read_text())
        if provenance.get('status') != 'pass' or provenance.get('product_dependency') is not False:
            raise ValueError('Test-tool acquisition/build provenance is incomplete')
        report['tool_provenance'] = dict(file=str(provenance_path.resolve()), sha256=sha(provenance_path),
                                        source=provenance['source'], version=provenance['version'])
        report['binaries'] = {name: sha(path) for name, path in tools.items()}
        if report['binaries'] != provenance['binaries']:
            raise ValueError('Test utilities differ from the source-bound bootstrap binaries')
        report['reader_sha256'] = sha(reader)
        payloads = {'empty.txt': b'', 'small.txt': b'Independent NTFS fixture\n',
                    'large.bin': bytes(range(BYTE_VALUES)) * (LARGE_FILE_BYTES // BYTE_VALUES),
                    'café-Ω.txt': 'Names and content: Україна\n'.encode()}
        payloads.update({f'entry-{number:03}.txt': f'file {number}\n'.encode()
                         for number in range(INDEX_EXTRA_FILES)})
        for name, content in payloads.items():
            with (output / name).open('xb') as destination:
                destination.write(content)
        ads = b'Named NTFS stream\x00with binary data'
        with (output / 'ads.bin').open('xb') as destination:
            destination.write(ads)
        report['payload_sha256'] = {name: hashlib.sha256(value).hexdigest() for name, value in payloads.items()}
        with (output / 'commands.log').open('x') as log:
            def run(argv, capture=False):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Interoperability exceeded its aggregate deadline')
                name = f'command-{len(report["commands"]):04d}'
                report['commands'].append(dict(name=name, argv=list(map(str, argv))))
                save()
                log.write(json.dumps(list(map(str, argv))) + '\n')
                log.flush()
                value = command(argv, output, name, environment,
                                timeout=min(COMMAND_SECONDS, remaining), output_limit=OUTPUT_BYTES, text=False)
                return value if capture else None

            for sector, cluster in GEOMETRIES:
                image = output / f'ntfs-s{sector}-c{cluster}.img'
                started = time.monotonic()
                current = dict(sector=sector, cluster=cluster, image=str(image), result='generating')
                report['profiles'].append(current)
                save()
                with image.open('xb') as volume:
                    volume.truncate(IMAGE_BYTES)
                run([tools['mkntfs'], '-F', '-Q', '-s', sector, '-c', cluster, '-L', 'Machlin reference', image])
                for name in payloads:
                    run([tools['ntfscp'], '-f', image, output / name, '/' + name])
                run([tools['ntfscp'], '-f', '-N', 'notes', image, output / 'ads.bin', '/small.txt'])
                before = sha(image)
                current.update(result='comparing', source_sha256=before)
                save()
                try:
                    info = run([reader, image, 'info'], True).decode()
                    names = run([reader, image, 'ls'], True).decode().splitlines()
                    assert set(payloads).issubset(names) and len(names) == len(set(names)), names
                    for name, expected in payloads.items():
                        actual = run([reader, image, 'cat', '/' + name], True)
                        oracle = run([tools['ntfscat'], image, '/' + name], True)
                        assert actual == oracle == expected, (sector, cluster, name)
                    assert run([reader, image, 'cat', '/SMALL.TXT'], True) == payloads['small.txt']
                    assert run([reader, image, 'cat', '/small.txt', 'notes'], True) == ads
                    root_reference = json.loads(run([reader, image, 'info-json'], True))['root_reference']
                    small_name = 'small.txt'.encode('utf-16-be').hex()
                    small = json.loads(run([reader, image, 'lookup-ref', root_reference, small_name], True))
                    streams = [json.loads(line)['name_utf16'] for line in
                               run([reader, image, 'streams-ref', small['reference']], True).splitlines()]
                    assert streams == [[], list(map(ord, 'notes'))]
                    current.update(files=len(payloads), seconds=round(time.monotonic() - started, 3),
                                   info=info, result='pass')
                finally:
                    current['sha256'] = sha(image)
                    current['image_unchanged'] = before == current['sha256']
                    save()
                assert current['image_unchanged'], 'read-only implementation changed the image'
        report['status'] = 'pass'
    except BaseException as error:
        report['status'] = 'fail'
        if report['profiles']:
            report['profiles'][-1]['result'] = 'fail'
        report['errors'].append(f'{type(error).__name__}: {error}')
        raise
    finally:
        save()
    print(f'PASS: {len(report["profiles"])} independent geometries, {len(payloads)} files each, '
          'ADS, case folding, byte-for-byte oracle and unchanged images')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools', type=Path, default=ROOT / 'vendor/ntfs-tools')
    parser.add_argument('--reader', type=Path, default=ROOT / '.build/ntfs-inspect')
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/interoperability')
    parser.add_argument('--tool-provenance', type=Path, help='Source-bound bootstrap report for the selected utilities')
    verify(parser.parse_args())


if __name__ == '__main__':
    main()
