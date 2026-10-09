#!/usr/bin/env python3
"""Select original hard-link expectations from an immutable artifact ZIP.

Do not expand the many sparse crash/recovery working copies in the producer
artifact. Only seven named original expectation files are needed for raw review.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import zipfile

from review_windows_hardlink import digest, read, require

PREFIX = 'windows-hardlink-storage'
PROFILES = ('cross-parent', 'same-parent', 'index-split')
FILES = (f'{PREFIX}/result.json', *(f'{PREFIX}/{profile}/selected-operation/{name}'
         for profile in PROFILES for name in ('before.ntfs', 'hardlink-transition.json')))
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_PARTITION_BYTES = 4096 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
RESERVED_DISK_BYTES = 4 * 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024


def extract(archive, binding, output):
    require(archive.is_file() and not archive.is_symlink() and
            0 < archive.stat().st_size <= MAX_ARCHIVE_BYTES, 'Expected a bounded regular artifact ZIP')
    selected = [row for row in binding['artifacts'] if row['name'] == 'hardlink-c-preparation']
    require(len(selected) == 1 and isinstance(selected[0]['id'], int) and selected[0]['id'] > 0,
            'Original immutable preparation artifact ID is missing')
    expected_hash = selected[0]['digest']
    require(isinstance(expected_hash, str) and re.fullmatch(r'sha256:[a-f0-9]{64}', expected_hash) is not None,
            'Original artifact archive digest is missing')
    archive_hash = digest(archive)
    require('sha256:' + archive_hash == expected_hash, 'Downloaded immutable artifact ZIP hash differs')
    output.mkdir(parents=True, exist_ok=False)
    report = dict(status='running', artifactId=selected[0]['id'], sourceRun=binding['sourceRun'],
                  sourceSha=binding['sourceSha'], archiveSha256=archive_hash, files=[])
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            require(len(entries) <= 50000, 'Artifact directory exceeds the source-side bound')
            by_name = {}
            for entry in entries:
                if entry.filename in FILES:
                    require(entry.filename not in by_name, 'Duplicate original expectation in artifact')
                    by_name[entry.filename] = entry
            require(set(by_name) == set(FILES), 'Artifact lacks original pre-Windows expectations')
            total = 0
            for name, entry in by_name.items():
                kind = stat.S_IFMT(entry.external_attr >> 16)
                maximum = MAX_PARTITION_BYTES if name.endswith('.ntfs') else MAX_JSON_BYTES
                require(not entry.is_dir() and kind in (0, stat.S_IFREG) and entry.flag_bits & 1 == 0 and
                        entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and
                        0 < entry.file_size <= maximum, 'Unexpected original expectation ZIP entry')
                total += entry.file_size
            require(shutil.disk_usage(output).free >= total + RESERVED_DISK_BYTES,
                    'Insufficient space for selected originals and bounded native review')
            for name in FILES:
                entry = by_name[name]
                destination = output / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                value_hash = hashlib.sha256()
                with bundle.open(entry) as source, destination.open('xb') as target:
                    for first in range(0, entry.file_size, CHUNK_BYTES):
                        count = min(CHUNK_BYTES, entry.file_size - first)
                        value = source.read(count)
                        require(len(value) == count, 'Original expectation decompression ended early')
                        value_hash.update(value)
                        if any(value):
                            require(target.write(value) == count, 'Incomplete original expectation transfer')
                        else:
                            target.seek(count, os.SEEK_CUR)
                    require(source.read(1) == b'', 'Original expectation exceeds its declared ZIP size')
                    target.truncate(entry.file_size)
                    target.flush()
                    os.fsync(target.fileno())
                require(digest(destination) == value_hash.hexdigest(), 'Extracted original bytes differ')
                destination.chmod(0o444)
                report['files'].append(dict(name=name, bytes=entry.file_size, sha256=value_hash.hexdigest()))
        local = read(output / PREFIX / 'result.json')
        require(local['status'] == 'pass' and local['storageFamily'] == 'selected-cache-posix-hardlink',
                'The original producer did not complete the storage-family preparation')
        for profile in PROFILES:
            folder = output / PREFIX / profile / 'selected-operation'
            transition = read(folder / 'hardlink-transition.json')
            require(digest(folder / 'before.ntfs') == transition['sourceSha256'],
                    'Original predecessor does not match the immutable transition manifest')
        require(digest(archive) == archive_hash, 'Original artifact ZIP changed during observation')
        report.update(status='pass', selectedBytes=total, extractedFiles=len(FILES))
    except BaseException as error:
        report.update(status='fail', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        (output / 'expectation-extraction.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--binding', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = extract(args.archive.resolve(strict=True), read(args.binding), args.output.resolve())
    print(json.dumps({name: result[name] for name in ('status', 'extractedFiles', 'selectedBytes')}))
