#!/usr/bin/env python3
"""Build pinned external NTFS utilities under ignored vendor/; never a product dependency."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import time
import urllib.parse
import urllib.request
import uuid

from benchmark_toolchain import command
from environment import selected_toolchain, sanitizer_environment

ROOT = Path(__file__).resolve().parents[1]
VERSION = '2022.10.3'
ARCHIVE_NAME = f'ntfs-3g_ntfsprogs-{VERSION}.tgz'
ARCHIVE_URL = f'https://tuxera.com/opensource/{ARCHIVE_NAME}'
ARCHIVE_SHA256 = 'f20e36ee68074b845e3629e6bced4706ad053804cbaf062fbae60738f854170c'
GIT_URL = 'https://github.com/tuxera/ntfs-3g.git'
GIT_COMMIT = '78414d93613532fd82f3a82aba5d4a1c32898781'
DOWNLOAD_BYTES_MAX = 16 * 1024 * 1024
DOWNLOAD_SECONDS_MAX = 120
DOWNLOAD_SOCKET_SECONDS = 15
EXTRACT_BYTES_MAX = 128 * 1024 * 1024
EXTRACT_FILES_MAX = 10000
COPY_BYTES = 1024 * 1024
CONFIGURE_PREFIX = '/ntfs-tools'


def configure_command():
    # Utilities link the private static noinst library. Installing that library
    # is unnecessary and upstream's shared-library relocation hook is not valid
    # for a static-only DESTDIR tree.
    return ['./configure', '--disable-ntfs-3g', '--disable-library', '--disable-shared',
            '--enable-static', '--disable-ldconfig', '--disable-mount-helper',
            f'--prefix={CONFIGURE_PREFIX}', f'--exec-prefix={CONFIGURE_PREFIX}']


def sha(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def require_plain(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected a plain regular source artifact')
    return path


def download(destination):
    """Retain partial bytes; publish nothing until the pinned hash is verified."""
    deadline = time.monotonic() + DOWNLOAD_SECONDS_MAX
    digest, count = hashlib.sha256(), 0
    with urllib.request.urlopen(ARCHIVE_URL, timeout=DOWNLOAD_SOCKET_SECONDS) as source:
        resolved = urllib.parse.urlparse(source.geturl())
        if resolved.scheme != 'https' or resolved.hostname not in ('tuxera.com', 'www.tuxera.com'):
            raise ValueError('Upstream download redirected outside its official HTTPS origin')
        with Path(destination).open('xb') as output:
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError('Pinned archive exceeded its aggregate download deadline')
                value = source.read1(COPY_BYTES)
                if not value:
                    break
                count += len(value)
                if count > DOWNLOAD_BYTES_MAX:
                    raise ValueError('Pinned archive exceeded its download byte budget')
                output.write(value)
                digest.update(value)
            output.flush()
            os.fsync(output.fileno())
    if digest.hexdigest() != ARCHIVE_SHA256:
        raise ValueError('External test-tool archive checksum mismatch; original download retained')
    return count


def extract(archive, destination):
    root_name = f'ntfs-3g_ntfsprogs-{VERSION}'
    with tarfile.open(require_plain(archive)) as package:
        members, total, names = [], 0, set()
        for member in package:
            if len(members) >= EXTRACT_FILES_MAX:
                raise ValueError('Pinned archive exceeds its entry budget')
            path = PurePosixPath(member.name)
            if (path.is_absolute() or not path.parts or path.parts[0] != root_name or
                    '..' in path.parts or path in names or
                    not (member.isfile() or member.isdir()) or member.size < 0):
                raise ValueError('Pinned archive has an unsafe path or entry type')
            names.add(path)
            members.append(member)
            total += member.size
            if member.size > DOWNLOAD_BYTES_MAX or total > EXTRACT_BYTES_MAX:
                raise ValueError('Pinned archive exceeds its expanded-byte budget')
        package.extractall(destination, members=members, filter='data')
    return destination / root_name


def bootstrap(args):
    vendor = ROOT / 'vendor'
    vendor.mkdir(exist_ok=True)
    if vendor.is_symlink():
        raise ValueError('External source storage cannot be a symbolic link')
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    report_path = output / 'report.json'
    report = dict(status='running', source=args.source, version=VERSION,
                  product_dependency=False, installed_on_host=False, commands=[], errors=[])

    def save():
        report_path.write_text(json.dumps(report, indent=2) + '\n')

    save()
    try:
        prefix = args.prefix.resolve(strict=False)
        if (not prefix.is_relative_to(vendor.absolute()) or prefix == vendor.absolute() or
                prefix.exists() or prefix.is_symlink()):
            raise ValueError('Use a new install prefix strictly beneath ignored vendor/')
        environment = selected_toolchain(args.compiler)
        environment.update({key: value for key, value in sanitizer_environment().items()
                            if key in ('ASAN_OPTIONS', 'UBSAN_OPTIONS')})
        work = vendor / ('ntfs-build-' + uuid.uuid4().hex)
        work.mkdir()
        report.update(work=str(work), prefix=str(prefix), compiler=environment['CC'])

        def run(label, argv, cwd=ROOT, timeout=300):
            report['commands'].append(dict(label=label, argv=list(map(str, argv))))
            save()
            return command(argv, output, label, environment, timeout=timeout, cwd=cwd)

        report['compiler_version'] = run('compiler-version', [environment['CC'], '--version'], timeout=15)
        if args.source == 'archive':
            archive = vendor / ARCHIVE_NAME
            if archive.exists() or archive.is_symlink():
                require_plain(archive)
                if archive.stat().st_size > DOWNLOAD_BYTES_MAX or sha(archive) != ARCHIVE_SHA256:
                    raise ValueError('Existing pinned archive checksum/size mismatch; preserved unchanged')
            else:
                partial = output / (ARCHIVE_NAME + '.download')
                download(partial)
                # An exclusive copy preserves caller-owned paths and the first download.
                with partial.open('rb') as source, archive.open('xb') as destination:
                    shutil.copyfileobj(source, destination, COPY_BYTES)
                    destination.flush()
                    os.fsync(destination.fileno())
                if sha(archive) != ARCHIVE_SHA256:
                    raise ValueError('Published source archive differs from the verified download')
            report.update(url=ARCHIVE_URL, sha256=ARCHIVE_SHA256, acquisition='pinned upstream release archive')
            source = extract(archive, work)
        else:
            source = work / 'source'
            report.update(url=GIT_URL, git_tag=VERSION, git_commit=GIT_COMMIT,
                          acquisition='explicit independently pinned upstream Git tag; not release-archive bytes')
            run('clone', ['git', '-c', 'core.hooksPath=/dev/null', 'clone', '--depth', '1',
                '--branch', VERSION, '--no-checkout', GIT_URL, source], timeout=120)
            commit = run('source-commit', ['git', '-C', source, 'rev-parse', 'HEAD'], timeout=15).strip()
            if commit != GIT_COMMIT:
                raise ValueError('Official upstream tag does not match the independently pinned commit')
            run('checkout', ['git', '-c', 'core.hooksPath=/dev/null', '-C', source,
                             'checkout', '--detach', GIT_COMMIT], timeout=60)
            run('autogen', ['./autogen.sh'], cwd=source, timeout=120)
        report['notices'] = {name: sha(require_plain(source / name)) for name in ('COPYING', 'COPYING.LIB')}
        run('configure', configure_command(), cwd=source)
        run('build', ['make', '-j4'], cwd=source, timeout=600)
        stage = work / 'install'
        stage.mkdir()
        run('install', ['make', 'install', f'DESTDIR={stage}',
                        f'rootlibdir={CONFIGURE_PREFIX}/lib'], cwd=source)
        installed = stage / CONFIGURE_PREFIX.lstrip('/')
        # Installation cannot write outside private staging, even if an upstream
        # target ignores --prefix. Refuse any unexpected staged top-level paths.
        if sorted(path.name for path in stage.iterdir()) != ['ntfs-tools']:
            raise ValueError('External install produced paths outside its requested staged prefix')
        shutil.copytree(installed, prefix, symlinks=True)
        names = {'mkntfs': 'sbin', 'ntfscp': 'sbin', 'ntfscat': 'bin', 'ntfsls': 'bin'}
        report['binaries'] = {name: sha(require_plain(prefix / directory / name)) for name, directory in names.items()}
        shutil.copyfile(source / 'COPYING', prefix / 'COPYING')
        shutil.copyfile(source / 'COPYING.LIB', prefix / 'COPYING.LIB')
        report['status'] = 'pass'
        with (prefix / 'source-provenance.json').open('x') as retained:
            retained.write(json.dumps(report, indent=2) + '\n')
    except BaseException as error:
        report['status'] = 'fail'
        report['errors'].append(f'{type(error).__name__}: {error}')
        raise
    finally:
        save()
    print(prefix)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', choices=('archive', 'git-pinned'), default='archive')
    parser.add_argument('--compiler', help='Explicit compiler executable, never ambient CC/flags')
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/test-tools', help='New evidence directory')
    parser.add_argument('--prefix', type=Path, default=ROOT / 'vendor/ntfs-tools', help='New prefix inside ignored vendor/')
    bootstrap(parser.parse_args())


if __name__ == '__main__':
    main()
