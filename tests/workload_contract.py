#!/usr/bin/env python3
"""Verify measured read ranges, cache accounting and concurrent owner teardown."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

import fixtures as f

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import tool_environment

SAMPLE_BYTES = 64
UINT32_MASK = (1 << 32) - 1
UINT64_MASK = (1 << 64) - 1
RANDOM_MULTIPLIER = 1664525
RANDOM_INCREMENT = 1013904223
RANDOM_SEED = 0x85A7F12D
OPERATIONS = 29
WARMUP_OPERATIONS = 13
READERS = 3


def expected_read(data, profile, request, operations, warmup, readers):
    """Independent byte oracle for the documented deterministic request schedule."""
    total_bytes = sampled_sum = 0
    for reader in range(readers):
        measured = operations // readers + (reader < operations % readers)
        skipped = warmup // readers + (reader < warmup % readers)
        offset, random = 0, RANDOM_SEED + reader
        for operation in range(skipped + measured):
            if profile == 'random':
                random = (random * RANDOM_MULTIPLIER + RANDOM_INCREMENT) & UINT32_MASK
                high = random << 32
                random = (random * RANDOM_MULTIPLIER + RANDOM_INCREMENT) & UINT32_MASK
                offset = (high | random) % (max(0, len(data) - request) + 1)
            value = data[offset:offset + request]
            if operation >= skipped:
                total_bytes += len(value)
                sampled_sum += sum(value[:SAMPLE_BYTES])
            offset += len(value)
            if offset >= len(data):
                offset = 0
    return total_bytes, sampled_sum & UINT64_MASK


def main():
    workload, inspector = (Path(value).resolve() for value in sys.argv[1:3])
    env = tool_environment()
    image, contents, _ = f.make_image()
    checks = 0
    with tempfile.TemporaryDirectory(prefix='ntfs-workload-contract-') as temporary:
        directory = Path(temporary)
        source = directory / 'source.img'
        source.write_bytes(image)
        original_hash = hashlib.sha256(image).hexdigest()

        def run(path, profile, *, backend='posix', operations=OPERATIONS,
                warmup=0, request=4096, readers=1, cache=64, stream='', image_path=source):
            nonlocal checks
            command = [str(workload), str(image_path), path, '--profile', profile,
                       '--backend', backend, '--operations', str(operations),
                       '--warmup-operations', str(warmup), '--request', str(request),
                       '--readers', str(readers), '--cache-entries', str(cache),
                       '--stream', stream]
            process = subprocess.run(command, env=env, capture_output=True, timeout=30)
            assert process.returncode == 0, (command, process.stderr.decode(errors='replace'))
            result = json.loads(process.stdout)
            assert result['profile'] == profile and result['backend'] == backend
            assert result['readers'] == readers and result['operations'] == operations
            assert result['warmup_operations'] == warmup
            assert 0 <= result['p50_ns'] <= result['p95_ns'] <= result['p99_ns']
            assert result['wall_clock_resolution_ns'] > 0
            assert result['wall_ns'] > 0 and result['cpu_ns'] > 0
            assert 0 < result['peak_core_bytes'] <= 64 * 1024 * 1024
            assert result['peak_rss_bytes'] > 0
            checks += 1
            return result

        # Full byte equality precedes measurements; sampling alone is not integrity evidence.
        for name, expected in contents.items():
            actual = subprocess.check_output([str(inspector), str(source), 'cat', '/' + name],
                                             env=env, timeout=30)
            assert actual == expected, name
        for name in ('hello.txt', 'fragmented.bin', 'extended.bin', 'sparse.bin',
                     'tail.bin', 'compressed.bin'):
            for profile in ('sequential', 'random'):
                request = 37 if name == 'hello.txt' else 4096
                expected_bytes, expected_sum = expected_read(contents[name], profile, request,
                                                              OPERATIONS, WARMUP_OPERATIONS, READERS)
                posix = run('/' + name, profile, request=request, readers=READERS,
                            warmup=WARMUP_OPERATIONS)
                memory = run('/' + name, profile, request=request, readers=READERS,
                             warmup=WARMUP_OPERATIONS, backend='memory')
                for result in (posix, memory):
                    assert result['bytes'] == expected_bytes, (name, result)
                    assert int(result['sampled_sum'], 16) == expected_sum, (name, result)
                for field in ('read_calls', 'read_bytes', 'allocations', 'record_cache_hits',
                              'record_cache_misses', 'peak_core_bytes'):
                    assert posix[field] == memory[field], (name, field, posix, memory)

        alternate = b'alternate payload'
        result = run('/streamed.txt', 'random', stream='notes')
        assert result['bytes'] == len(alternate) * OPERATIONS
        assert int(result['sampled_sum'], 16) == sum(alternate) * OPERATIONS
        assert result['read_calls'] == 0  # Resident content, with setup excluded.
        fresh = run('/compressed.bin', 'sequential', request=17)
        warmed = run('/compressed.bin', 'sequential', request=17, warmup=1)
        assert fresh['read_calls'] > 0 and warmed['read_calls'] == 0
        cached = run('/extended.bin', 'open')
        uncached = run('/extended.bin', 'open', cache=0)
        assert int(cached['sampled_sum'], 16) == len(contents['extended.bin']) * OPERATIONS
        assert uncached['read_calls'] > cached['read_calls']
        assert uncached['record_cache_misses'] > 0 and uncached['record_cache_hits'] == 0
        lookup = run('/hello.txt', 'lookup', readers=READERS)
        assert int(lookup['sampled_sum'], 16) == f.file_reference(f.FILE_RECORDS['hello.txt']) * OPERATIONS
        full_scan = run('/', 'directory-scan', operations=7, readers=READERS)
        assert full_scan['entries'] == len(contents) * 7
        names = sorted(contents, key=str.upper)
        summed = sum(f.file_reference(f.FILE_RECORDS[name]) + len(name.encode('utf-16le')) // f.U16_BYTES
                     for name in names)
        assert int(full_scan['sampled_sum'], 16) == summed * 7
        cursor = run('/', 'directory-next', readers=READERS, warmup=WARMUP_OPERATIONS)
        assert cursor['entries'] == OPERATIONS
        expected_cursor_sum = 0
        for reader in range(READERS):
            skipped = WARMUP_OPERATIONS // READERS + (reader < WARMUP_OPERATIONS % READERS)
            measured = OPERATIONS // READERS + (reader < OPERATIONS % READERS)
            for operation in range(skipped, skipped + measured):
                name = names[operation % len(names)]
                expected_cursor_sum += f.file_reference(f.FILE_RECORDS[name]) + len(name.encode('utf-16le')) // f.U16_BYTES
        assert int(cursor['sampled_sum'], 16) == expected_cursor_sum

        # Multi-GiB offsets must remain wide; fully sparse content requires no backing reads.
        sparse = bytearray(image)
        f.put_record(sparse, f.FILE_RECORDS['fragmented.bin'], f.file_record(
            f.FILE_RECORDS['fragmented.bin'], [f.standard(f.FILE_ATTRIBUTE_SPARSE),
                f.nonresident(f.DATA, [(f.LARGE_SPARSE_BYTES // f.CLUSTER, None)],
                              f.LARGE_SPARSE_BYTES, 1, flags=f.SPARSE)]))
        sparse_path = directory / 'large-sparse.img'
        sparse_path.write_bytes(sparse)
        result = run('/fragmented.bin', 'random', readers=READERS, image_path=sparse_path)
        assert result['bytes'] == OPERATIONS * 4096
        assert int(result['sampled_sum'], 16) == 0 and result['read_calls'] == 0
        assert hashlib.sha256(sparse_path.read_bytes()).digest() == hashlib.sha256(sparse).digest()

        for arguments in (['--operations', '0'], ['--operations', '-1'],
                          ['--operations', '1000001'], ['--request', '1048577'],
                          ['--readers', '65'], ['--profile', 'unknown'],
                          ['--backend', 'unknown'], ['--warmup-operations', '-1'],
                          ['--operations', '1', '--readers', '2']):
            invalid = subprocess.run([str(workload), str(source), '/hello.txt', *arguments],
                                     env=env, capture_output=True, timeout=30)
            assert invalid.returncode == 2 and not invalid.stdout, arguments
        failure = subprocess.run([str(workload), str(source), '/missing', '--profile', 'open'],
                                 env=env, capture_output=True, timeout=30)
        assert failure.returncode == 1 and not failure.stdout
        assert hashlib.sha256(source.read_bytes()).hexdigest() == original_hash
    print(f'PASS: {checks} measured profiles, byte oracles, cache controls, serialized readers and immutable images')


if __name__ == '__main__':
    main()
