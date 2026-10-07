#!/usr/bin/env python3
"""Check bounded instrumentation against exact private file transfers."""
from pathlib import Path
import errno
import json
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from environment import sanitizer_environment

NTFS_OK, NTFS_IO, NTFS_RANGE = 0, 4, 11
SECTOR_BYTES, FRAME_BYTES, IMAGE_SLOTS = 512, 4096, 8
PROFILE_WRITES = 48
PROFILE_EVENTS = 1 + PROFILE_WRITES * 2
DEFAULT_EVENTS, DEFAULT_FRAME_BYTES = 32, 1024 * 1024
STORAGE_BYTES = DEFAULT_EVENTS * DEFAULT_FRAME_BYTES
WRITE_MULTIPLIER, BYTE_MULTIPLIER, PATTERN_FIRST, BYTE_VALUES = 29, 7, 11, 256


def invoke(tool, arguments, expected):
    done = subprocess.run([str(tool), *map(str, arguments)], cwd=ROOT,
        env=sanitizer_environment(), stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    assert done.returncode == expected and not done.stderr, (arguments, done.returncode, done.stderr)
    return json.loads(done.stdout)


def expected(capacity, frame_bytes, failed_write, prefix, failed_barrier):
    transfers = [None]
    for index in range(PROFILE_WRITES):
        data = bytes((index * WRITE_MULTIPLIER + byte * BYTE_MULTIPLIER + PATTERN_FIRST) % BYTE_VALUES
            for byte in range(FRAME_BYTES))
        transfers.extend(((index % IMAGE_SLOTS * FRAME_BYTES, data), None))
    image = bytearray(FRAME_BYTES * IMAGE_SLOTS)
    events = []
    writes = barriers = 0
    result, triggered = NTFS_OK, False
    for index, transfer in enumerate(transfers):
        if index == capacity or transfer is not None and len(transfer[1]) > frame_bytes:
            result = NTFS_RANGE
            break
        if transfer is None:
            barriers += 1
            injected = barriers == failed_barrier
            event = dict(barrier=True, physical=0, bytes=0, completed=0,
                native_result=NTFS_OK, result=NTFS_IO if injected else NTFS_OK,
                injected=injected, native_attempted=True)
        else:
            writes += 1
            injected = writes == failed_write
            physical, data = transfer
            completed = prefix if injected else len(data)
            image[physical:physical + completed] = data[:completed]
            event = dict(barrier=False, physical=physical, bytes=len(data), completed=completed,
                native_result=NTFS_OK, result=NTFS_IO if injected else NTFS_OK,
                injected=injected, native_attempted=bool(completed))
        events.append((event, transfer))
        if injected:
            result, triggered = NTFS_IO, True
            break
    return bytes(image), events, writes, barriers, result, triggered


def main():
    tool = Path(sys.argv[1]).resolve()
    profiles = [
        ('complete', 'bounded', PROFILE_EVENTS, FRAME_BYTES, 0, 0, 0),
        ('spare-event', 'bounded', PROFILE_EVENTS + 1, FRAME_BYTES, 0, 0, 0),
        ('last-barrier-capacity', 'bounded', PROFILE_EVENTS - 1, FRAME_BYTES, 0, 0, 0),
        ('default-capacity', 'default', DEFAULT_EVENTS, DEFAULT_FRAME_BYTES, 0, 0, 0),
        ('transfer-capacity', 'bounded', PROFILE_EVENTS, SECTOR_BYTES, 0, 0, 0),
        ('write-empty', 'bounded', PROFILE_EVENTS, FRAME_BYTES, 37, 0, 0),
        ('write-sector', 'bounded', PROFILE_EVENTS, FRAME_BYTES, 37, SECTOR_BYTES, 0),
        ('write-whole', 'bounded', PROFILE_EVENTS, FRAME_BYTES, 37, FRAME_BYTES, 0),
        ('last-write-whole', 'bounded', PROFILE_EVENTS, FRAME_BYTES, PROFILE_WRITES, FRAME_BYTES, 0),
        ('initial-barrier', 'bounded', PROFILE_EVENTS, FRAME_BYTES, 0, 0, 1),
        ('later-barrier', 'bounded', PROFILE_EVENTS, FRAME_BYTES, 0, 0, 39),
        ('last-barrier', 'bounded', PROFILE_EVENTS, FRAME_BYTES, 0, 0, PROFILE_WRITES + 1)]
    invalid = [
        ('zero-events', 0, FRAME_BYTES, 0, 0, 0),
        ('zero-frame', PROFILE_EVENTS, 0, 0, 0, 0),
        ('unaligned-frame', PROFILE_EVENTS, SECTOR_BYTES - 1, 0, 0, 0),
        ('oversize-frame', 1, DEFAULT_FRAME_BYTES + SECTOR_BYTES, 0, 0, 0),
        ('oversize-storage', STORAGE_BYTES // SECTOR_BYTES + 1, SECTOR_BYTES, 0, 0, 0),
        ('both-failures', PROFILE_EVENTS, FRAME_BYTES, 1, 0, 1),
        ('prefix-without-write', PROFILE_EVENTS, FRAME_BYTES, 0, SECTOR_BYTES, 0),
        ('unaligned-prefix', PROFILE_EVENTS, FRAME_BYTES, 1, 1, 0),
        ('oversize-prefix', PROFILE_EVENTS, FRAME_BYTES, 1, FRAME_BYTES + SECTOR_BYTES, 0),
        ('oversize-write', PROFILE_EVENTS, FRAME_BYTES, PROFILE_EVENTS + 1, 0, 0),
        ('oversize-barrier', PROFILE_EVENTS, FRAME_BYTES, 0, 0, PROFILE_EVENTS + 1)]
    with tempfile.TemporaryDirectory(prefix='machlin-ntfs-image-profile-') as temporary:
        root = Path(temporary)
        for label, mode, capacity, frame_bytes, write, prefix, barrier in profiles:
            directory = root / label
            directory.mkdir()
            image = directory / 'private.img'
            image.write_bytes(bytes(FRAME_BYTES * IMAGE_SLOTS))
            wanted, events, writes, barriers, result, triggered = expected(capacity, frame_bytes, write, prefix, barrier)
            report = invoke(tool, [mode, image, capacity, frame_bytes, PROFILE_WRITES, write, prefix, barrier, directory], int(result != NTFS_OK))
            assert report == dict(result=result, triggered=triggered, uncertain=triggered)
            assert image.read_bytes() == wanted
            trace = json.loads((directory / 'events.json').read_text())
            assert not trace['native_failure'] and trace['triggered'] == triggered
            assert trace['event_capacity'] == capacity and trace['event_bytes'] == frame_bytes
            assert (trace['writes'], trace['barriers']) == (writes, barriers)
            assert trace['events'] == [event for event, _ in events]
            for index, (event, transfer) in enumerate(events):
                capture = directory / f'event-{index}.bin'
                assert capture.exists() != event['barrier']
                if transfer is not None:
                    assert capture.read_bytes() == transfer[1]
        for label, capacity, frame_bytes, write, prefix, barrier in invalid:
            directory = root / label
            directory.mkdir()
            image = directory / 'private.img'
            untouched = bytes(FRAME_BYTES * IMAGE_SLOTS)
            image.write_bytes(untouched)
            report = invoke(tool, ['bounded', image, capacity, frame_bytes, PROFILE_WRITES, write, prefix, barrier, directory], 2)
            assert report == dict(open_error=errno.EINVAL)
            assert image.read_bytes() == untouched and not (directory / 'events.json').exists()
    print(f'PASS {len(profiles)} actual transfer profiles and {len(invalid)} before-open refusals')


if __name__ == '__main__':
    main()
