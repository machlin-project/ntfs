#!/usr/bin/env python3
"""Assign unique outer GPT identities to isolated Windows recovery fixtures.

This only changes the two GPT headers and matching entry arrays. Filesystem bytes,
partition geometry, names, type GUIDs and attributes remain exact. Wire fields are
from UEFI 2.10 chapter 5, not a filesystem implementation.
"""
import uuid
import zlib

from logfile_fixtures import Layout
from write_journal_fixtures import fields

SECTOR_BYTES = 512
PRIMARY_HEADER_LBA = 1
GPT_SIGNATURE = b'EFI PART'
GPT_REVISION = 0x00010000
BASIC_DATA_TYPE = uuid.UUID('ebd0a0a2-b9e5-4433-87c0-68b6b72699c7').bytes_le
EMPTY_GUID = bytes(16)
HEADER = Layout((('signature', '8s'), ('revision', 'I'), ('header_bytes', 'I'),
                 ('header_crc32', 'I'), ('reserved', 'I'), ('current_lba', 'Q'),
                 ('backup_lba', 'Q'), ('first_usable_lba', 'Q'), ('last_usable_lba', 'Q'),
                 ('disk_guid', '16s'), ('entries_lba', 'Q'), ('entries_count', 'I'),
                 ('entry_bytes', 'I'), ('entries_crc32', 'I')))
ENTRY = Layout((('type_guid', '16s'), ('unique_guid', '16s'), ('first_lba', 'Q'),
                ('last_lba', 'Q'), ('attributes', 'Q'), ('name', '72s')))
MAX_ENTRIES_BYTES = 1024 * 1024


def read_at(source, first, length):
    source.seek(first)
    value = source.read(length)
    assert len(value) == length
    return value


def checked_header(source, lba, disk_bytes):
    raw = read_at(source, lba * SECTOR_BYTES, SECTOR_BYTES)
    header = fields(HEADER, raw)
    assert header['signature'] == GPT_SIGNATURE and header['revision'] == GPT_REVISION
    assert header['header_bytes'] == HEADER.size and header['reserved'] == 0
    assert header['current_lba'] == lba and header['backup_lba'] < disk_bytes // SECTOR_BYTES
    assert HEADER.size <= SECTOR_BYTES and not any(raw[HEADER.size:])
    checksum = bytearray(raw[:header['header_bytes']])
    HEADER.put(checksum, 'header_crc32', 0)
    assert zlib.crc32(checksum) == header['header_crc32']
    assert header['entry_bytes'] == ENTRY.size and header['entries_count'] > 0
    entries_bytes = header['entries_count'] * header['entry_bytes']
    assert entries_bytes <= MAX_ENTRIES_BYTES
    entries_first = header['entries_lba'] * SECTOR_BYTES
    assert entries_first + entries_bytes <= disk_bytes
    entries = read_at(source, entries_first, entries_bytes)
    assert zlib.crc32(entries) == header['entries_crc32']
    return raw, header, entries


def unique_gpt(source, disk_bytes, partition_first, partition_bytes):
    """Return exact outer-container patches and the new disk/partition UUIDs."""
    primary = checked_header(source, PRIMARY_HEADER_LBA, disk_bytes)
    backup = checked_header(source, primary[1]['backup_lba'], disk_bytes)
    assert backup[1]['backup_lba'] == PRIMARY_HEADER_LBA
    assert backup[1]['current_lba'] == disk_bytes // SECTOR_BYTES - 1
    assert primary[2] == backup[2]
    for key in ('first_usable_lba', 'last_usable_lba', 'disk_guid',
                'entries_count', 'entry_bytes', 'entries_crc32'):
        assert primary[1][key] == backup[1][key]
    assert partition_first % SECTOR_BYTES == partition_bytes % SECTOR_BYTES == 0
    entries = bytearray(primary[2])
    disk_id = uuid.uuid4()
    partition_id = None
    for index in range(primary[1]['entries_count']):
        first = index * ENTRY.size
        entry = fields(ENTRY, entries, first)
        if entry['type_guid'] == EMPTY_GUID:
            assert entries[first:first + ENTRY.size] == bytes(ENTRY.size)
            continue
        assert primary[1]['first_usable_lba'] <= entry['first_lba'] <= entry['last_lba'] <= primary[1]['last_usable_lba']
        identity = uuid.uuid4()
        ENTRY.put(entries, 'unique_guid', identity.bytes_le, first)
        if entry['type_guid'] == BASIC_DATA_TYPE:
            assert partition_id is None
            assert entry['first_lba'] * SECTOR_BYTES == partition_first
            assert (entry['last_lba'] - entry['first_lba'] + 1) * SECTOR_BYTES == partition_bytes
            partition_id = identity
    assert partition_id is not None and disk_id.bytes_le != primary[1]['disk_guid']
    patches = []
    for raw, header, _ in (primary, backup):
        replacement = bytearray(raw)
        HEADER.put(replacement, 'disk_guid', disk_id.bytes_le)
        HEADER.put(replacement, 'entries_crc32', zlib.crc32(entries))
        HEADER.put(replacement, 'header_crc32', 0)
        HEADER.put(replacement, 'header_crc32', zlib.crc32(replacement[:header['header_bytes']]))
        patches.append((header['current_lba'] * SECTOR_BYTES, bytes(replacement)))
        patches.append((header['entries_lba'] * SECTOR_BYTES, bytes(entries)))
    for first, value in patches:
        assert first + len(value) <= partition_first or first >= partition_first + partition_bytes
    return patches, str(disk_id), str(partition_id)
