"""Bind original DeallocateFileRecord packets to exact native FILE home LSNs.

This read-only research command does not select current history, execute recovery
or qualify a write protocol. Reused home slots are retained as excluded evidence.
The packet manifest is supplied by the separate complete-local packet observer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests'))
import fixtures as f
import filename_storage as storage
import logfile_fixtures as log
import secure_fixtures as secure
from secure_store_fixtures import resident_value
from write_journal_fixtures import fields

MAX_PACKETS = 4096
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_PACKET_BYTES = log.RECORD.size + log.UPDATE.size + 2 * f.CLUSTER
MAX_MFT_BITMAP_BYTES = 4 * 1024 * 1024
OP_INITIALIZE_FILE = 0x02
OP_DEALLOCATE_FILE = 0x03
MFT_TARGET_FLAGS = 0x02
MFT_RECORD = 0
BITMAP_ATTRIBUTE = f.BITMAP
FILE_IN_USE = 0x01
FILE_DIRECTORY = 0x02
REFERENCE_SEQUENCE_SHIFT = 48
CLUSTER_BLOCK_BYTES = f.SECTOR
BYTE_BITS = 8
WORD = struct.Struct('<H')
WORD_MAX = (1 << (WORD.size * BYTE_BITS)) - 1
RETIREMENT_PREFIX = struct.Struct('<4sHHQHHHH')
RETIREMENT_FIELDS = ('magic', 'usa_offset', 'usa_count', 'lsn', 'sequence',
                     'links', 'attrs_offset', 'flags')


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(4 * 1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def identity(path):
    value = path.stat()
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def read(source, size_bytes, offset, length):
    assert 0 <= offset <= size_bytes and 0 <= length <= size_bytes - offset
    source.seek(offset)
    value = source.read(length)
    assert len(value) == length
    return value


def mapped_read(source, size_bytes, runs, offset, length):
    result = bytearray()
    logical = 0
    for count, lcn in runs:
        run_bytes = count * f.CLUSTER
        if offset < logical + run_bytes and len(result) < length:
            within = max(0, offset - logical)
            take = min(run_bytes - within, length - len(result))
            assert lcn is not None
            result += read(source, size_bytes, lcn * f.CLUSTER + within, take)
            offset += take
        logical += run_bytes
    assert len(result) == length
    return bytes(result)


def lcn_at(runs, vcn):
    first = 0
    for count, lcn in runs:
        if first <= vcn < first + count:
            assert lcn is not None
            return lcn + vcn - first
        first += count
    raise AssertionError('Target VCN is outside the original checked MFT map')


def restore_file(raw):
    value = bytearray(raw)
    header = dict(zip(secure.FILE_HEADER_FIELDS, f.FILE_HEADER.unpack_from(value)))
    assert len(value) == f.RECORD and header['magic'] == b'FILE'
    assert header['usa_offset'] == f.FILE_HEADER.size
    assert header['usa_count'] == f.RECORD // f.SECTOR + 1
    assert header['allocated'] == f.RECORD
    marker = value[header['usa_offset']:header['usa_offset'] + f.U16_BYTES]
    assert marker not in (bytes(f.U16_BYTES), bytes([0xff]) * f.U16_BYTES)
    for sector in range(1, header['usa_count']):
        tail = sector * f.SECTOR - f.U16_BYTES
        saved = header['usa_offset'] + sector * f.U16_BYTES
        assert value[tail:tail + f.U16_BYTES] == marker
        value[tail:tail + f.U16_BYTES] = value[saved:saved + f.U16_BYTES]
    return bytes(value), header


def retain(path, value):
    path.write_bytes(value)
    path.chmod(0o444)
    return dict(path=path.name, bytes=len(value), sha256=hashlib.sha256(value).hexdigest())


def inspect(args):
    image, packets, output = args.image.resolve(), args.packets.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = identity(image)
    assert stat.S_ISREG(before[2]) and not before[2] & 0o222
    source_hash = digest(image)
    manifest_path = packets / 'result.json'
    assert manifest_path.stat().st_size <= MAX_MANIFEST_BYTES
    manifest_hash = digest(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    assert manifest['success'] and manifest['sourceSha256'] == source_hash
    samples = manifest['retainedSamples']
    assert len(samples) <= MAX_PACKETS
    matches, reused, examined = [], [], 0
    with image.open('rb') as source:
        boot = read(source, before[3], 0, f.SECTOR)
        assert WORD.unpack_from(boot, f.BOOT_FIELDS['sector_size'])[0] == f.SECTOR
        assert boot[f.BOOT_FIELDS['cluster_sectors']] * f.SECTOR == f.CLUSTER
        mft_lcn = struct.unpack_from('<Q', boot, f.BOOT_FIELDS['mft'])[0]
        mft_raw = read(source, before[3], mft_lcn * f.CLUSTER, f.RECORD)
        _, mft_header = restore_file(mft_raw)
        header, attributes = storage.record_parts(mft_raw)
        assert header == mft_header and header['number'] == MFT_RECORD
        mft_reference = header['sequence'] << REFERENCE_SEQUENCE_SHIFT
        data = next(value for value in attributes
                    if storage.attr_header(value)['type'] == f.DATA and not storage.attr_name(value))
        sizes, mft_runs = storage.mapping(data)
        assert sizes['lowest'] == 0 and sizes['initialized'] <= sizes['size']
        bitmap_attribute = next(value for value in attributes
                                if storage.attr_header(value)['type'] == BITMAP_ATTRIBUTE
                                and not storage.attr_name(value))
        if storage.attr_header(bitmap_attribute)['nonresident']:
            bitmap_sizes, bitmap_runs = storage.mapping(bitmap_attribute)
            assert bitmap_sizes['lowest'] == 0
            assert bitmap_sizes['initialized'] == bitmap_sizes['size'] <= MAX_MFT_BITMAP_BYTES
            bitmap = mapped_read(source, before[3], bitmap_runs, 0, bitmap_sizes['size'])
        else:
            bitmap = resident_value(bitmap_attribute)
        for sample in samples:
            if sample['update']['redo_operation'] != OP_DEALLOCATE_FILE:
                continue
            examined += 1
            name = sample['path']
            assert Path(name).name == name and name.endswith('.bin')
            packet_path = packets / name
            assert stat.S_ISREG(packet_path.stat().st_mode)
            assert not packet_path.stat().st_mode & 0o222
            assert packet_path.stat().st_size <= MAX_PACKET_BYTES
            packet = packet_path.read_bytes()
            assert hashlib.sha256(packet).hexdigest() == sample['packetSha256']
            record = fields(log.RECORD, packet)
            assert log.RECORD.size + record['data_bytes'] == len(packet)
            body = packet[log.RECORD.size:]
            update = fields(log.UPDATE, body)
            assert update['redo_operation'] == OP_DEALLOCATE_FILE
            assert update['undo_operation'] == OP_INITIALIZE_FILE
            assert update['redo_bytes'] == 0 and update['undo_bytes'] == RETIREMENT_PREFIX.size
            assert update['lcns'] == 1 and update['attribute_flags'] == MFT_TARGET_FLAGS
            assert update['record_offset'] == update['attribute_offset'] == 0
            within = update['cluster_index'] * CLUSTER_BLOCK_BYTES
            assert within % f.RECORD == 0 and within + f.RECORD <= f.CLUSTER
            undo_first = update['undo_offset']
            assert undo_first >= log.UPDATE.size + log.LSN_BYTES
            assert undo_first + RETIREMENT_PREFIX.size <= len(body)
            undo = body[undo_first:undo_first + RETIREMENT_PREFIX.size]
            assert undo.hex() == sample['undoHex']
            prefix = dict(zip(RETIREMENT_FIELDS, RETIREMENT_PREFIX.unpack(undo)))
            assert prefix['magic'] == b'FILE' and prefix['sequence']
            assert prefix['flags'] in (FILE_IN_USE, FILE_IN_USE | FILE_DIRECTORY)
            lcn = struct.unpack_from('<Q', body, log.UPDATE.size)[0]
            assert lcn == lcn_at(mft_runs, update['target_vcn'])
            logical = update['target_vcn'] * f.CLUSTER + within
            assert logical + f.RECORD <= sizes['initialized']
            number = logical // f.RECORD
            raw = read(source, before[3], lcn * f.CLUSTER + within, f.RECORD)
            home, home_header = restore_file(raw)
            assert home_header['number'] == number
            if home_header['lsn'] != record['lsn']:
                reused.append(dict(packet=name, recordNumber=number, packetLsn=record['lsn'],
                                   homeLsn=home_header['lsn'], reason='different-home-LSN'))
                continue
            assert number // BYTE_BITS < len(bitmap)
            assert not bitmap[number // BYTE_BITS] & (1 << (number % BYTE_BITS))
            expected = dict(prefix)
            expected['sequence'] = (prefix['sequence'] + 1) & WORD_MAX or 1
            expected['flags'], expected['lsn'] = 0, record['lsn']
            predicted = RETIREMENT_PREFIX.pack(*(expected[key] for key in RETIREMENT_FIELDS))
            assert home[:RETIREMENT_PREFIX.size] == predicted
            directory = output / f'file-{number}'
            directory.mkdir(exist_ok=False)
            constructed = bytearray(home)
            constructed[:RETIREMENT_PREFIX.size] = undo
            files = [retain(directory / 'packet.original.bin', packet),
                     retain(directory / 'home.protected.bin', raw),
                     retain(directory / 'home.restored.bin', home),
                     retain(directory / 'before-header.original.bin', undo),
                     retain(directory / 'before.constructed.bin', bytes(constructed))]
            matches.append(dict(recordNumber=number, packetLsn=record['lsn'],
                                physicalOffset=lcn * f.CLUSTER + within,
                                beforeSequence=prefix['sequence'], afterSequence=expected['sequence'],
                                beforeLinks=prefix['links'], afterLinks=home_header['links'],
                                beforeFlags=prefix['flags'], afterFlags=home_header['flags'],
                                homeUsedBytes=home_header['used'], files=files))
    assert matches
    assert identity(image) == before and digest(image) == source_hash
    assert digest(manifest_path) == manifest_hash
    result = dict(success=True, sourceUnchanged=True, sourceSha256=source_hash,
                  manifestSha256=manifest_hash, mftReference=mft_reference,
                  examinedPackets=examined, exactHomeLsnMatches=matches, excludedReusedSlots=reused,
                  precedingBodyCaptured=False, currentHistorySelected=False,
                  nativeRecoveryQualified=False, vmUsed=False, productAdmissionChanged=False)
    (output / 'cases.list').write_text(''.join(f"file-{row['recordNumber']}\n" for row in matches))
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(success=True, examined=examined, exactHomeLsnMatches=len(matches),
                         reusedSlots=len(reused), sourceUnchanged=True)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--packets', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        inspect(args)
    except Exception as error:
        if args.output.is_dir() and not (args.output / 'result.json').exists():
            (args.output / 'result.json').write_text(json.dumps(dict(success=False,
                errorType=type(error).__name__, detail=str(error)), indent=2) + '\n')
        raise


if __name__ == '__main__':
    main()
