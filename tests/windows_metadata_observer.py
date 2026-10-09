"""Pure native-record identity binding tests; no Windows provider is fabricated."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import observe_windows_metadata as observer

RECORD_NUMBER = 53
SEQUENCE = 7
REFERENCE = (SEQUENCE << observer.REFERENCE_RECORD_BITS) | RECORD_NUMBER


def packet(returned=REFERENCE):
    record = bytearray(observer.PROBE_RECORD_BYTES)
    record[:4] = b'FILE'
    struct.pack_into('<H', record, observer.FILE_SEQUENCE_OFFSET, SEQUENCE)
    struct.pack_into('<H', record, observer.FILE_FLAGS_OFFSET, observer.FILE_RECORD_IN_USE)
    struct.pack_into('<I', record, observer.FILE_NUMBER_OFFSET, RECORD_NUMBER)
    return bytearray(bytes(observer.FileRecordOutput(returned, len(record))) + record)


class NativeRecordIdentity(unittest.TestCase):
    def test_binds_exact_ordinal_and_file_header_sequence(self):
        # Literal FILE prefix and FSCTL header authored independently of the
        # structures and offset helpers under test: record 53, generation 7.
        golden_output = bytes.fromhex('3500000000000700 00040000')
        golden_file = bytes.fromhex(
            '46494c45 3000 0300 0504030201000000 0700 0200 3800 0100 '
            '80000000 00040000 0000000000000000 0400 0000 35000000')
        golden = golden_output + golden_file + bytes(observer.PROBE_RECORD_BYTES - len(golden_file))
        result = observer.verify_record(REFERENCE, golden, observer.PROBE_RECORD_BYTES)
        self.assertEqual((result['sequence'], result['record_number']), (7, '53'))
        header = observer.FileHeader.from_buffer_copy(golden_file)
        self.assertEqual((header.usa_offset, header.usa_count, header.lsn, header.links,
                          header.attributes_offset, header.used_bytes, header.allocated_bytes,
                          header.next_attribute), (48, 3, 0x0102030405, 2, 56, 128, 1024, 4))
        for returned in (REFERENCE, RECORD_NUMBER):
            with self.subTest(returned=returned):
                raw = packet(returned)
                before = bytes(raw)
                result = observer.verify_record(REFERENCE, raw, observer.PROBE_RECORD_BYTES)
                self.assertEqual(result['requested_reference'], f'{REFERENCE:016x}')
                self.assertEqual(result['returned_reference'], f'{returned:016x}')
                self.assertEqual(result['sequence'], SEQUENCE)
                self.assertEqual(result['record_number'], str(RECORD_NUMBER))
                self.assertEqual(bytes(raw), before)

    def test_refuses_downward_substitution_and_wrong_generation(self):
        for returned in (RECORD_NUMBER - 1, REFERENCE - 1,
                         ((SEQUENCE + 1) << observer.REFERENCE_RECORD_BITS) | RECORD_NUMBER):
            with self.subTest(returned=returned), self.assertRaises(ValueError):
                observer.verify_record(REFERENCE, packet(returned), observer.PROBE_RECORD_BYTES)
        for offset, format_, value in (
                (observer.FILE_SEQUENCE_OFFSET, '<H', SEQUENCE + 1),
                (observer.FILE_NUMBER_OFFSET, '<I', RECORD_NUMBER - 1),
                (observer.FILE_BASE_REFERENCE_OFFSET, '<Q', REFERENCE),
                (observer.FILE_FLAGS_OFFSET, '<H', 0)):
            raw = packet()
            struct.pack_into(format_, raw, observer.RECORD_OUTPUT_BYTES + offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                observer.verify_record(REFERENCE, raw, observer.PROBE_RECORD_BYTES)

    def test_refuses_short_oversized_and_unqualified_records(self):
        raw = packet()
        cases = [(REFERENCE, raw[:size], observer.PROBE_RECORD_BYTES)
                 for size in (0, observer.RECORD_OUTPUT_BYTES - 1, len(raw) - 1)]
        cases += [(REFERENCE, raw + bytes(5), observer.PROBE_RECORD_BYTES),
                  (REFERENCE, raw, observer.PROBE_RECORD_BYTES * 2),
                  (RECORD_NUMBER, raw, observer.PROBE_RECORD_BYTES),
                  (-1, raw, observer.PROBE_RECORD_BYTES),
                  (1 << 64, raw, observer.PROBE_RECORD_BYTES)]
        bad_magic = packet()
        bad_magic[observer.RECORD_OUTPUT_BYTES:observer.RECORD_OUTPUT_BYTES + 4] = b'BAAD'
        cases.append((REFERENCE, bad_magic, observer.PROBE_RECORD_BYTES))
        bad_length = packet()
        struct.pack_into('<I', bad_length, observer.FileRecordOutput.length.offset, observer.PROBE_RECORD_BYTES - 1)
        cases.append((REFERENCE, bad_length, observer.PROBE_RECORD_BYTES))
        for reference, data, record_bytes in cases:
            with self.subTest(reference=reference, length=len(data), record_bytes=record_bytes), self.assertRaises(ValueError):
                observer.verify_record(reference, data, record_bytes)


if __name__ == '__main__':
    unittest.main()
