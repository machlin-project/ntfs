#!/usr/bin/env python3
"""Portable scratch-input admission contracts; these are not Windows evidence."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import windows_cloud_inputs as cloud


def authored_geometry():
    return dict(schema_version=1, provenance='Windows native scratch VHD bootstrap',
        acquisition_status='complete', stage='complete', errors=[], automatic_retry=False,
        native_recovery_qualified=False, platform=dict(system='Windows', version='test only'),
        volume_lock_and_flush_succeeded=True,
        root_name='MachlinCloudNTFS-' + '1' * 32, disk_bytes=256 * cloud.MIB,
        protected_disk_numbers=[0, 1],
        disk=dict(Number=4, Size=256 * cloud.MIB, LogicalSectorSize=512, IsBoot=False,
                  IsSystem=False, UniqueId='test-only', Guid='55b1872c-235f-447e-af3c-32a015c5a7d6'),
        partition=dict(Offset=16 * cloud.MIB, Size=239 * cloud.MIB, PartitionNumber=2,
                       IsBoot=False, IsSystem=False, Guid='637edc09-bb66-4b70-a3b8-e50393b5dafb',
                       GptType=str(cloud.BASIC_DATA_TYPE)))


class CloudInputContracts(unittest.TestCase):
    def test_exact_native_geometry(self):
        source = authored_geometry()
        self.assertEqual(cloud.geometry(source), (256 * cloud.MIB, 16 * cloud.MIB, 239 * cloud.MIB))
        for field, value in (('acquisition_status', 'partial'), ('stage', 'failed'),
                             ('provenance', 'synthetic'), ('automatic_retry', True),
                             ('native_recovery_qualified', True), ('errors', ['original error']),
                             ('volume_lock_and_flush_succeeded', False),
                             ('root_name', '../escape'), ('disk_bytes', True),
                             ('disk_bytes', 4097 * cloud.MIB)):
            changed = copy.deepcopy(source)
            changed[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                cloud.geometry(changed)

    def test_reject_system_boot_existing_disks_and_partition_drift(self):
        source = authored_geometry()
        for owner, field, value in (
                ('disk', 'Number', 0), ('disk', 'Number', True), ('disk', 'IsBoot', True),
                ('disk', 'IsSystem', True), ('disk', 'LogicalSectorSize', 4096),
                ('disk', 'Size', 128 * cloud.MIB), ('disk', 'Guid', str(uuid.UUID(int=0))),
                ('partition', 'IsBoot', True), ('partition', 'IsSystem', True),
                ('partition', 'Offset', 512), ('partition', 'Offset', 16 * cloud.MIB + 1),
                ('partition', 'Size', 256 * cloud.MIB), ('partition', 'Size', -512),
                ('partition', 'Size', True), ('partition', 'PartitionNumber', 0),
                ('partition', 'GptType', '55b1872c-235f-447e-af3c-32a015c5a7d6')):
            changed = copy.deepcopy(source)
            changed[owner][field] = value
            with self.subTest(owner=owner, field=field), self.assertRaises(ValueError):
                cloud.geometry(changed)

    def test_artifact_containment_type_and_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            # Darwin's temporary directory may start with the /var symlink.
            # Admission deliberately requires a canonical artifact root.
            directory = Path(temporary).resolve()
            plain = directory / 'plain.bin'
            plain.write_bytes(b'original bytes')
            self.assertEqual(cloud.plain_file(directory, 'plain.bin'), plain)
            cloud.checked_hash(plain, hashlib.sha256(b'original bytes').hexdigest())
            for name in ('../escape', '/etc/passwd', 'C:/escaped', 'a\\b', ''):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    cloud.plain_file(directory, name)
            (directory / 'alias').symlink_to(plain)
            with self.assertRaises(ValueError):
                cloud.plain_file(directory, 'alias')
            (directory / 'directory-alias').symlink_to(directory, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symbolic-link ancestor'):
                cloud.plain_file(directory / 'directory-alias', 'plain.bin')
            with self.assertRaises(ValueError):
                cloud.checked_hash(plain, '0' * 64)
            (directory / 'hardlink').hardlink_to(plain)
            with self.assertRaises(ValueError):
                cloud.plain_file(directory, 'plain.bin')

    def test_duplicate_and_oversized_manifests(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'manifest.json'
            path.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(ValueError):
                cloud.json_file(path)
            with path.open('wb') as output:
                output.truncate(cloud.MAX_MANIFEST_BYTES + 1)
            with self.assertRaises(ValueError):
                cloud.json_file(path)

    def test_unknown_native_root_and_missing_workload_fail(self):
        source = authored_geometry()
        with self.assertRaises(ValueError):
            cloud.baseline(source, dict(entries=[]))
        entry = dict(path_utf16=[list(map(ord, 'different'))])
        with self.assertRaises(ValueError):
            cloud.baseline(source, dict(entries=[entry]))

    def test_manifest_geometry_overlay_preserves_outer_bytes(self):
        from native_directory_package import overlay_partition
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            raw, image = directory / 'disk.raw', directory / 'partition.ntfs'
            original = bytes((index * 13 + 7) % 256 for index in range(2048))
            partition = b'a' * 1024
            raw.write_bytes(original)
            image.write_bytes(partition)
            overlay_partition(image, raw, hashlib.sha256(partition).hexdigest(), 512, 1024, 2048)
            observed = raw.read_bytes()
            self.assertEqual(observed, original[:512] + partition + original[1536:])
            self.assertEqual(image.read_bytes(), partition)
            with self.assertRaises(AssertionError):
                overlay_partition(image, raw, hashlib.sha256(partition).hexdigest(), 512, 512, 2048)


if __name__ == '__main__':
    unittest.main()
