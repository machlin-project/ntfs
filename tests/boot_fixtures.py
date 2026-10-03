"""Original boot owners, reserved replicas and complete diagnostic inventories."""
import struct
import fixtures as f
import validation_fixtures as v
from mirror_fixtures import transform_record

SECTOR_BYTES = (512, 1024, 2048, 4096)
BOOT_RECORD = v.BOOT_RECORD
BOOT_TAIL_LCN = v.ORPHAN_LCN
STAGE_MOUNT, STAGE_ATTRIBUTES, STAGE_BOOT = 1, 3, 10
RESULTS = {'ok': 'success', 'corrupt': 'corrupt metadata',
           'unsupported': 'unsupported format'}
# The named BPB/extended-BPB wire prefix ends with the serial and checksum.
BOOT_CODE_BYTE = struct.calcsize('<3s8sHBHBHHBHHHII4sQQQB3sB3sQI')
SECTOR_PADDING_BYTE = f.SECTOR
TRAILING_RESOURCE_BYTE = 0xa9


def geometry(image, sector):
    """Change BPB sector units without changing 512-byte MST protection units."""
    volume_bytes = f.IMAGE_SIZE
    image = bytearray(image[:volume_bytes])
    assert volume_bytes % sector == 0 and f.CLUSTER % sector == 0
    struct.pack_into('<H', image, f.BOOT_FIELDS['sector_size'], sector)
    image[f.BOOT_FIELDS['cluster_sectors']] = f.CLUSTER // sector
    struct.pack_into('<Q', image, f.BOOT_FIELDS['sectors'], volume_bytes // sector)
    image.extend(image[:sector])
    return image


def author(output, source):
    cases = []

    def save(name, image, result='ok', stage=STAGE_BOOT):
        filename = 'validation-boot-' + name + '.img'
        (output / filename).write_bytes(image)
        expected = {} if result == 'ok' else {'stage': stage}
        if result != 'ok' and stage == STAGE_BOOT:
            expected['record_number'] = str(BOOT_RECORD)
        cases.append({'image': filename, 'result': RESULTS[result],
                      'complete': result == 'ok', 'boot': expected})

    standard = v.build(source, 'standard')
    for sector in SECTOR_BYTES:
        image = geometry(standard, sector)
        save('sector-' + str(sector), image)
        mismatch = bytearray(image)
        mismatch[f.IMAGE_SIZE + BOOT_CODE_BYTE] ^= 1
        save('code-' + str(sector), mismatch, 'corrupt')
        if sector > f.SECTOR:
            mismatch = bytearray(image)
            mismatch[f.IMAGE_SIZE + SECTOR_PADDING_BYTE] ^= 1
            save('padding-' + str(sector), mismatch, 'corrupt')
        save('partial-' + str(sector), image[:-1], 'corrupt')

    for name, options, result, stage in (
            ('missing-data', {'missing': True}, 'corrupt', STAGE_BOOT),
            ('resident', {'resident': True}, 'corrupt', STAGE_BOOT),
            ('wrong-anchor', {'runs': ((1, BOOT_TAIL_LCN),)}, 'corrupt', STAGE_BOOT),
            ('short', {'size': f.SECTOR - 1}, 'corrupt', STAGE_BOOT),
            ('partial-initialization', {'initialized': f.SECTOR - 1}, 'corrupt', STAGE_BOOT),
            ('sparse', {'flags': f.SPARSE}, 'unsupported', STAGE_BOOT),
            ('encrypted', {'flags': f.ENCRYPTED}, 'unsupported', STAGE_ATTRIBUTES),
            ('fragmented', {'runs': ((1, v.BOOT_LCN), (1, BOOT_TAIL_LCN)),
                            'size': f.CLUSTER * 2}, 'ok', STAGE_BOOT),
            ('listed', {'runs': ((1, v.BOOT_LCN), (1, BOOT_TAIL_LCN)),
                        'size': f.CLUSTER * 2, 'listed': True}, 'ok', STAGE_BOOT)):
        save(name, v.build(source, 'standard', boot=v.Boot(**options)), result, stage)

    for name, flags in (('directory-owner', f.FILE_IS_DIRECTORY),
                        ('view-owner', f.FILE_VIEW_INDEX),
                        ('uninterpreted-owner', f.FILE_UNINTERPRETED)):
        image = bytearray(standard)
        offset = f.MFT_LCN * f.CLUSTER + BOOT_RECORD * f.RECORD
        image[offset:offset + f.RECORD] = transform_record(image[offset:offset + f.RECORD],
            fields={'flags': f.FILE_IN_USE | flags})
        save(name, image, 'unsupported')

    for name, field in (('signature', 'signature'), ('oem', 'oem'), ('serial', 'serial'),
                        ('sector-count', 'sectors'), ('mft-anchor', 'mft'),
                        ('mirror-anchor', 'mirror'), ('sector-size', 'sector_size')):
        image = bytearray(standard)
        image[f.IMAGE_SIZE + f.BOOT_FIELDS[field]] ^= 1
        save(name, image, 'corrupt')

    save('missing-replica', standard[:f.IMAGE_SIZE], 'corrupt')
    trailing = bytearray(standard)
    trailing.extend(bytes([TRAILING_RESOURCE_BYTE]) * f.SECTOR)
    save('trailing-resource', trailing)
    # A plausible last-resource sector cannot substitute for the declared copy.
    decoy = bytearray(standard)
    decoy[f.IMAGE_SIZE + f.BOOT_FIELDS['signature']] ^= 1
    decoy.extend(standard[:f.SECTOR])
    save('last-resource-decoy', decoy, 'corrupt')
    return cases
