"""Independent ordinary-index allocation, reachability and unused-storage cases."""
import fixtures as f
import validation_fixtures as v
from mirror_fixtures import geometry, SMALL_GEOMETRY, SMALL_DATA, LARGE_GEOMETRY, LARGE_DATA

BITMAP_BYTES = 513
SUBCLUSTER_BLOCK_BYTES = 1024
STANDARD_BLOCK_BYTES = 4096
STAGE_INDEX_ALLOCATION = 8


def author(output, source):
    manifest = []

    def save(name, image, result='success', cluster=0, owner=None):
        filename = 'validation-index-' + name + '.img'
        (output / filename).write_bytes(image)
        item = {'image': filename, 'result': result, 'complete': result == 'success'}
        if not item['complete']:
            number = f.ROOT_RECORD if owner is None else owner
            item['inventory'] = {'stage': STAGE_INDEX_ALLOCATION,
                                 'record_number': str(number),
                                 'reference': f'{f.file_reference(number):016x}',
                                 'attribute_type': f.BITMAP, 'cluster': str(cluster)}
        manifest.append(item)

    cases = {
        'free-garbage': v.Index(f.CLUSTER, slots=2),
        'orphan-valid': v.Index(f.CLUSTER, slots=2, bitmap=b'\x03', unused_valid=True),
        'orphan-garbage': v.Index(f.CLUSTER, slots=2, bitmap=b'\x03'),
        'outside-allocation': v.Index(f.CLUSTER, bitmap=b'\x03'),
        'padding-used': v.Index(f.CLUSTER, bitmap=bytes([1 | (1 << (f.BYTE_BITS - 1))])),
        'later-used': v.Index(f.CLUSTER, bitmap=b'\x01\x01'),
        'partial-allocation': v.Index(f.CLUSTER, trailing_bytes=1),
        'two-blocks': v.Index(f.CLUSTER, slots=2, split=True, bitmap=b'\x03'),
        'fragmented': v.Index(f.CLUSTER, slots=2, split=True, bitmap=b'\x03', fragmented=True),
        'orphan-fragmented': v.Index(f.CLUSTER, slots=2, bitmap=b'\x03', fragmented=True),
        'resident-paged-bitmap': v.Index(f.CLUSTER, bitmap=b'\x01' + bytes(BITMAP_BYTES - 1)),
        'nonresident-paged-bitmap': v.Index(f.CLUSTER, bitmap=b'\x01' + bytes(BITMAP_BYTES - 1),
                                         bitmap_lcn=v.ORPHAN_LCN),
        'late-bitmap-used': v.Index(f.CLUSTER, bitmap=b'\x01' + bytes(BITMAP_BYTES - 2) + b'\x01',
                                  bitmap_lcn=v.ORPHAN_LCN),
        'leaf-zero-bitmap': v.Index(f.CLUSTER, leaf_bitmap=b'\x00'),
        'leaf-used-bitmap': v.Index(f.CLUSTER, leaf_bitmap=b'\x01'),
        'leaf-free-storage': v.Index(f.CLUSTER, leaf_bitmap=b'\x00', leaf_allocation=True),
    }
    failures = {'orphan-valid': f.INDEX_LCN + 1, 'orphan-garbage': f.INDEX_LCN + 1,
                'outside-allocation': 0, 'padding-used': 0, 'later-used': 0,
                'partial-allocation': 0, 'orphan-fragmented': v.ORPHAN_LCN,
                'late-bitmap-used': 0, 'leaf-used-bitmap': 0}
    for name, layout in cases.items():
        save(name, v.build(source, 'index-inventory', index=layout),
             'corrupt metadata' if name in failures else 'success', failures.get(name, 0),
             v.FIRST_DIRECTORY if name == 'leaf-used-bitmap' else None)

    for orphan in (False, True):
        layout = v.Index(SUBCLUSTER_BLOCK_BYTES, slots=2, split=not orphan, bitmap=b'\x03')
        save('subcluster' + ('-orphan' if orphan else '-two-blocks'),
             v.build(source, 'index-inventory', index=layout),
             'corrupt metadata' if orphan else 'success', f.INDEX_LCN if orphan else 0)
    for prefix, layout, data in (('small-cluster', SMALL_GEOMETRY, SMALL_DATA),
                                 ('large-cluster', LARGE_GEOMETRY, LARGE_DATA)):
        with geometry(source, layout, data) as seed:
            for orphan in (False, True):
                index = v.Index(STANDARD_BLOCK_BYTES, slots=2, split=not orphan, bitmap=b'\x03')
                cluster = f.INDEX_LCN + STANDARD_BLOCK_BYTES // f.CLUSTER
                save(prefix + ('-orphan' if orphan else '-two-blocks'),
                     v.build(seed, 'index-inventory', index=index),
                     'corrupt metadata' if orphan else 'success', cluster if orphan else 0)
    return manifest
