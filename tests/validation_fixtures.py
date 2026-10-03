"""Author complete metadata inventories for the diagnostic's supported scope.

These are original synthetic images, not Windows-authored qualification. Stored
filename sizes may be stale; the independent allocation set is authoritative.
"""
import json
import struct
from dataclasses import dataclass
import fixtures as f

MIRROR_RECORD = 1
LOGFILE_RECORD = 2
BOOT_RECORD = 7
BAD_CLUSTERS_RECORD = 8
HELLO_RECORD = 24
FRAGMENTED_RECORD = 25
EXTRA_RECORD = 26
FIRST_DIRECTORY = 48
SECOND_DIRECTORY = 49
FRAGMENT_MIN_CLUSTERS = 2
EXTENSION_RECORD = 40
RESERVED_FIRST, RESERVED_LAST = 12, 15
MIRROR_RECORDS = 4
SI_INSTANCE = 0
FILENAME_INSTANCE = 1
DATA_INSTANCE = 2
LIST_INSTANCE = 3
EXTRA_FILENAME_INSTANCE = 4
FILENAME_INSTANCES = (FILENAME_INSTANCE, EXTRA_FILENAME_INSTANCE)
ADDITIONAL_FILENAME_INSTANCE = 16
ADS_INSTANCE = 5
SECURITY_INSTANCE = 6
SECURITY_ATTRIBUTE = 0x50
SECURITY_REVISION = 1
SECURITY_SELF_RELATIVE = 0x8000
SECURITY_HEADER = struct.Struct('<BBHIIII')
ROOT_INDEX_INSTANCE = 2
ROOT_ALLOCATION_INSTANCE = 3
ROOT_BITMAP_INSTANCE = 4
MFT_BITMAP_INSTANCE = 3
VOLUME_NAME_INSTANCE = 3
VOLUME_INFO_INSTANCE = 4
BOOT_LCN = 0
FIRST_DATA_LCN, SECOND_DATA_LCN = 128, 130
ORPHAN_LCN = 160
UPCASE_UNITS = 1 << (f.U16_BYTES * f.BYTE_BITS)
MFT_BYTES = f.MFT_COUNT * f.RECORD
VOLUME_INFORMATION = struct.Struct('<8xBBH')
INDEX_STREAM_NAME = '$I30'
INDEX_UNUSED_STORAGE_BYTE = 0xa9
HELLO_DATA = b'validation resident data'
FRAGMENTED_DATA = f.pattern(f.FRAGMENTED_BYTES)


def standard(attributes=0, **fields):
    # These focused inventories omit $Secure. Indexed references are authored
    # separately by secure_store_fixtures; active files have per-file descriptors.
    return f.standard(attributes, security_id=0, **fields)


def security():
    # A self-relative descriptor with absent owner/group/ACLs is valid metadata;
    # these inventories make no access decision from that descriptor.
    payload = SECURITY_HEADER.pack(SECURITY_REVISION, 0, SECURITY_SELF_RELATIVE,
                                   0, 0, 0, 0)
    return f.resident(SECURITY_ATTRIBUTE, payload, SECURITY_INSTANCE)


@dataclass(frozen=True)
class Link:
    name: str
    parent: int = f.ROOT_REF
    namespace: int = f.NAMESPACE_WIN32
    size: int = 0


@dataclass(frozen=True)
class Mirror:
    runs: tuple
    size: int = MIRROR_RECORDS * f.RECORD
    initialized: int | None = None
    flags: int = 0
    missing: bool = False
    resident: bool = False
    listed: bool = False
    list_lcn: int | None = None


@dataclass(frozen=True)
class Boot:
    runs: tuple = ((1, BOOT_LCN),)
    size: int | None = None
    initialized: int | None = None
    flags: int = 0
    missing: bool = False
    resident: bool = False
    listed: bool = False


@dataclass(frozen=True)
class Index:
    block_bytes: int
    slots: int = 1
    split: bool = False
    bitmap: bytes = b'\x01'
    bitmap_lcn: int | None = None
    fragmented: bool = False
    unused_valid: bool = False
    leaf_bitmap: bytes | None = None
    leaf_allocation: bool = False
    trailing_bytes: int = 0


def filename(link, instance=FILENAME_INSTANCE, directory=False):
    attributes = f.FILE_ATTRIBUTE_DIRECTORY if directory else 0
    return f.resident(f.FILENAME, f.key(link.name, link.size, link.namespace,
                                     link.parent, attributes), instance)


def index_entry(number, link, directory=False, reference=None, child=None):
    encoded = bytearray(f.entry(link.name, number, link.size,
                               namespace=link.namespace, parent=link.parent,
                               attributes=f.FILE_ATTRIBUTE_DIRECTORY if directory else 0,
                               child=child))
    if reference is not None:
        _, length, key_length, flags = f.INDEX_ENTRY.unpack_from(encoded)
        f.INDEX_ENTRY.pack_into(encoded, 0, reference, length, key_length, flags)
    return bytes(encoded)


def collation(item):
    _, link, _ = item
    raw = link.name.encode('utf-16le', errors='surrogatepass')
    units = struct.unpack('<' + 'H' * (len(raw) // f.U16_BYTES), raw)
    folded = tuple(unit - ord('a') + ord('A') if ord('a') <= unit <= ord('z')
                   else unit for unit in units)
    return folded, units


def root_value(entries, external=False, block_bytes=None):
    block_bytes = f.CLUSTER if block_bytes is None else block_bytes
    unit = f.CLUSTER if f.CLUSTER <= block_bytes else f.SECTOR
    return (f.INDEX_ROOT_HEADER.pack(f.FILENAME, f.COLLATION_FILENAME,
                                    block_bytes, block_bytes // unit)
            + f.INDEX_HEADER.pack(f.INDEX_HEADER.size, f.INDEX_HEADER.size + len(entries),
                                  f.INDEX_HEADER.size + len(entries),
                                  f.INDEX_LARGE if external else 0) + entries)


def build(source, case, *, mirror=None, index=None, boot=None,
          links_override=None, directory_records=()):
    image = bytearray(source)
    if mirror is None:
        clusters = (MIRROR_RECORDS * f.RECORD + f.CLUSTER - 1) // f.CLUSTER
        mirror = Mirror(((clusters, f.MIRROR_LCN),))
    boot = Boot() if boot is None else boot
    assert not (mirror.listed and boot.listed)
    f.put_data(image, f.MFT_LCN, bytes(MFT_BYTES))
    links = {
        f.MFT_RECORD: [Link('$MFT')], MIRROR_RECORD: [Link('$MFTMirr')],
        f.VOLUME_RECORD: [Link('$Volume')], f.ROOT_RECORD: [Link('.')],
        f.BITMAP_RECORD: [Link('$Bitmap')], BOOT_RECORD: [Link('$Boot')],
        f.UPCASE_RECORD: [Link('$UpCase')], HELLO_RECORD: [Link('hello.txt')],
        FRAGMENTED_RECORD: [Link('fragmented.bin')],
    }
    directories = {f.ROOT_RECORD}
    if case == 'logfile-empty':
        links[LOGFILE_RECORD] = [Link('$LogFile')]
    if index is not None:
        image[f.BOOT_FIELDS['index_code']] = -(index.block_bytes.bit_length() - 1) % f.BYTE_VALUES
        if index.leaf_bitmap is not None:
            directories.add(FIRST_DIRECTORY)
            links[FIRST_DIRECTORY] = [Link('empty')]
    records = {}
    fragmented_clusters = max(FRAGMENT_MIN_CLUSTERS,
                              (f.FRAGMENTED_BYTES + f.CLUSTER - 1) // f.CLUSTER)
    occupied = {BOOT_LCN, f.INDEX_LCN, FIRST_DATA_LCN, SECOND_DATA_LCN}
    for clusters, lcn in boot.runs:
        if lcn is not None:
            occupied.update(range(lcn, lcn + clusters))
    for clusters, lcn in mirror.runs:
        if lcn is not None:
            occupied.update(range(lcn, lcn + clusters))
    if mirror.list_lcn is not None:
        occupied.add(mirror.list_lcn)
    occupied.update(range(f.MFT_LCN, f.MFT_LCN + MFT_BYTES // f.CLUSTER))
    occupied.update(range(f.UPCASE_LCN, f.UPCASE_LCN + UPCASE_UNITS * f.U16_BYTES // f.CLUSTER))
    occupied.update(range(SECOND_DATA_LCN, SECOND_DATA_LCN + fragmented_clusters - 1))
    first_lcn, second_lcn = FIRST_DATA_LCN, SECOND_DATA_LCN
    if case == 'overlap-streams':
        first_lcn = f.UPCASE_LCN
        occupied.discard(FIRST_DATA_LCN)
    if case == 'self-overlap':
        second_lcn = FIRST_DATA_LCN
        occupied.discard(SECOND_DATA_LCN)

    if case == 'sensitive':
        links[HELLO_RECORD] = [Link('Foo.txt')]
        links[FRAGMENTED_RECORD] = [Link('foo.txt')]
    if case == 'hardlinks':
        links[HELLO_RECORD].append(Link('other-hello.txt'))
    if case in ('dos', 'dos-header-count-low', 'dos-header-count-high'):
        links[HELLO_RECORD].append(Link('HELLO~1.TXT', namespace=f.NAMESPACE_DOS))
    elif case == 'dos-only':
        links[HELLO_RECORD] = [Link('HELLO~1.TXT', namespace=f.NAMESPACE_DOS)]
    elif case == 'combined-name':
        links[HELLO_RECORD] = [Link('HELLO.TXT', namespace=f.NAMESPACE_WIN32_DOS)]
    elif case in ('dos-hardlinks', 'dos-nested-hardlinks'):
        if case == 'dos-nested-hardlinks':
            directories.update((FIRST_DIRECTORY, SECOND_DIRECTORY))
            links[FIRST_DIRECTORY] = [Link('first')]
            links[SECOND_DIRECTORY] = [Link('second')]
            parents = (f.file_reference(FIRST_DIRECTORY), f.file_reference(SECOND_DIRECTORY))
        else:
            parents = (f.ROOT_REF, f.ROOT_REF)
        links[HELLO_RECORD] = [
            Link('hello.txt', parent=parents[0]),
            Link('HELLO~1.TXT', parent=parents[0], namespace=f.NAMESPACE_DOS),
            Link('other-hello.txt', parent=parents[1]),
            Link('OTHERH~1.TXT', parent=parents[1], namespace=f.NAMESPACE_DOS)]
    elif case == 'dos-directory':
        directories.add(FIRST_DIRECTORY)
        links[FIRST_DIRECTORY] = [Link('directory'), Link('DIRECT~1', namespace=f.NAMESPACE_DOS)]
    if case == 'stale-cached-sizes':
        links[HELLO_RECORD] = [Link('hello.txt', size=f.LARGE_SPARSE_BYTES)]
        links[FRAGMENTED_RECORD] = [Link('fragmented.bin', size=1)]
    if case in ('nested', 'directory-cycle'):
        directories.update((FIRST_DIRECTORY, SECOND_DIRECTORY))
        first_parent = (f.file_reference(SECOND_DIRECTORY)
                        if case == 'directory-cycle' else f.ROOT_REF)
        links[FIRST_DIRECTORY] = [Link('first', parent=first_parent)]
        links[SECOND_DIRECTORY] = [Link('second', parent=f.file_reference(FIRST_DIRECTORY))]
    if case.startswith('bad-clusters-'):
        links[BAD_CLUSTERS_RECORD] = [Link('$BadClus')]
    if case == 'missing-root-anchor':
        links[f.ROOT_RECORD] = []
    elif case == 'duplicate-root-anchor':
        links[f.ROOT_RECORD].append(Link('.'))
    elif case == 'invalid-root-anchor':
        links[f.ROOT_RECORD] = [Link('other-root-name')]

    if links_override is not None:
        links.update(links_override)
    directories.update(directory_records)
    index_links = {number: list(names) for number, names in links.items()}
    if case == 'filename-mismatch':
        links[HELLO_RECORD] = [Link('changed-name.txt')]
    elif case == 'stale-parent':
        links[HELLO_RECORD] = [Link('hello.txt', parent=f.file_reference(f.ROOT_RECORD,
                                                                        f.SYSTEM_SEQUENCE + 1))]
    elif case == 'nondirectory-parent':
        links[FRAGMENTED_RECORD] = [Link('fragmented.bin', parent=f.file_reference(HELLO_RECORD))]
    elif case == 'missing-index-link':
        index_links[HELLO_RECORD] = []
    elif case == 'duplicate-filename':
        links[HELLO_RECORD].append(links[HELLO_RECORD][0])
    elif case == 'duplicate-index':
        index_links[HELLO_RECORD].append(index_links[HELLO_RECORD][0])

    def attrs(number, extras=()):
        names = links[number]
        return [standard(f.FILE_ATTRIBUTE_DIRECTORY if number in directories else 0),
                *(filename(link, FILENAME_INSTANCES[i] if i < len(FILENAME_INSTANCES)
                           else ADDITIONAL_FILENAME_INSTANCE + i - len(FILENAME_INSTANCES),
                           number in directories) for i, link in enumerate(names)),
                security(), *extras]

    mirror_data = (f.resident(f.DATA, b'', DATA_INSTANCE) if mirror.resident else
                   f.nonresident(f.DATA, mirror.runs[:1] if mirror.listed else mirror.runs,
                                 mirror.size, DATA_INSTANCE, initialized=mirror.initialized,
                                 flags=mirror.flags,
                                 allocated=sum(count for count, _ in mirror.runs) * f.CLUSTER))
    records[MIRROR_RECORD] = attrs(MIRROR_RECORD, [] if mirror.missing else [mirror_data])
    if mirror.listed:
        owner, extension = f.file_reference(MIRROR_RECORD), f.file_reference(EXTENSION_RECORD)
        first_clusters = mirror.runs[0][0]
        listing = (f.list_entry(owner, SI_INSTANCE, 0, f.SI)
                   + f.list_entry(owner, FILENAME_INSTANCE, 0, f.FILENAME)
                   + f.list_entry(owner, SECURITY_INSTANCE, 0, SECURITY_ATTRIBUTE)
                   + f.list_entry(owner, DATA_INSTANCE, 0)
                   + f.list_entry(extension, SI_INSTANCE, first_clusters))
        list_attribute = (f.resident(f.ATTR_LIST, listing, LIST_INSTANCE)
                          if mirror.list_lcn is None else
                          f.nonresident(f.ATTR_LIST, [(1, mirror.list_lcn)],
                                        len(listing), LIST_INSTANCE))
        records[MIRROR_RECORD].append(list_attribute)
        if mirror.list_lcn is not None:
            f.put_data(image, mirror.list_lcn, listing)
        records[EXTENSION_RECORD] = [f.nonresident(
            f.DATA, mirror.runs[1:], 0, SI_INSTANCE, lowest=first_clusters)]
    records[f.VOLUME_RECORD] = attrs(f.VOLUME_RECORD, [
        f.resident(f.VOL_NAME, 'Validation'.encode('utf-16le'), VOLUME_NAME_INSTANCE),
        f.resident(f.VOL_INFO, VOLUME_INFORMATION.pack(f.NTFS_MAJOR_VERSION,
                                                    f.NTFS_MINOR_VERSION, 0), VOLUME_INFO_INSTANCE)])
    boot_size = f.CLUSTER if boot.size is None else boot.size
    boot_data = (f.resident(f.DATA, image[:f.SECTOR], DATA_INSTANCE) if boot.resident else
                 f.nonresident(f.DATA, boot.runs[:1] if boot.listed else boot.runs,
                               boot_size, DATA_INSTANCE, initialized=boot.initialized,
                               flags=boot.flags,
                               allocated=sum(count for count, lcn in boot.runs
                                             if lcn is not None) * f.CLUSTER))
    records[BOOT_RECORD] = attrs(BOOT_RECORD, [] if boot.missing else [boot_data])
    if boot.listed:
        owner = f.file_reference(BOOT_RECORD)
        first_clusters = boot.runs[0][0]
        listing = (f.list_entry(owner, SI_INSTANCE, 0, f.SI)
                   + f.list_entry(owner, FILENAME_INSTANCE, 0, f.FILENAME)
                   + f.list_entry(owner, SECURITY_INSTANCE, 0, SECURITY_ATTRIBUTE)
                   + f.list_entry(owner, DATA_INSTANCE, 0)
                   + f.list_entry(f.file_reference(EXTENSION_RECORD), SI_INSTANCE,
                                  first_clusters))
        records[BOOT_RECORD].append(f.resident(f.ATTR_LIST, listing, LIST_INSTANCE))
        records[EXTENSION_RECORD] = [f.nonresident(
            f.DATA, boot.runs[1:], 0, SI_INSTANCE, lowest=first_clusters)]
    records[f.UPCASE_RECORD] = attrs(f.UPCASE_RECORD, [f.nonresident(
        f.DATA, [(UPCASE_UNITS * f.U16_BYTES // f.CLUSTER, f.UPCASE_LCN)],
        UPCASE_UNITS * f.U16_BYTES, DATA_INSTANCE)])
    records[HELLO_RECORD] = attrs(HELLO_RECORD, [f.resident(f.DATA, HELLO_DATA, DATA_INSTANCE)])
    if case == 'logfile-empty':
        records[LOGFILE_RECORD] = attrs(LOGFILE_RECORD, [f.resident(f.DATA, b'', DATA_INSTANCE)])
    if case.startswith('bad-clusters-'):
        cluster_count = f.IMAGE_SIZE // f.CLUSTER
        volume_bytes = cluster_count * f.CLUSTER
        runs = [(cluster_count, None)]
        if case in ('bad-clusters-owned', 'bad-clusters-wrong-target', 'bad-clusters-free'):
            target = ORPHAN_LCN + 1 if case == 'bad-clusters-wrong-target' else ORPHAN_LCN
            runs = [(ORPHAN_LCN, None), (1, target), (cluster_count - ORPHAN_LCN - 1, None)]
            if case != 'bad-clusters-free':
                occupied.add(target)
        elif case == 'bad-clusters-short':
            runs = [(cluster_count - 1, None)]
        descriptors = b''
        if case == 'bad-clusters-listed':
            owner = f.file_reference(BAD_CLUSTERS_RECORD)
            descriptors = (f.list_entry(owner, SI_INSTANCE, 0, f.SI)
                           + f.list_entry(owner, FILENAME_INSTANCE, 0, f.FILENAME)
                           + f.list_entry(owner, SECURITY_INSTANCE, 0, SECURITY_ATTRIBUTE)
                           + f.list_entry(owner, DATA_INSTANCE, 0)
                           + f.list_entry(owner, ADS_INSTANCE, 0, name='$Bad'))
        records[BAD_CLUSTERS_RECORD] = attrs(BAD_CLUSTERS_RECORD, [
            f.resident(f.DATA, b'', DATA_INSTANCE),
            f.nonresident(f.DATA, runs, volume_bytes - 1 if case == 'bad-clusters-invalid-size'
                          else volume_bytes, ADS_INSTANCE, '$Bad', initialized=0,
                          allocated=volume_bytes),
            *([f.resident(f.ATTR_LIST, descriptors, LIST_INSTANCE)] if descriptors else [])])
        if case == 'bad-clusters-duplicate':
            records[BAD_CLUSTERS_RECORD].append(f.nonresident(
                f.DATA, runs, volume_bytes, EXTRA_FILENAME_INSTANCE, '$Bad',
                initialized=0, allocated=volume_bytes))
    if case == 'duplicate-resident-stream':
        records[HELLO_RECORD].append(f.resident(f.DATA, b'duplicate data', ADS_INSTANCE))
    if case == 'ads':
        records[HELLO_RECORD].append(f.nonresident(f.DATA, [(1, ORPHAN_LCN)],
                                                 f.CLUSTER, ADS_INSTANCE, 'notes'))
        occupied.add(ORPHAN_LCN)
        f.put_data(image, ORPHAN_LCN, b'N' * f.CLUSTER)

    listed = case in ('listed', 'extension-filename', 'stale-extension', 'wrong-extension-owner',
                      'unlisted-continuation', 'stale-list-reference', 'duplicate-list-entry',
                      'missing-base-list-entry')
    if listed:
        base_reference = f.file_reference(FRAGMENTED_RECORD)
        extension_reference = f.file_reference(EXTENSION_RECORD)
        filename_reference = extension_reference if case == 'extension-filename' else base_reference
        descriptors = [f.list_entry(base_reference, SI_INSTANCE, 0, f.SI),
                       f.list_entry(filename_reference, FILENAME_INSTANCE, 0, f.FILENAME),
                       f.list_entry(base_reference, SECURITY_INSTANCE, 0, SECURITY_ATTRIBUTE),
                       f.list_entry(base_reference, DATA_INSTANCE, 0)]
        continuation_ref = (f.file_reference(EXTENSION_RECORD, f.FILE_SEQUENCE + 1)
                            if case == 'stale-list-reference' else extension_reference)
        continuation = f.list_entry(continuation_ref, SI_INSTANCE, 1)
        if case != 'unlisted-continuation':
            descriptors.append(continuation)
        if case == 'duplicate-list-entry':
            descriptors.append(continuation)
        if case == 'missing-base-list-entry':
            descriptors = descriptors[1:]
        records[FRAGMENTED_RECORD] = attrs(FRAGMENTED_RECORD, [
            f.resident(f.ATTR_LIST, b''.join(descriptors), LIST_INSTANCE),
            f.nonresident(f.DATA, [(1, first_lcn)], f.FRAGMENTED_BYTES,
                          DATA_INSTANCE, allocated=2 * f.CLUSTER)])
        records[EXTENSION_RECORD] = [f.nonresident(f.DATA, [(1, second_lcn)], 0,
                                                 lowest=1)]
        if case == 'extension-filename':
            records[FRAGMENTED_RECORD].remove(filename(links[FRAGMENTED_RECORD][0]))
            records[EXTENSION_RECORD].append(filename(links[FRAGMENTED_RECORD][0]))
    else:
        records[FRAGMENTED_RECORD] = attrs(FRAGMENTED_RECORD, [f.nonresident(
            f.DATA, [(1, first_lcn), (fragmented_clusters - 1, second_lcn)], f.FRAGMENTED_BYTES,
            DATA_INSTANCE, initialized=f.FRAGMENTED_BYTES + 1 if case == 'invalid-size' else None)])
    if case == 'orphan-extension':
        records[EXTENSION_RECORD] = [f.resident(f.DATA, b'unlisted extension')]
    if case == 'efs':
        records[FRAGMENTED_RECORD] = attrs(FRAGMENTED_RECORD, [f.nonresident(
            f.DATA, [(1, first_lcn), (1, second_lcn)], f.FRAGMENTED_BYTES,
            DATA_INSTANCE, flags=f.ENCRYPTED)])
    if case == 'sparse':
        records[FRAGMENTED_RECORD] = attrs(FRAGMENTED_RECORD, [f.nonresident(
            f.DATA, [(1, first_lcn), (1, None), (1, second_lcn)], 3 * f.CLUSTER,
            DATA_INSTANCE, flags=f.SPARSE)])
    if case == 'ordinary-unflagged-hole':
        records[FRAGMENTED_RECORD] = attrs(FRAGMENTED_RECORD, [f.nonresident(
            f.DATA, [(1, first_lcn), (1, None), (1, second_lcn)], 3 * f.CLUSTER,
            DATA_INSTANCE, initialized=0)])
    if case != 'overlap-streams':
        f.put_data(image, first_lcn, FRAGMENTED_DATA[:f.CLUSTER])
    f.put_data(image, second_lcn, FRAGMENTED_DATA[f.CLUSTER:])

    for number in directories:
        items = [(child, link, None) for child, names in index_links.items() for link in names
                 if link.parent == f.file_reference(number) and child != f.ROOT_RECORD]
        items.sort(key=collation)
        entries = []
        for child, link, _ in items:
            reference = None
            if number == f.ROOT_RECORD and child == HELLO_RECORD:
                if case == 'stale-index-reference':
                    reference = f.file_reference(child, f.FILE_SEQUENCE + 1)
                elif case == 'dangling-index':
                    reference = f.file_reference(EXTRA_RECORD)
            entries.append(index_entry(child, link, child in directories, reference))
        if number == f.ROOT_RECORD:
            layout = Index(f.CLUSTER) if index is None else index
            unit = f.CLUSTER if f.CLUSTER <= layout.block_bytes else f.SECTOR
            allocation_bytes = layout.slots * layout.block_bytes + layout.trailing_bytes
            clusters = (allocation_bytes + f.CLUSTER - 1) // f.CLUSTER
            runs = ([(1, f.INDEX_LCN), (1, ORPHAN_LCN)] if layout.fragmented
                    else [(clusters, f.INDEX_LCN)])
            for count, lcn in runs:
                occupied.update(range(lcn, lcn + count))
            midpoint = len(items) // 2
            root_entries = f.entry(child=0)
            if layout.split:
                child, link, _ = items[midpoint]
                root_entries = (index_entry(child, link, child in directories, child=0)
                                + f.entry(child=layout.block_bytes // unit))
            # The format author uses the requested block geometry, independently
            # of the core's VCN-to-slot conversion.
            previous_cluster = f.CLUSTER
            try:
                f.CLUSTER = layout.block_bytes
                blocks = [f.index_block(0, entries[:midpoint] if layout.split else entries)]
                for slot in range(1, layout.slots):
                    vcn = slot * layout.block_bytes // unit
                    blocks.append(f.index_block(vcn, entries[midpoint + 1:] if layout.split else [])
                                  if layout.split or layout.unused_valid else
                                  bytes([INDEX_UNUSED_STORAGE_BYTE]) * layout.block_bytes)
            finally:
                f.CLUSTER = previous_cluster
            payload = b''.join(blocks) + bytes(layout.trailing_bytes)
            position = 0
            for count, lcn in runs:
                length = count * f.CLUSTER
                f.put_data(image, lcn, payload[position:position + length])
                position += length
            bitmap_attribute = f.resident(f.BITMAP, layout.bitmap, ROOT_BITMAP_INSTANCE,
                                          INDEX_STREAM_NAME)
            if layout.bitmap_lcn is not None:
                occupied.add(layout.bitmap_lcn)
                f.put_data(image, layout.bitmap_lcn, layout.bitmap)
                bitmap_attribute = f.nonresident(f.BITMAP, [(1, layout.bitmap_lcn)],
                    len(layout.bitmap), ROOT_BITMAP_INSTANCE, INDEX_STREAM_NAME)
            records[number] = attrs(number, [
                f.resident(f.INDEX_ROOT, root_value(root_entries, True, layout.block_bytes),
                           ROOT_INDEX_INSTANCE, INDEX_STREAM_NAME),
                f.nonresident(f.INDEX_ALLOC, runs, allocation_bytes,
                              ROOT_ALLOCATION_INSTANCE, INDEX_STREAM_NAME),
                bitmap_attribute])
            if case == 'sensitive':
                records[number][SI_INSTANCE] = standard(f.FILE_ATTRIBUTE_DIRECTORY, version=1)
        else:
            records[number] = attrs(number, [f.resident(
                f.INDEX_ROOT, root_value(b''.join(entries) + f.entry(),
                                        block_bytes=None if index is None else index.block_bytes),
                ROOT_INDEX_INSTANCE, INDEX_STREAM_NAME)])
            if index is not None and index.leaf_bitmap is not None:
                records[number].append(f.resident(f.BITMAP, index.leaf_bitmap,
                    ROOT_BITMAP_INSTANCE, INDEX_STREAM_NAME))
                if index.leaf_allocation:
                    occupied.add(f.INDEX_LCN + 1)
                    f.put_data(image, f.INDEX_LCN + 1,
                               bytes([INDEX_UNUSED_STORAGE_BYTE]) * f.CLUSTER)
                    records[number].append(f.nonresident(f.INDEX_ALLOC,
                        [(1, f.INDEX_LCN + 1)], index.block_bytes,
                        ROOT_ALLOCATION_INSTANCE, INDEX_STREAM_NAME))

    if case in ('reserved-empty', 'reserved-inert', 'reserved-with-data', 'unexpected-empty'):
        numbers = (range(RESERVED_FIRST, RESERVED_LAST + 1)
                   if case != 'unexpected-empty' else (EXTRA_RECORD,))
        for number in numbers:
            records[number] = ([] if case in ('reserved-empty', 'unexpected-empty') else
                               [standard(common_only=True),
                                f.resident(f.DATA, b'payload' if case == 'reserved-with-data' else b'',
                                           DATA_INSTANCE)])

    records[f.MFT_RECORD] = attrs(f.MFT_RECORD, [f.nonresident(
        f.DATA, [(MFT_BYTES // f.CLUSTER, f.MFT_LCN)],
        MFT_BYTES - 1 if case == 'partial-mft-record' else MFT_BYTES, DATA_INSTANCE)])
    records[f.BITMAP_RECORD] = attrs(f.BITMAP_RECORD)
    mft_bits = bytearray((f.MFT_COUNT + f.BYTE_BITS - 1) // f.BYTE_BITS)
    for number in records:
        mft_bits[number // f.BYTE_BITS] |= 1 << (number % f.BYTE_BITS)
    if case == 'mft-free-active':
        mft_bits[HELLO_RECORD // f.BYTE_BITS] &= ~(1 << (HELLO_RECORD % f.BYTE_BITS))
    elif case == 'mft-allocated-empty':
        mft_bits[EXTRA_RECORD // f.BYTE_BITS] |= 1 << (EXTRA_RECORD % f.BYTE_BITS)
    if case == 'mft-short-bitmap':
        mft_bits = mft_bits[:-1]
    if case != 'mft-missing-bitmap':
        records[f.MFT_RECORD].append(f.resident(f.BITMAP, mft_bits, MFT_BITMAP_INSTANCE))
    if case == 'free-claimed-cluster':
        occupied.remove(FIRST_DATA_LCN)
    elif case == 'allocated-unclaimed-cluster':
        occupied.add(ORPHAN_LCN)
    volume_bits = bytearray(f.IMAGE_SIZE // f.CLUSTER // f.BYTE_BITS)
    for cluster in occupied:
        volume_bits[cluster // f.BYTE_BITS] |= 1 << (cluster % f.BYTE_BITS)
    records[f.BITMAP_RECORD].append(f.resident(f.DATA, volume_bits, DATA_INSTANCE))

    for number, attributes in records.items():
        attributes.sort(key=lambda attr: f.ATTR_HEADER.unpack_from(attr)[0])
        extension_owner = (MIRROR_RECORD if mirror.listed else
                           BOOT_RECORD if boot.listed else FRAGMENTED_RECORD)
        base = (f.file_reference(extension_owner)
                if number == EXTENSION_RECORD else 0)
        if number == EXTENSION_RECORD and case == 'stale-extension':
            base = f.file_reference(FRAGMENTED_RECORD, f.FILE_SEQUENCE + 1)
        elif number == EXTENSION_RECORD and case in ('wrong-extension-owner', 'orphan-extension'):
            base = f.file_reference(HELLO_RECORD)
        header_links = len(links.get(number, [])) if attributes and base == 0 else 0
        if case == 'header-link-count' and number == HELLO_RECORD:
            header_links += 1
        if case == 'dos-header-count-low' and number == HELLO_RECORD:
            header_links -= 1
        elif case == 'dos-header-count-high' and number == HELLO_RECORD:
            header_links += 1
        if case == 'root-header-link-count' and number == f.ROOT_RECORD:
            header_links += 1
        f.put_record(image, number, f.file_record(number, attributes,
                     directory=number in directories, base=base, links=header_links,
                     uninterpreted=case == 'uninterpreted-flag' and number == HELLO_RECORD))
    start = f.MFT_LCN * f.CLUSTER
    payload = image[start:start + max(mirror.size, MIRROR_RECORDS * f.RECORD)]
    # Keep the boot-addressed bootstrap copy even for malformed stream mappings.
    f.put_data(image, f.MIRROR_LCN, payload[:MIRROR_RECORDS * f.RECORD])
    position = 0
    for clusters, lcn in mirror.runs:
        length = clusters * f.CLUSTER
        if lcn is not None:
            f.put_data(image, lcn, payload[position:position + length])
        position += length
    # The boot-declared data span excludes the final reserved boot sector.
    # Focused ordinary parser fixtures omit it; complete inventories retain it.
    sector = struct.unpack_from('<H', image, f.BOOT_FIELDS['sector_size'])[0]
    backup = struct.unpack_from('<Q', image, f.BOOT_FIELDS['sectors'])[0] * sector
    assert backup + sector > len(image) and backup == len(image)
    image.extend(image[:sector])
    return image


def author(output, source):
    cases = [
        ('standard', 'ok'), ('listed', 'ok'), ('extension-filename', 'ok'),
        ('hardlinks', 'ok'), ('ads', 'ok'), ('sparse', 'ok'), ('nested', 'ok'),
        ('sensitive', 'ok'), ('stale-cached-sizes', 'ok'), ('reserved-empty', 'ok'),
        ('reserved-inert', 'ok'), ('reserved-with-data', 'corrupt'),
        ('uninterpreted-flag', 'ok'), ('duplicate-resident-stream', 'corrupt'),
        ('bad-clusters-empty', 'ok'), ('bad-clusters-owned', 'ok'),
        ('bad-clusters-wrong-target', 'corrupt'), ('bad-clusters-free', 'corrupt'),
        ('bad-clusters-short', 'corrupt'), ('bad-clusters-invalid-size', 'corrupt'),
        ('bad-clusters-listed', 'ok'), ('ordinary-unflagged-hole', 'corrupt'),
        ('bad-clusters-duplicate', 'corrupt'), ('missing-root-anchor', 'corrupt'),
        ('duplicate-root-anchor', 'corrupt'), ('invalid-root-anchor', 'corrupt'),
        ('root-header-link-count', 'corrupt'),
        ('mft-free-active', 'corrupt'), ('mft-allocated-empty', 'corrupt'),
        ('mft-short-bitmap', 'corrupt'), ('mft-missing-bitmap', 'corrupt'),
        ('partial-mft-record', 'corrupt'), ('stale-extension', 'stale'),
        ('wrong-extension-owner', 'stale'), ('orphan-extension', 'corrupt'),
        ('unlisted-continuation', 'corrupt'), ('stale-list-reference', 'stale'),
        ('duplicate-list-entry', 'corrupt'), ('missing-base-list-entry', 'corrupt'),
        ('filename-mismatch', 'corrupt'), ('stale-parent', 'stale'),
        ('nondirectory-parent', 'corrupt'), ('missing-index-link', 'corrupt'),
        ('duplicate-filename', 'corrupt'), ('duplicate-index', 'corrupt'),
        ('stale-index-reference', 'stale'), ('dangling-index', 'stale'),
        ('header-link-count', 'corrupt'), ('directory-cycle', 'corrupt'),
        ('free-claimed-cluster', 'corrupt'), ('allocated-unclaimed-cluster', 'corrupt'),
        ('overlap-streams', 'corrupt'), ('self-overlap', 'corrupt'),
        ('invalid-size', 'corrupt'), ('unexpected-empty', 'corrupt'),
        ('dos', 'ok'), ('dos-hardlinks', 'ok'), ('dos-nested-hardlinks', 'ok'),
        ('dos-directory', 'ok'), ('combined-name', 'ok'), ('dos-only', 'corrupt'),
        ('dos-header-count-low', 'corrupt'), ('dos-header-count-high', 'corrupt'),
        ('efs', 'unsupported'),
    ]
    manifest = []
    names = {'ok': 'success', 'corrupt': 'corrupt metadata',
             'stale': 'stale file reference', 'unsupported': 'unsupported format'}
    for case, expected in cases:
        name = 'validation-' + case + '.img'
        (output / name).write_bytes(build(source, case))
        manifest.append({'image': name, 'result': names[expected], 'complete': expected == 'ok'})
    from mirror_fixtures import author as mirror_fixtures
    manifest.extend(mirror_fixtures(output, source))
    from index_inventory_fixtures import author as index_inventory_fixtures
    manifest.extend(index_inventory_fixtures(output, source))
    from security_validation_fixtures import author as security_validation_fixtures
    manifest.extend(security_validation_fixtures(output, source))
    from bad_clusters_fixtures import author as bad_clusters_fixtures
    manifest.extend(bad_clusters_fixtures(output, source))
    from boot_fixtures import author as boot_fixtures
    manifest.extend(boot_fixtures(output, source))
    (output / 'validation-cases.json').write_text(json.dumps(manifest, indent=2) + '\n')
