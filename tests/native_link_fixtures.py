"""Independent Windows target spelling and native link expectations."""
import base64
import json
import struct
import fixtures as f

SOURCE_RECORD = f.FILE_RECORDS['hello.txt']
TARGET_RECORD = f.FILE_RECORDS['fragmented.bin']
FOLDER_RECORD = max(f.FILE_RECORDS.values()) + 1
EXTENSION_RECORD = f.MFT_COUNT - 1
GUID = '12345678-1234-5678-9abc-123456789abc'
NATIVE_PATH_BYTES = 1023
NATIVE_COMPONENT_LIMIT = (NATIVE_PATH_BYTES + 1) // 2
PRINT_PADDING_UNITS = 3000
STANDARD_INSTANCE = 0
DATA_INSTANCE = 1
CONTINUATION_INSTANCE = 0
FIRST_EXTENT_VCN = 0
CONTINUATION_VCN = 1
ROOT_CHILD_VCN = 0
ROOT_INDEX_CLUSTERS = 1
CHAIN_FIRST_RECORD = 40
CHAIN_DESTINATION_RECORD = FOLDER_RECORD
CHAIN_SOURCE_PARENT_RECORD = FOLDER_RECORD + 1
CHAIN_MFT_RECORDS = f.MFT_COUNT * 2
CHAIN_MFT_CONTINUATION_LCN = 192
CHAIN_SOURCE_REPARSE_LCN = 224
CHAIN_INDEX_PAGES = 2
CHAIN_RESOLUTION_LIMIT = 63
CHAIN_INNER_DOTS = 300


def order(name):
    encoded = name.encode('utf-16le', errors='surrogatepass')
    units = struct.unpack('<' + 'H' * (len(encoded) // f.U16_BYTES), encoded)
    folded = tuple(u - ord('a') + ord('A') if ord('a') <= u <= ord('z') else u
                   for u in units)
    return folded, units


def author(output, source):
    cases = []

    def save(label, substitute, expected=None, *, code='ok', relative=True,
             roots=(), nested=False, target='fragmented.bin', storage='resident',
             junction=False, opaque=False, hidden=False, dos=False, sensitive=False,
             intermediate=False, cycle=False, links=1, maximum=None, raw_override=None):
        image = bytearray(source)
        tag = f.REPARSE_TAG_MOUNT_POINT if junction else f.REPARSE_TAG_SYMLINK
        display = 'P' * PRINT_PADDING_UNITS if storage in ('fragmented', 'listed') else 'display only'
        raw = f.reparse_value(tag, substitute, display, relative=relative,
                              print_first=True)
        if opaque:
            payload = b'opaque provider'
            raw = f.REPARSE_HEADER.pack(f.REPARSE_TAG_WOF, len(payload), 0) + payload
        if raw_override is not None:
            raw = raw_override
        common = [f.standard(f.FILE_ATTRIBUTE_REPARSE |
                             (f.FILE_ATTRIBUTE_DIRECTORY if junction else 0)),
                  f.resident(f.DATA, b'ordinary data is not readlink', DATA_INSTANCE)]
        allocated = 0
        if storage in ('fragmented', 'listed') or len(raw) > f.RECORD // 2:
            clusters = (len(raw) + f.CLUSTER - 1) // f.CLUSTER
            lcns = [f.REPARSE_LCNS[0] + index * (f.REPARSE_LCNS[1] - f.REPARSE_LCNS[0])
                    for index in range(clusters)]
            allocated = clusters * f.CLUSTER
            for index, lcn in enumerate(lcns):
                f.put_data(image, lcn, raw[index * f.CLUSTER:(index + 1) * f.CLUSTER])
            if storage == 'listed':
                assert clusters == len(f.REPARSE_LCNS)
                listing = f.list_entry(f.file_reference(SOURCE_RECORD), STANDARD_INSTANCE,
                                        FIRST_EXTENT_VCN, f.SI)
                listing += f.list_entry(f.file_reference(SOURCE_RECORD), DATA_INSTANCE,
                                        FIRST_EXTENT_VCN, f.DATA)
                listing += f.list_entry(f.file_reference(SOURCE_RECORD),
                                        f.REPARSE_INSTANCE, FIRST_EXTENT_VCN, f.REPARSE_POINT)
                listing += f.list_entry(f.file_reference(EXTENSION_RECORD),
                                        CONTINUATION_INSTANCE, CONTINUATION_VCN, f.REPARSE_POINT)
                common += [f.resident(f.ATTR_LIST, listing, f.REPARSE_LIST_INSTANCE),
                           f.nonresident(f.REPARSE_POINT, [(1, lcns[0])], len(raw),
                                         f.REPARSE_INSTANCE, allocated=allocated)]
                f.put_record(image, EXTENSION_RECORD, f.file_record(EXTENSION_RECORD,
                             [f.nonresident(f.REPARSE_POINT, [(1, lcns[CONTINUATION_VCN])], 0,
                                            instance=CONTINUATION_INSTANCE, lowest=CONTINUATION_VCN)],
                             base=f.file_reference(SOURCE_RECORD)))
            else:
                common.append(f.nonresident(f.REPARSE_POINT, [(1, lcn) for lcn in lcns],
                                            len(raw), f.REPARSE_INSTANCE))
        elif storage == 'extension':
            listing = f.list_entry(f.file_reference(SOURCE_RECORD), STANDARD_INSTANCE,
                                    FIRST_EXTENT_VCN, f.SI)
            listing += f.list_entry(f.file_reference(SOURCE_RECORD), DATA_INSTANCE,
                                    FIRST_EXTENT_VCN, f.DATA)
            listing += f.list_entry(f.file_reference(EXTENSION_RECORD),
                                    f.REPARSE_INSTANCE, FIRST_EXTENT_VCN, f.REPARSE_POINT)
            common.append(f.resident(f.ATTR_LIST, listing, f.REPARSE_LIST_INSTANCE))
            f.put_record(image, EXTENSION_RECORD, f.file_record(EXTENSION_RECORD,
                         [f.resident(f.REPARSE_POINT, raw, f.REPARSE_INSTANCE)],
                         base=f.file_reference(SOURCE_RECORD)))
        else:
            common.append(f.resident(f.REPARSE_POINT, raw, f.REPARSE_INSTANCE))
        f.put_record(image, SOURCE_RECORD,
                     f.file_record(SOURCE_RECORD, common, directory=junction, links=links))
        folder_name = '~folder' if label.startswith('shared-scan-') else 'Folder'
        local_name = '~local' if label.startswith('shared-scan-') else 'Local.TXT'
        root_links = [(folder_name, FOLDER_RECORD, f.NAMESPACE_WIN32),
                      (target, TARGET_RECORD, f.NAMESPACE_WIN32)]
        if hidden:
            root_links.append(('!metadata', f.VOLUME_RECORD, f.NAMESPACE_WIN32))
        if dos:
            root_links.append(('FRAGME~1', TARGET_RECORD, f.NAMESPACE_DOS))
        if not nested:
            root_links.append(('hello.txt', SOURCE_RECORD, f.NAMESPACE_WIN32))
        if links > 1:
            root_links.append(('other-link', SOURCE_RECORD, f.NAMESPACE_WIN32))
        root_links.sort(key=lambda link: order(link[0]))
        f.put_record(image, f.ROOT_RECORD,
                     f.directory_record(f.entry(child=ROOT_CHILD_VCN), allocation_clusters=ROOT_INDEX_CLUSTERS,
                                        version=int(sensitive)))
        f.put_data(image, f.INDEX_LCN, f.index_block(ROOT_CHILD_VCN,
                   [f.entry(name, record, namespace=namespace)
                    for name, record, namespace in root_links]))
        folder_links = [(local_name, TARGET_RECORD)]
        if nested:
            folder_links.append(('hello.txt', SOURCE_RECORD))
        if cycle:
            folder_links.append(('loop', FOLDER_RECORD))
        folder_links.sort(key=lambda link: order(link[0]))
        folder_entries = b''.join(f.entry(name, record, parent=f.file_reference(FOLDER_RECORD))
                                   for name, record in folder_links) + f.entry()
        folder = f.directory_record(folder_entries, number=FOLDER_RECORD)
        if intermediate:
            value = f.reparse_value(f.REPARSE_TAG_MOUNT_POINT, '\\??\\C:\\Folder', '')
            folder = f.file_record(FOLDER_RECORD,
                                  [f.standard(f.FILE_ATTRIBUTE_DIRECTORY | f.FILE_ATTRIBUTE_REPARSE),
                                   f.resident(f.REPARSE_POINT, value, f.REPARSE_INSTANCE)],
                                  directory=True)
        f.put_record(image, FOLDER_RECORD, folder)
        if expected == 'alias':
            visible = [link for link in root_links
                       if link[1] >= f.SYSTEM_RECORD_LIMIT and link[2] != f.NAMESPACE_DOS]
            ordinal = next(index for index, link in enumerate(visible) if link[0] == target)
            expected = f'~ntfs-{f.file_reference(TARGET_RECORD):016x}-{ordinal:08x}'
            if nested:
                expected = '../' + expected
        elif expected == 'directory-alias':
            visible = [link for link in root_links
                       if link[1] >= f.SYSTEM_RECORD_LIMIT and link[2] != f.NAMESPACE_DOS]
            ordinal = next(index for index, link in enumerate(visible) if link[0] == folder_name)
            expected = (f'~ntfs-{f.file_reference(FOLDER_RECORD):016x}-{ordinal:08x}/'
                        f'~ntfs-{f.file_reference(TARGET_RECORD):016x}-{0:08x}')
        filename = 'native-link-' + label + '.img'
        (output / filename).write_bytes(image)
        cases.append(dict(image=filename, target=expected, code=code, roots=list(roots),
                          nested=nested, allocated=allocated,
                          raw=base64.b64encode(raw).decode('ascii'),
                          type='unknown' if opaque else 'symlink', maximum=maximum,
                          inventory_code=code if raw_override is not None else 'ok'))

    save('relative', 'fragmented.bin', 'fragmented.bin')
    save('canonical', 'FRAGMENTED.BIN', 'fragmented.bin')
    save('unicode', 'Ωmega.txt', 'Ωmega.txt', target='Ωmega.txt')
    save('dots', '.\\Folder\\..\\fragmented.bin', './Folder/../fragmented.bin')
    save('directory', 'Folder\\Local.TXT', 'Folder/Local.TXT')
    save('trailing', 'Folder\\', 'Folder/')
    save('self', '.', '.')
    save('dangling', 'missing\\file.txt', 'missing/file.txt')
    save('nested-relative', 'local.txt', 'Local.TXT', nested=True)
    save('nested-parent', '..\\fragmented.bin', '../fragmented.bin', nested=True)
    save('root-relative', '\\fragmented.bin', '../fragmented.bin', nested=True)
    save('drive', '\\??\\c:\\FRAGMENTED.BIN', '../fragmented.bin',
         relative=False, roots=('C:',), nested=True)
    save('win32', '\\\\?\\C:\\fragmented.bin', 'fragmented.bin', relative=False, roots=('c:',))
    save('guid', '\\??\\Volume{' + GUID + '}\\fragmented.bin', 'fragmented.bin',
         relative=False, roots=('Volume{' + GUID.upper() + '}',))
    save('junction', '\\??\\C:\\Folder', 'Folder', relative=False, roots=('C:',), junction=True)
    save('bound-root', '\\??\\C:\\', '../', relative=False, roots=('C:',), nested=True)
    save('reserved', '~literal', 'alias', target='~literal', hidden=True)
    save('unpaired', 'bad\ud800name', 'alias', target='bad\ud800name')
    save('oversized', 'Ω' * f.NAME_MAX_UNITS, 'alias', target='Ω' * f.NAME_MAX_UNITS)
    save('dos', 'FRAGME~1', 'alias', target='~literal', dos=True, hidden=True)
    save('nested-alias', '..\\~literal', 'alias', target='~literal', nested=True)
    # The first alias scans three root entries and the second scans one child.
    root_alias_entries = 3
    child_alias_entries = 1
    save('shared-scan-boundary', '~folder\\~local', 'directory-alias',
         maximum=root_alias_entries + child_alias_entries)
    save('shared-scan-range', '~folder\\~local', code='range', maximum=root_alias_entries)
    for storage in ('fragmented', 'listed', 'extension'):
        save(storage, 'fragmented.bin', 'fragmented.bin', storage=storage)
    boundary_components = (NATIVE_PATH_BYTES + 1) // (f.NAME_MAX_UNITS + 1)
    exact = '\\'.join(['x' * f.NAME_MAX_UNITS] * boundary_components)
    assert len(exact.encode('ascii')) == NATIVE_PATH_BYTES
    save('path-boundary', exact, exact.replace('\\', '/'))
    save('path-range', exact + '\\', code='range')
    dot_boundary = '\\'.join(['.'] * NATIVE_COMPONENT_LIMIT)
    save('component-boundary', dot_boundary, dot_boundary.replace('\\', '/'))
    save('component-range', dot_boundary + '\\.', code='range')
    save('scan-range', '~literal', code='range', target='~literal', hidden=True, maximum=1)
    save('unbound', '\\??\\C:\\fragmented.bin', code='unsupported', relative=False)
    save('foreign', '\\??\\D:\\fragmented.bin', code='unsupported', relative=False, roots=('C:',))
    save('unc', '\\\\server\\share\\file', code='unsupported')
    save('device', '\\\\.\\PhysicalDrive0', code='unsupported', relative=False)
    save('drive-relative', 'C:fragmented.bin', code='unsupported')
    save('stream-path', 'fragmented.bin:notes', code='unsupported')
    save('escape', '..\\fragmented.bin', code='unsupported')
    save('nested-escape', '..\\..\\fragmented.bin', code='unsupported', nested=True)
    save('dangling-alias', '~missing', code='unsupported')
    save('sensitive-missing', 'FRAGMENTED.BIN', 'FRAGMENTED.BIN', sensitive=True)
    save('intermediate', 'Folder\\Local.TXT', code='loop', intermediate=True, roots=('C:',))
    save('not-directory', 'fragmented.bin\\child', code='not-directory')
    save('cycle', 'Folder\\loop\\Local.TXT', code='corrupt', cycle=True)
    save('hardlinked', 'fragmented.bin', code='unsupported', links=2)
    save('opaque', 'unused', code='unsupported', opaque=True)
    save('short', 'unused', code='corrupt', raw_override=bytes(f.REPARSE_HEADER.size - 1))
    cases.extend(author_chains(output, source))
    (output / 'native-links.json').write_text(json.dumps(cases, ensure_ascii=True, indent=2) + '\n')


def author_chains(output, source):
    """Author original packets/edges and expected native bytes without a resolver."""
    cases = []

    def save(label, targets, substitute, expected=None, *, code='ok', roots=(),
             junction=False, destination='Destination', leaf='Local.TXT', nested=False,
             sensitive=False, links=1, maximum=None, storage='resident', opaque=False,
             malformed=False):
        image = bytearray(source)
        prefix_clusters = f.MFT_COUNT * f.RECORD // f.CLUSTER
        extension_clusters = (CHAIN_MFT_RECORDS - f.MFT_COUNT) * f.RECORD // f.CLUSTER
        mft = f.file_record(f.MFT_RECORD, [f.standard(), f.nonresident(f.DATA,
                            [(prefix_clusters, f.MFT_LCN),
                             (extension_clusters, CHAIN_MFT_CONTINUATION_LCN)],
                            CHAIN_MFT_RECORDS * f.RECORD, DATA_INSTANCE)])
        f.put_record(image, f.MFT_RECORD, mft)
        f.put_data(image, f.MIRROR_LCN, mft)

        def record(number, attrs, **flags):
            encoded = f.file_record(number, attrs, **flags)
            if number < f.MFT_COUNT:
                f.put_record(image, number, encoded)
            else:
                position = (CHAIN_MFT_CONTINUATION_LCN * f.CLUSTER
                            + (number - f.MFT_COUNT) * f.RECORD)
                image[position:position + f.RECORD] = encoded

        raw = f.reparse_value(f.REPARSE_TAG_SYMLINK, substitute, 'outer display', relative=True)
        source_attrs = [f.standard(f.FILE_ATTRIBUTE_REPARSE)]
        source_allocated = 0
        if len(raw) > f.RECORD // 2:
            assert len(raw) <= f.CLUSTER
            f.put_data(image, CHAIN_SOURCE_REPARSE_LCN, raw)
            source_attrs.append(f.nonresident(f.REPARSE_POINT, [(1, CHAIN_SOURCE_REPARSE_LCN)],
                                              len(raw), f.REPARSE_INSTANCE))
            source_allocated = f.CLUSTER
        else:
            source_attrs.append(f.resident(f.REPARSE_POINT, raw, f.REPARSE_INSTANCE))
        record(SOURCE_RECORD, source_attrs)
        root_links = [(destination, CHAIN_DESTINATION_RECORD),
                      ('fragmented.bin', TARGET_RECORD)]
        if nested:
            root_links.append(('Folder', CHAIN_SOURCE_PARENT_RECORD))
            f.put_record(image, CHAIN_SOURCE_PARENT_RECORD, f.directory_record(
                         f.entry('hello.txt', SOURCE_RECORD,
                                 parent=f.file_reference(CHAIN_SOURCE_PARENT_RECORD)) + f.entry(),
                         number=CHAIN_SOURCE_PARENT_RECORD))
        else:
            root_links.append(('hello.txt', SOURCE_RECORD))
        for index, target in enumerate(targets):
            number = CHAIN_FIRST_RECORD + index
            name = f'H{index:02d}'
            root_links.append((name, number))
            tag = f.REPARSE_TAG_MOUNT_POINT if junction else f.REPARSE_TAG_SYMLINK
            packet = f.reparse_value(tag, target, 'inner display', relative=not junction)
            if opaque:
                packet = f.REPARSE_HEADER.pack(f.REPARSE_TAG_CLOUD, 0, 0)
            if malformed:
                packet = bytes(f.REPARSE_HEADER.size - 1)
            attrs = [f.standard(f.FILE_ATTRIBUTE_REPARSE |
                               (f.FILE_ATTRIBUTE_DIRECTORY if junction else 0))]
            if storage == 'listed':
                # Distinct physical runs and a sequence-checked continuation.
                packet = f.reparse_value(tag, target, 'P' * PRINT_PADDING_UNITS,
                                         relative=not junction)
                first_lcn, second_lcn = f.REPARSE_LCNS
                f.put_data(image, first_lcn, packet[:f.CLUSTER])
                f.put_data(image, second_lcn, packet[f.CLUSTER:])
                continuation = CHAIN_MFT_RECORDS - 1
                listing = f.list_entry(f.file_reference(number), STANDARD_INSTANCE,
                                      FIRST_EXTENT_VCN, f.SI)
                listing += f.list_entry(f.file_reference(number), f.REPARSE_INSTANCE,
                                       FIRST_EXTENT_VCN, f.REPARSE_POINT)
                listing += f.list_entry(f.file_reference(continuation), CONTINUATION_INSTANCE,
                                       CONTINUATION_VCN, f.REPARSE_POINT)
                attrs += [f.resident(f.ATTR_LIST, listing, f.REPARSE_LIST_INSTANCE),
                          f.nonresident(f.REPARSE_POINT, [(1, first_lcn)], len(packet),
                                        f.REPARSE_INSTANCE, allocated=len(f.REPARSE_LCNS) * f.CLUSTER)]
                record(continuation, [f.nonresident(f.REPARSE_POINT, [(1, second_lcn)], 0,
                       CONTINUATION_INSTANCE, lowest=CONTINUATION_VCN)],
                       base=f.file_reference(number))
            elif len(packet) > f.RECORD // 2:
                assert len(packet) <= f.CLUSTER
                f.put_data(image, f.REPARSE_LCNS[0], packet)
                attrs.append(f.nonresident(f.REPARSE_POINT, [(1, f.REPARSE_LCNS[0])],
                                          len(packet), f.REPARSE_INSTANCE))
            else:
                attrs.append(f.resident(f.REPARSE_POINT, packet, f.REPARSE_INSTANCE))
            record(number, attrs, directory=junction, links=links)
        if links > 1:
            root_links.append(('Other', CHAIN_FIRST_RECORD))
        f.put_record(image, CHAIN_DESTINATION_RECORD, f.directory_record(
                     f.entry(leaf, TARGET_RECORD, parent=f.file_reference(CHAIN_DESTINATION_RECORD))
                     + f.entry(), number=CHAIN_DESTINATION_RECORD, version=int(sensitive)))
        root_links.sort(key=lambda edge: order(edge[0]))
        median = len(root_links) // 2
        pivot = root_links[median]
        f.put_record(image, f.ROOT_RECORD, f.directory_record(
                     f.entry(pivot[0], pivot[1], child=ROOT_CHILD_VCN)
                     + f.entry(child=ROOT_CHILD_VCN + 1), allocation_clusters=CHAIN_INDEX_PAGES))
        for page, edges in enumerate((root_links[:median], root_links[median + 1:])):
            f.put_data(image, f.INDEX_LCN + page,
                       f.index_block(page, [f.entry(name, number) for name, number in edges]))
        filename = 'native-link-chain-' + label + '.img'
        (output / filename).write_bytes(image)
        cases.append(dict(image=filename, target=expected, code=code, roots=list(roots),
                          nested=nested, allocated=source_allocated,
                          raw=base64.b64encode(raw).decode('ascii'),
                          type='symlink', maximum=maximum,
                          inventory_code='corrupt' if malformed else 'ok'))

    save('relative', ['Destination'], 'H00\\local.txt', 'H00/Local.TXT')
    save('junction', ['\\??\\C:\\Destination'], 'H00\\local.txt', 'H00/Local.TXT',
         junction=True, roots=('C:',))
    save('two-hop', ['H01', 'Destination'], 'H00\\local.txt', 'H00/Local.TXT')
    save('listed', ['Destination'], 'H00\\local.txt', 'H00/Local.TXT', storage='listed')
    save('nested-root', ['Destination'], '\\H00\\local.txt', '../H00/Local.TXT', nested=True)
    save('parent', ['Destination'], 'H00\\..\\FRAGMENTED.BIN', 'H00/../fragmented.bin')
    save('root', ['\\??\\C:\\'], 'H00\\fragmented.bin', 'H00/fragmented.bin',
         junction=True, roots=('C:',))
    save('root-escape', ['\\??\\C:\\'], 'H00\\..\\fragmented.bin', code='unsupported',
         junction=True, roots=('C:',))
    save('foreign', ['\\??\\D:\\Destination'], 'H00\\Local.TXT', code='unsupported',
         junction=True, roots=('C:',))
    save('sensitive-dangling', ['Destination'], 'H00\\local.txt', 'H00/local.txt', sensitive=True)
    save('dangling', ['missing'], 'H00\\file.txt', 'H00/file.txt')
    save('dangling-alias', ['missing'], 'H00\\~file', code='unsupported')
    save('dangling-escape', ['missing'], 'H00\\..\\..\\file.txt', code='unsupported')
    save('not-directory', ['fragmented.bin'], 'H00\\file.txt', code='not-directory')
    save('opaque', ['Destination'], 'H00\\Local.TXT', code='unsupported', opaque=True)
    save('malformed', ['Destination'], 'H00\\Local.TXT', code='corrupt', malformed=True)
    save('hardlinked', ['Destination'], 'H00\\Local.TXT', code='unsupported', links=2)
    save('self-loop', ['H00'], 'H00\\Local.TXT', code='loop')
    save('two-loop', ['H01', 'H00'], 'H00\\Local.TXT', code='loop')
    save('outer-loop', ['hello.txt'], 'H00\\Local.TXT', code='loop')
    for count, code in ((CHAIN_RESOLUTION_LIMIT - 1, 'ok'), (CHAIN_RESOLUTION_LIMIT, 'loop')):
        targets = [f'H{index + 1:02d}' for index in range(count - 1)] + ['Destination']
        save(f'depth-{code}', targets, 'H00\\local.txt', 'H00/Local.TXT' if code == 'ok' else None,
             code=code)
        components = ['H00', '..'] * count + ['fragmented.bin']
        save(f'reuse-{code}', ['Destination'], '\\'.join(components),
             '/'.join(components) if code == 'ok' else None, code=code)
    leaf_alias = f'~ntfs-{f.file_reference(TARGET_RECORD):016x}-{0:08x}'
    # Four visible root entries precede/contain the reserved destination; the
    # independent leaf directory then contributes one raw entry to the budget.
    alias_reads = 4 + 1
    save('alias', ['~Destination'], 'H00\\~local', 'H00/' + leaf_alias,
         destination='~Destination', leaf='~local')
    save('alias-boundary', ['~Destination'], 'H00\\~local', 'H00/' + leaf_alias,
         destination='~Destination', leaf='~local', maximum=alias_reads)
    save('alias-range', ['~Destination'], 'H00\\~local', code='range',
         destination='~Destination', leaf='~local', maximum=alias_reads - 1)
    inner = ['.'] * CHAIN_INNER_DOTS + ['Destination']
    outer_dots = NATIVE_COMPONENT_LIMIT - len(inner) - 2
    for extra, code in ((0, 'ok'), (1, 'range')):
        outer = ['.'] * (outer_dots + extra) + ['H00', 'local.txt']
        native = ['.'] * (outer_dots + extra) + ['H00', 'Local.TXT']
        save('components-' + code, ['\\'.join(inner)], '\\'.join(outer),
             '/'.join(native) if code == 'ok' else None, code=code)
    return cases
