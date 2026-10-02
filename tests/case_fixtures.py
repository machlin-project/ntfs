"""Author case-policy images; synthetic evidence, not Windows qualification."""
import fixtures as f

CASE_INSENSITIVE = 0
CASE_SENSITIVE = 1
UNKNOWN_DIRECTORY_POLICY = 2
STORAGE_HINT = 0x76543200
LEGACY_VERSION_LIMIT = 3
SENSITIVE_DIRECTORY = 48
INSENSITIVE_DIRECTORY = 49
INDEX_EXTENSION = 42
LEFT_VCN, RIGHT_VCN, PARENT_VCN = 0, 1, 2
TWO_CHILDREN = 2
NESTED_BLOCKS = 3
NAMES = (('A.txt', 50), ('a.txt', 54), ('Foo.txt', 51), ('foo.txt', 52),
         ('Z.txt', 53), ('Ωmega', 56), ('ωmega', 57))
SEPARATOR = 'foo.txt'


def payload(name):
    return b'case-file/' + name.encode('utf-8')


def author(output, source):
    image = bytearray(source)
    numbers = dict(NAMES)
    for name, number in NAMES:
        f.put_record(image, number, f.file_record(number, [f.standard(version=UNKNOWN_DIRECTORY_POLICY),
                     f.resident(f.DATA, payload(name), 1)]))

    def link(name, child=None, parent=f.ROOT_REF):
        return f.entry(name, numbers[name], len(payload(name)), child=child, parent=parent)

    def write(name, changed):
        (output / ('case-' + name + '.img')).write_bytes(changed)

    def resident(version, names=NAMES, **options):
        changed = bytearray(image)
        entries = b''.join(link(name) for name, _ in names) + f.entry()
        f.put_record(changed, f.ROOT_RECORD, f.directory_record(entries, version=version, **options))
        return changed

    sensitive = resident(CASE_SENSITIVE)
    write('resident', sensitive)
    write('common', resident(CASE_SENSITIVE, common_only=True))
    write('storage-sensitive', resident(STORAGE_HINT | CASE_SENSITIVE))
    unique = (('Foo.txt', numbers['Foo.txt']), ('Z.txt', numbers['Z.txt']))
    write('insensitive', resident(CASE_INSENSITIVE, unique))
    write('storage-insensitive', resident(STORAGE_HINT | CASE_INSENSITIVE, unique))
    write('legacy-version', resident(UNKNOWN_DIRECTORY_POLICY, unique,
                                     max_versions=LEGACY_VERSION_LIMIT))
    write('unknown-root', resident(UNKNOWN_DIRECTORY_POLICY))

    tree = bytearray(image)
    separator_index = next(i for i, (name, _) in enumerate(NAMES) if name == SEPARATOR)
    left = [link(name) for name, _ in NAMES[:separator_index]]
    right = [link(name) for name, _ in NAMES[separator_index + 1:]]
    f.put_data(tree, f.INDEX_LCN + LEFT_VCN, f.index_block(LEFT_VCN, left))
    f.put_data(tree, f.INDEX_LCN + RIGHT_VCN, f.index_block(RIGHT_VCN, right))
    root_entries = link(SEPARATOR, LEFT_VCN) + f.entry(child=RIGHT_VCN)
    f.put_record(tree, f.ROOT_RECORD, f.directory_record(root_entries, TWO_CHILDREN, version=CASE_SENSITIVE))
    write('external', tree)
    insensitive = bytearray(tree)
    f.put_record(insensitive, f.ROOT_RECORD, f.directory_record(root_entries, TWO_CHILDREN))
    write('insensitive-collision', insensitive)
    nested = bytearray(tree)
    f.put_data(nested, f.INDEX_LCN + PARENT_VCN,
               f.index_block(PARENT_VCN, [link(SEPARATOR, LEFT_VCN)], RIGHT_VCN))
    f.put_record(nested, f.ROOT_RECORD, f.directory_record(f.entry(child=PARENT_VCN),
                 NESTED_BLOCKS, version=CASE_SENSITIVE))
    write('nested', nested)

    listed = bytearray(tree)
    index_root = f.INDEX_ROOT_HEADER.pack(f.FILENAME, f.COLLATION_FILENAME, f.CLUSTER, 1)
    index_root += f.INDEX_HEADER.pack(f.INDEX_HEADER.size, f.INDEX_HEADER.size + len(root_entries),
                                     f.INDEX_HEADER.size + len(root_entries), f.INDEX_LARGE)
    index_root += root_entries
    bitmap = ((1 << TWO_CHILDREN) - 1).to_bytes((TWO_CHILDREN + f.BYTE_BITS - 1) // f.BYTE_BITS, 'little')
    root_ref = f.file_reference(f.ROOT_RECORD)
    attribute_list = (f.list_entry(root_ref, 0, 0, f.SI) +
                      f.list_entry(f.file_reference(INDEX_EXTENSION), f.DIR_ROOT_INSTANCE, 0, f.INDEX_ROOT, '$I30') +
                      f.list_entry(root_ref, f.DIR_ALLOCATION_INSTANCE, 0, f.INDEX_ALLOC, '$I30') +
                      f.list_entry(root_ref, f.DIR_BITMAP_INSTANCE, 0, f.BITMAP, '$I30'))
    list_instance = f.DIR_BITMAP_INSTANCE + 1
    f.put_record(listed, f.ROOT_RECORD, f.file_record(f.ROOT_RECORD, [
        f.standard(f.FILE_ATTRIBUTE_DIRECTORY, version=CASE_SENSITIVE),
        f.resident(f.ATTR_LIST, attribute_list, list_instance),
        f.nonresident(f.INDEX_ALLOC, [(TWO_CHILDREN, f.INDEX_LCN)], TWO_CHILDREN * f.CLUSTER,
                      f.DIR_ALLOCATION_INSTANCE, '$I30'),
        f.resident(f.BITMAP, bitmap, f.DIR_BITMAP_INSTANCE, '$I30')], directory=True))
    f.put_record(listed, INDEX_EXTENSION, f.file_record(INDEX_EXTENSION, [
        f.resident(f.INDEX_ROOT, index_root, f.DIR_ROOT_INSTANCE, '$I30')], base=root_ref))
    write('listed', listed)

    def mixed(root_policy, sensitive_policy=CASE_SENSITIVE):
        changed = bytearray(image)
        foo_number = numbers['Foo.txt']
        f.put_record(changed, foo_number, f.file_record(foo_number,
                     [f.standard(), f.resident(f.DATA, payload('Foo.txt'), 1)], links=TWO_CHILDREN))
        for directory, policy, names in (
                (SENSITIVE_DIRECTORY, sensitive_policy, ('Foo.txt', 'foo.txt')),
                (INSENSITIVE_DIRECTORY, CASE_INSENSITIVE, ('Foo.txt',))):
            own_ref = f.file_reference(directory)
            entries = b''.join(link(name, parent=own_ref) for name in names) + f.entry()
            f.put_record(changed, directory, f.directory_record(entries, number=directory, version=policy))
        entries = (f.entry('Insensitive', INSENSITIVE_DIRECTORY, attributes=f.FILE_ATTRIBUTE_DIRECTORY) +
                   f.entry('Sensitive', SENSITIVE_DIRECTORY, attributes=f.FILE_ATTRIBUTE_DIRECTORY) + f.entry())
        f.put_record(changed, f.ROOT_RECORD, f.directory_record(entries, version=root_policy))
        return changed

    write('mixed', mixed(CASE_INSENSITIVE))
    write('mixed-sensitive-root', mixed(CASE_SENSITIVE))
    write('unknown-child', mixed(CASE_INSENSITIVE, UNKNOWN_DIRECTORY_POLICY))
    wrong_parent = bytearray(tree)
    left[0] = link(NAMES[0][0], parent=f.file_reference(SENSITIVE_DIRECTORY))
    f.put_data(wrong_parent, f.INDEX_LCN + LEFT_VCN, f.index_block(LEFT_VCN, left))
    write('wrong-parent', wrong_parent)
    wrong_order = bytearray(tree)
    # Raw UTF-16 would place Z before a: NTFS filename collation does not.
    f.put_data(wrong_order, f.INDEX_LCN + LEFT_VCN,
               f.index_block(LEFT_VCN, [link('Z.txt'), link('a.txt')]))
    write('wrong-order', wrong_order)
    stale = bytearray(tree)
    foo_number = numbers['Foo.txt']
    f.put_record(stale, foo_number, f.file_record(foo_number,
                 [f.standard(), f.resident(f.DATA, payload('Foo.txt'), 1)], sequence=f.FILE_SEQUENCE + 1))
    write('stale', stale)
