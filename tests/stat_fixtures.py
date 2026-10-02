"""Author stream-metadata layouts independently of the core implementation."""
import struct
import fixtures as f

FILE_RECORD = f.FILE_RECORDS['hello.txt']
# Preserve extended.bin's continuation by using the last unused MFT slot.
EXTENSION_RECORD = f.MFT_COUNT - 1
DATA_INSTANCE = 1
LIST_INSTANCE = 2
ADS_INSTANCE = 3
LIST_LCN = 150
UNKNOWN_COMPRESSION_FORMAT = 2
UNKNOWN_ATTRIBUTE_FLAG = 0x2000
ATTRIBUTE_FIELDS = ('type', 'length', 'form', 'name_length', 'name_offset', 'flags', 'instance')
NONRESIDENT_FIELDS = ('lowest', 'highest', 'mapping_offset', 'compression_unit',
                      'allocated', 'size', 'initialized')
ADS_PAYLOAD = b'independent stream payload'


def change_header(attribute, **changes):
    value = bytearray(attribute)
    fields = dict(zip(NONRESIDENT_FIELDS,
                      f.NONRESIDENT_HEADER.unpack_from(value, f.ATTR_HEADER.size)))
    fields.update(changes)
    f.NONRESIDENT_HEADER.pack_into(value, f.ATTR_HEADER.size,
                                  *(fields[name] for name in NONRESIDENT_FIELDS))
    return bytes(value)


def change_flags(attribute, flags):
    value = bytearray(attribute)
    fields = dict(zip(ATTRIBUTE_FIELDS, f.ATTR_HEADER.unpack_from(value)))
    fields['flags'] = flags
    f.ATTR_HEADER.pack_into(value, 0, *(fields[name] for name in ATTRIBUTE_FIELDS))
    return bytes(value)


def author(output, source):
    runs = [(1, lcn) for lcn in f.DATA_LCNS['fragmented.bin']]
    encrypted = f.nonresident(f.DATA, runs, f.FRAGMENTED_BYTES, DATA_INSTANCE,
                              flags=f.ENCRYPTED)
    compressed = f.nonresident(f.DATA, runs, f.FRAGMENTED_BYTES, DATA_INSTANCE,
                               flags=f.COMPRESSED)
    encoded = change_flags(compressed, UNKNOWN_COMPRESSION_FORMAT)

    def save(name, attribute, file_flags=0, extension=None, nonresident_list=False,
             next_vcn=1):
        image = bytearray(source)
        attributes = [f.standard(file_flags), attribute]
        if extension is not None:
            listing = f.list_entry(f.file_reference(FILE_RECORD), 0, 0, kind=f.SI)
            listing += f.list_entry(f.file_reference(FILE_RECORD), DATA_INSTANCE, 0)
            listing += f.list_entry(f.file_reference(EXTENSION_RECORD),
                                    0, next_vcn)
            listing += f.list_entry(f.file_reference(FILE_RECORD), ADS_INSTANCE,
                                    0, name='notes')
            list_attribute = (f.nonresident(f.ATTR_LIST, [(1, LIST_LCN)],
                                            len(listing), LIST_INSTANCE)
                              if nonresident_list else
                              f.resident(f.ATTR_LIST, listing, LIST_INSTANCE))
            attributes.insert(1, list_attribute)
            f.put_record(image, EXTENSION_RECORD, extension)
            if nonresident_list:
                f.put_data(image, LIST_LCN, listing)
        attributes.append(f.resident(f.DATA, ADS_PAYLOAD, ADS_INSTANCE, 'notes'))
        f.put_record(image, FILE_RECORD, f.file_record(FILE_RECORD, attributes))
        (output / ('stat-' + name + '.img')).write_bytes(image)

    save('encrypted', encrypted, f.FILE_ATTRIBUTE_ENCRYPTED)
    save('format', encoded, f.FILE_ATTRIBUTE_COMPRESSED)
    save('unit', change_header(compressed, compression_unit=f.COMPRESSION_UNIT_SHIFT + 1),
         f.FILE_ATTRIBUTE_COMPRESSED)
    save('empty-encrypted', f.nonresident(f.DATA, [], 0, DATA_INSTANCE,
                                         flags=f.ENCRYPTED), f.FILE_ATTRIBUTE_ENCRYPTED)
    save('bad-vdl', change_header(encrypted, initialized=f.FRAGMENTED_BYTES + 1),
         f.FILE_ATTRIBUTE_ENCRYPTED)
    save('bad-allocation', change_header(encrypted, allocated=f.CLUSTER),
         f.FILE_ATTRIBUTE_ENCRYPTED)
    save('short-mapping', change_header(encrypted, highest=len(runs)),
         f.FILE_ATTRIBUTE_ENCRYPTED)
    save('unknown-flags', change_flags(encrypted, f.ENCRYPTED | UNKNOWN_ATTRIBUTE_FLAG),
         f.FILE_ATTRIBUTE_ENCRYPTED)
    save('resident-flags', change_flags(f.resident(f.DATA, ADS_PAYLOAD, DATA_INSTANCE),
                                       f.ENCRYPTED), f.FILE_ATTRIBUTE_ENCRYPTED)
    bad_physical = bytearray(encoded)
    struct.pack_into('<Q', bad_physical, f.ATTR_HEADER.size + f.NONRESIDENT_HEADER.size,
                     f.CLUSTER)
    save('bad-physical', bytes(bad_physical), f.FILE_ATTRIBUTE_COMPRESSED)
    base = f.nonresident(f.DATA, runs[:1], f.FRAGMENTED_BYTES, DATA_INSTANCE,
                         flags=f.ENCRYPTED, allocated=len(runs) * f.CLUSTER)
    continuation = f.nonresident(f.DATA, runs[1:], 0, lowest=1, flags=f.ENCRYPTED)

    def extension(attribute=continuation, **kwargs):
        return f.file_record(EXTENSION_RECORD, [attribute],
                             base=f.file_reference(FILE_RECORD), **kwargs)

    save('listed-encrypted', base, f.FILE_ATTRIBUTE_ENCRYPTED, extension())
    save('nonresident-list', base, f.FILE_ATTRIBUTE_ENCRYPTED, extension(), True)
    save('stale-extension', base, f.FILE_ATTRIBUTE_ENCRYPTED,
         extension(sequence=f.FILE_SEQUENCE + 1))
    save('gap', base, f.FILE_ATTRIBUTE_ENCRYPTED,
         extension(change_header(continuation, lowest=len(runs), highest=len(runs))),
         next_vcn=len(runs))
    save('continuation-flags', base, f.FILE_ATTRIBUTE_ENCRYPTED,
         extension(change_flags(continuation, 0)))
