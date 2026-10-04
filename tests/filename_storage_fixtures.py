#!/usr/bin/env python3
"""Author native namespace inputs with complete selected filename storage.

These are selected-object storage oracles, not whole-volume diagnostic images.
Unreferenced legacy fixture records and system stores retain their original scope.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile

import fixtures as f
from filename_storage import FILENAME_FIELDS, FilenameStorage, record_parts


def root_filename():
    return f.key('.', namespace=f.NAMESPACE_WIN32_DOS, attributes=f.FILE_ATTRIBUTE_DIRECTORY)


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    manifest = []

    def save(label, source, names, streams, *, rejected_reference=None, rejected_result=None,
             lookup_cases=()):
        original_digest = hashlib.sha256(source).hexdigest()
        writer = FilenameStorage(source)
        expected = []
        for number, payloads in names.items():
            original_header = writer.parts[number][0]
            writer.filenames(number, payloads)
            namespaces = [dict(zip(FILENAME_FIELDS, f.FILENAME_HEADER.unpack_from(payload)))['namespace']
                          for payload in payloads]
            reference = f.file_reference(number, original_header['sequence'])
            expected.append({'reference': f'{reference:016x}',
                             'filename_body_hashes': sorted(hashlib.sha256(body).hexdigest()
                                                            for body in payloads),
                             'counts': {'physical_names': len(payloads),
                                        'primary_names': sum(ns != f.NAMESPACE_DOS for ns in namespaces),
                                        'dos_aliases': namespaces.count(f.NAMESPACE_DOS)},
                             'result': rejected_result if reference == rejected_reference else 'success'})
        image = writer.finish()
        assert hashlib.sha256(source).hexdigest() == original_digest
        filename = label + '.img'
        (output / filename).write_bytes(image)
        manifest.append({'image': filename, 'objects': expected,
                         'lookup_cases': list(lookup_cases),
                         'streams': [{'reference': f'{reference:016x}', 'hex': content.hex()}
                                     for reference, content in streams.items()],
                         'mft_record_slots': writer.mft_record_slots,
                         'new_extension_records': writer.next_record - writer.original_records,
                         'source_sha256': original_digest,
                         'sha256': hashlib.sha256(image).hexdigest()})

    for label, legacy in (('standard', False), ('ntfs30', True)):
        source, contents, _ = f.make_image(legacy=legacy)
        names = {f.ROOT_RECORD: [root_filename()]}
        names.update({f.FILE_RECORDS[name]: [f.key(name, len(content))]
                      for name, content in contents.items()})
        streams = {f.file_reference(f.FILE_RECORDS[name]): content for name, content in contents.items()}
        save(label, source, names, streams)

    source, contents, _ = f.make_image()
    with tempfile.TemporaryDirectory(prefix='filename-author-', dir=output) as temporary:
        authored = Path(temporary)
        f.namespace_fixtures(authored, source, contents)
        for label in ('namespace', 'namespace-sensitive', 'namespace-hidden', 'namespace-large',
                      'namespace-invalid', 'namespace-stale'):
            original = (authored / (label + '.img')).read_bytes()
            number = f.FILE_RECORDS['hello.txt']
            if label == 'namespace-invalid':
                stored_names = ['\0bad']
            else:
                inventory = json.loads((authored / ('namespace-large.json'
                                        if label == 'namespace-large' else 'namespace.json')).read_text())
                stored_names = [b''.join(unit.to_bytes(f.U16_BYTES, 'little') for unit in entry['units'])
                                .decode('utf-16le', errors='surrogatepass') for entry in inventory]
            names = {f.ROOT_RECORD: [root_filename()],
                     number: [f.key(name, len(contents['hello.txt'])) for name in stored_names]}
            if label == 'namespace-hidden':
                # Exact names used by fixtures.namespace_fixtures, including its
                # hidden metadata entry and independently stored DOS alias.
                names[number].append(f.key('AAA~1', len(contents['hello.txt']), namespace=f.NAMESPACE_DOS))
                names[f.VOLUME_RECORD] = [f.key('!metadata')]
            reject = f.file_reference(number) if label == 'namespace-invalid' else None
            header, _ = record_parts(original[f.MFT_LCN * f.CLUSTER + number * f.RECORD:
                                             f.MFT_LCN * f.CLUSTER + (number + 1) * f.RECORD])
            streams = {} if label == 'namespace-invalid' else {f.file_reference(number, header['sequence']):
                                                                contents['hello.txt']}
            lookups = []
            if label == 'namespace-stale':
                lookups.append({'parent': f'{f.ROOT_REF:016x}',
                                'name_units': [ord(unit) for unit in 'hello.txt'],
                                'result': 'stale file reference'})
            save(label, original, names, streams, rejected_reference=reject,
                 rejected_result='corrupt metadata' if reject is not None else None,
                 lookup_cases=lookups)
    (output / 'filename-storage-cases.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('stamp', nargs='?', type=Path)
    args = parser.parse_args()
    author(args.output)
    if args.stamp:
        args.stamp.write_text('authored complete selected filename storage\n')
