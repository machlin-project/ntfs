"""Independent namespace/content expectations shared by offline and mounted acceptance."""
import hashlib

PRESSURE_FILES = 320
REPLACEMENT_FILES = 80
NAME_UNITS = 180
PAYLOAD_BYTES = 129
DIRECTORIES = ('native-growth', 'native-move')
PHASES = ('full', 'contracted', 'reused', 'empty')


def pressure_name(identifier):
    assert 0 <= identifier < PRESSURE_FILES
    prefix = f'pressure-{identifier:04d}-'
    return prefix + 'n' * (NAME_UNITS - len(prefix))


def replacement_name(identifier):
    assert 0 <= identifier < REPLACEMENT_FILES
    return f'replacement-{identifier:04d}'


def contents(identifier, mounted=False):
    if not mounted:
        return b''
    value = bytearray((identifier * 17 + index * 37 + 11) & 255 for index in range(PAYLOAD_BYTES))
    value[:2] = identifier.to_bytes(2, 'big')
    return bytes(value)


def expected(phase, mounted=False):
    assert phase in PHASES
    names = {}
    if phase != 'empty':
        for identifier in range(PRESSURE_FILES):
            if phase == 'full' or (identifier != 0 and identifier % 4 == 0):
                names['native-growth/' + pressure_name(identifier)] = contents(identifier, mounted)
    if phase in ('contracted', 'reused'):
        names['native-move/sustained-renamed'] = contents(0, mounted)
    if phase == 'reused':
        for identifier in range(REPLACEMENT_FILES):
            names['native-growth/' + replacement_name(identifier)] = contents(PRESSURE_FILES + identifier, mounted)
    return names


def operations():
    yield 'mkdir', 'native-growth', (), None
    yield 'mkdir', 'native-move', (), None
    for identifier in range(PRESSURE_FILES):
        yield 'create', 'native-growth/' + pressure_name(identifier), (), 'full' if identifier == PRESSURE_FILES - 1 else None
    yield 'rename', 'native-growth/' + pressure_name(0), ('native-move/sustained-renamed', 0), None
    victims = [identifier for identifier in range(PRESSURE_FILES) if identifier % 4]
    for identifier in victims:
        yield 'remove', 'native-growth/' + pressure_name(identifier), (), 'contracted' if identifier == victims[-1] else None
    for identifier in range(REPLACEMENT_FILES):
        yield 'create', 'native-growth/' + replacement_name(identifier), (), 'reused' if identifier == REPLACEMENT_FILES - 1 else None
    names = list(expected('reused'))
    for index, name in enumerate(names):
        yield 'remove', name, (), 'empty' if index == len(names) - 1 else None


def verify_objects(rows, phase, mounted=False):
    wanted = expected(phase, mounted)
    actual = {}
    directories = []
    for row in rows:
        assert row['present'] is True
        name = row['relativePath'].replace('\\', '/')
        if row['directory']:
            directories.append(name)
        else:
            assert name not in actual
            actual[name] = row
    assert sorted(directories) == sorted(DIRECTORIES) and set(actual) == set(wanted)
    for name, value in wanted.items():
        assert actual[name]['bytes'] == len(value)
        assert actual[name]['sha256'] == hashlib.sha256(value).hexdigest()
