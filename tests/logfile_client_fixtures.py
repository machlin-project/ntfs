#!/usr/bin/env python3
"""Author selected active/free LFS client snapshots and independent pair queries."""
from pathlib import Path
import json
import sys
import logfile_fixtures as w
from logfile_source_fixtures import restart, SMALL_FILE_BYTES, SMALL_PAGE_BYTES

SUCCESS, STALE = 0, 10
ZERO_SEQUENCE = 0
MAX_SEQUENCE = (1 << (w.WORD_BYTES * w.BITS_PER_BYTE)) - 1
NAME_ALPHABET_START = ord('A')
NAME_ALPHABET_UNITS = 26
UNPAIRED_NAME_UNIT = 0xd800
MIXED_CLIENTS = 5
FREE_CLIENTS = 3
MIXED_ACTIVE_ORDER = (4, 2, 1)
MIXED_FREE_ORDER = (0, 3)
ALL_FREE_ORDER = (1, 0, 2)
FREE_STALE_LSN = (1 << w.LSN_BITS) - 1
CLI_SAMPLE_DIVISOR = 2


def author(output):
    output.mkdir(parents=True, exist_ok=True)
    cases, lines = [], []

    def add(name, sequences, active, free, *, system=SMALL_PAGE_BYTES,
            log=SMALL_PAGE_BYTES, file_bytes=SMALL_FILE_BYTES,
            major=w.LEGACY_MAJOR, minor=w.LEGACY_MINOR):
        count = len(sequences)
        active, free = list(active), list(free)
        assert sorted(active + free) == list(range(count))
        circular = w.RESTART_PAGES * system + (
            w.FAST_PAGES if major == w.FAST_MAJOR else w.LEGACY_TAIL_PAGES) * log
        current = w.lsn_at(circular + w.PAGE_DATA_OFFSET, file_bytes) if active else 0
        entries = []
        for index, sequence in enumerate(sequences):
            chain = active if index in active else free
            position = chain.index(index)
            previous = chain[position - 1] if position else w.NO_CLIENT
            following = chain[position + 1] if position + 1 < len(chain) else w.NO_CLIENT
            name_units = tuple(UNPAIRED_NAME_UNIT if unit == 0 else
                NAME_ALPHABET_START + (index + unit) % NAME_ALPHABET_UNITS
                for unit in range(w.CLIENT_NAME_BYTES // w.WORD_BYTES))
            lsn = current if index in active else FREE_STALE_LSN
            entries.append(w.client(oldest=lsn, restart=lsn, previous=previous,
                following=following, sequence=sequence, name=name_units))
        raw, fields = restart(system=system, log=log, file_bytes=file_bytes,
            major=major, minor=minor, clients=entries, current=current,
            in_use_head=active[0] if active else w.NO_CLIENT,
            free_head=free[0] if free else w.NO_CLIENT)
        source = bytearray(file_bytes)
        for position in range(w.RESTART_PAGES):
            source[position * system:(position + 1) * system] = raw
        filename = name + '.journal'
        (output / filename).write_bytes(source)
        queries = []
        for index, sequence in enumerate(sequences):
            for requested in (sequence, (sequence + 1) & MAX_SEQUENCE):
                queries.append(dict(index=index, sequence=requested,
                    code=SUCCESS if index in active and requested == sequence else STALE,
                    fields=entries[index][1]))
        for index in (count, w.NO_CLIENT):
            queries.append(dict(index=index, sequence=ZERO_SEQUENCE, code=STALE, fields=None))
        sampled = {0, count // CLI_SAMPLE_DIVISOR, count - 1, count, w.NO_CLIENT}
        cases.append(dict(path=filename, client_count=count, active=active, free=free,
            fields=fields, queries=queries,
            cli_queries=[query for query in queries if query['index'] in sampled]))
        for query in queries:
            original = query['fields'] or {}
            units = original.get('name_utf16', [])
            fixed = (filename, query['index'], query['sequence'], query['code'],
                int(query['fields'] is not None), original.get('oldest_lsn', 0),
                original.get('restart_lsn', 0), original.get('previous', 0),
                original.get('next', 0), original.get('sequence', 0), len(units))
            lines.append('\t'.join(map(str, (*fixed, *units))))

    add('zero-sequence', [ZERO_SEQUENCE], [0], [])
    add('maximum-sequence', [MAX_SEQUENCE], [0], [])
    add('mixed-chain', [w.CLIENT_SEQUENCE + index for index in range(MIXED_CLIENTS)],
        MIXED_ACTIVE_ORDER, MIXED_FREE_ORDER, system=w.PAGE_BYTES)
    add('all-free', [w.CLIENT_SEQUENCE + index for index in range(FREE_CLIENTS)],
        [], ALL_FREE_ORDER, system=w.PAGE_BYTES)
    add('empty', [], [], [])
    area = max(w.RESTART_OFFSET, w.aligned(w.RESTART_HEADER.size +
        (w.MAX_PAGE_BYTES // w.USA_STRIDE + 1) * w.WORD_BYTES))
    maximum_clients = (w.MAX_PAGE_BYTES - area - w.CLIENTS_OFFSET) // w.CLIENT.size
    add('maximum-active', [index for index in range(maximum_clients)],
        list(reversed(range(maximum_clients))), [], system=w.MAX_PAGE_BYTES,
        log=w.PAGE_BYTES, file_bytes=w.FILE_BYTES)
    add('fast-mixed-chain', [w.CLIENT_SEQUENCE + index for index in range(MIXED_CLIENTS)],
        MIXED_ACTIVE_ORDER, MIXED_FREE_ORDER, system=w.PAGE_BYTES,
        major=w.FAST_MAJOR, minor=w.FAST_MINOR)
    (output / 'manifest.json').write_text(json.dumps(dict(cases=cases), indent=2) + '\n')
    (output / 'queries.tsv').write_text('\n'.join(lines) + '\n')
    return cases


if __name__ == '__main__':
    author(Path(sys.argv[1]))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text('original-active-client-pairs\n')
