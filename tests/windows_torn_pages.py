#!/usr/bin/env python3
"""Predict exact native USA observations from independently retained fault bytes."""
import struct

import logfile_fixtures as wire


def logfile_torn_pages(image, logfile_physical, page_physical):
    """Inspect only the journal pages touched by an authored transfer schedule.

    A predicted torn page is evidence of the injected sector mixture, not a
    filesystem health verdict. Native content, metadata, clean state, chkdsk and
    bounded event observations still have to pass independently.
    """
    result = []
    for physical in sorted(set(page_physical)):
        image.seek(physical)
        page = image.read(wire.PAGE_BYTES)
        assert len(page) == wire.PAGE_BYTES
        magic = page[:struct.calcsize('4s')]
        if magic not in (b'RSTR', b'RCRD'):
            continue
        layout = wire.RESTART_HEADER if magic == b'RSTR' else wire.PAGE
        first = struct.unpack_from('<H', page, layout.offsets['usa_offset'])[0]
        count = struct.unpack_from('<H', page, layout.offsets['usa_count'])[0]
        assert count == wire.PAGE_BYTES // wire.USA_STRIDE + 1
        assert first >= layout.size and first + count * wire.WORD_BYTES <= wire.USA_STRIDE - wire.WORD_BYTES
        sequence = struct.unpack_from('<H', page, first)[0]
        for index in range(count - 1):
            tail = (index + 1) * wire.USA_STRIDE - wire.WORD_BYTES
            actual = struct.unpack_from('<H', page, tail)[0]
            if sequence != actual:
                result.append({'bufferOffset': str(physical - logfile_physical),
                               'blockIndex': str(index), 'expectedSequenceNumber': str(sequence),
                               'actualSequenceNumber': str(actual)})
                break
    return result
