"""Run an offline diagnostic with bounded output and a monotonic deadline."""
import os
from pathlib import Path
import selectors
import stat
import subprocess
import time

from environment import sanitizer_environment

ROOT = Path(__file__).resolve().parents[1]
PIPE_CHUNK_BYTES = 65536
DEFAULT_OUTPUT_BYTES = 4096
DEFAULT_TIMEOUT_SECONDS = 10


def bounded_read(path, limit):
    """Reject special files before reading, including FIFOs without a writer."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('Diagnostic artifact is not a bounded regular file')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Diagnostic artifact exceeds its byte budget')
        return data
    finally:
        os.close(fd)


def run_tool(arguments, *, timeout=DEFAULT_TIMEOUT_SECONDS, output_limit=DEFAULT_OUTPUT_BYTES):
    if timeout <= 0 or output_limit <= 0:
        raise ValueError('Invalid diagnostic execution budget')
    deadline = time.monotonic() + timeout
    output, errors = bytearray(), bytearray()
    process = subprocess.Popen(arguments, cwd=ROOT, env=sanitizer_environment(), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, output)
            selector.register(process.stderr, selectors.EVENT_READ, errors)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Diagnostic exceeded its operation deadline')
                ready = selector.select(remaining)
                if not ready:
                    raise TimeoutError('Diagnostic exceeded its operation deadline')
                for key, _ in ready:
                    chunk = os.read(key.fileobj.fileno(), PIPE_CHUNK_BYTES)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif len(key.data) + len(chunk) > output_limit:
                        raise ValueError('Diagnostic exceeded its output byte budget')
                    else:
                        key.data.extend(chunk)
        process.wait(timeout=max(0, deadline - time.monotonic()))
        if process.returncode != 0:
            raise RuntimeError(f'Diagnostic exited {process.returncode}: ' + errors.decode('utf-8', errors='replace'))
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()
