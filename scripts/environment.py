"""Isolate build tools and fix archive timestamps for ordinary Release builds.

Meson records its environment in test reports. Never forward ambient cloud,
payment, signing-service or API credentials into those reports.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys

TOOL_QUERY_TIMEOUT_SECONDS = 15

def tool_environment():
    allowed = ('PATH', 'HOME', 'USER', 'LOGNAME', 'TMPDIR', 'TMP', 'TEMP',
               'SystemRoot', 'DEVELOPER_DIR', 'TOOLCHAINS')
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    # Apple ar and ranlib honor this without rewriting completed products.
    environment.update({'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TERM': 'dumb',
                        'ZERO_AR_DATE': '1'})
    return environment


def sanitizer_environment():
    """Keep tool isolation and make ASan/UBSan findings terminate their child."""
    environment = tool_environment()
    environment.update({
        'ASAN_OPTIONS': 'halt_on_error=1:abort_on_error=1:print_summary=1',
        'UBSAN_OPTIONS': 'halt_on_error=1:abort_on_error=1:print_summary=1:print_stacktrace=1',
    })
    return environment


def selected_toolchain(compiler=None):
    """Choose one executable without forwarding ambient CC or compiler flags.

    Darwin retains the selected Xcode SDK even with an explicit LLVM compiler.
    A compiler override is an executable name/path, never a shell command.
    """
    environment = tool_environment()
    if sys.platform == 'darwin':
        def xcrun(*arguments):
            return subprocess.check_output(
                ['xcrun', *arguments], env=environment.copy(), stdin=subprocess.DEVNULL,
                text=True, timeout=TOOL_QUERY_TIMEOUT_SECONDS).strip()

        selected = compiler or xcrun('--find', 'clang')
        sdk = xcrun('--show-sdk-path')
        if not Path(sdk).is_dir():
            raise ValueError('The selected Xcode SDK does not exist')
        environment['SDKROOT'] = sdk
    else:
        selected = compiler or 'cc'
    executable = shutil.which(selected, path=environment.get('PATH', os.defpath))
    if executable is None:
        raise ValueError(f'C compiler executable not found: {selected}')
    environment['CC'] = str(Path(executable).resolve())
    return environment
