"""Isolate build tools and fix archive timestamps for ordinary Release builds.

Meson records its environment in test reports. Never forward ambient cloud,
payment, signing-service or API credentials into those reports.
"""
import os

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
