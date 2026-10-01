#!/usr/bin/env python3
"""Run core tests without forwarding ambient credentials to Meson reports."""
from pathlib import Path
import subprocess
import sys
from environment import tool_environment

root = Path(__file__).resolve().parents[1]
build = sys.argv[1] if len(sys.argv) > 1 else '.build'
subprocess.run(['meson', 'test', '-C', build, '--print-errorlogs'], cwd=root,
               env=tool_environment(), check=True)
