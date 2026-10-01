"""Ensure ambient credentials cannot enter Meson reports through our launchers."""
from pathlib import Path
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from environment import tool_environment

class EnvironmentTests(unittest.TestCase):
    def test_allowlist(self):
        with patch.dict(os.environ, {'PATH': '/usr/bin', 'HOME': '/tmp/test-user',
                                     'API_KEY': 'test-value', 'AWS_SECRET_ACCESS_KEY': 'test-value',
                                     'UNFAMILIAR_CREDENTIAL': 'test-value', 'CC': 'untrusted-compiler'}, clear=True):
            clean = tool_environment()
        self.assertEqual(clean['PATH'], '/usr/bin')
        self.assertEqual(clean['HOME'], '/tmp/test-user')
        self.assertNotIn('API_KEY', clean)
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', clean)
        self.assertNotIn('UNFAMILIAR_CREDENTIAL', clean)
        self.assertNotIn('CC', clean)

if __name__ == '__main__':
    unittest.main()
