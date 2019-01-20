from __future__ import print_function
from __future__ import unicode_literals

import unittest
from napalm.base.base import NetworkDriver
import napalm.base.test.base as ntb

# Note: don't import the TestGettersNetworkDriver class itself, or
# nose finds it and tries to run the tests for it, which yields
# errors.


class TestSkipNotImplemented(unittest.TestCase, ntb.TestGettersNetworkDriver):
    """Ensure that any tests are skipped if not implemented."""

    def setUp(self):
        class FakeThing(NetworkDriver):
            def __init__(self):
                pass

        self.device = FakeThing()
