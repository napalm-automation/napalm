"""Test the method get_network_driver."""


import unittest
from ddt import ddt, data, unpack

from napalm_base import get_network_driver


@ddt
class TestGetNetworkDriver(unittest.TestCase):
    """Test the method get_network_driver."""

    @data('eos', 'fortios', 'ios', 'iosxr', 'junos', 'nxos', 'pluribus')
    def test_get_network_driver(self, driver):
        """Check that we can get the desired driver."""
        self.assertTrue(get_network_driver(driver))
