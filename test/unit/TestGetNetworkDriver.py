"""Test the method get_network_driver."""


import unittest
from ddt import ddt, data, unpack

from napalm_base import get_network_driver
from napalm_base.base import NetworkDriver
from napalm_base.exceptions import ModuleImportError


@ddt
class TestGetNetworkDriver(unittest.TestCase):
    """Test the method get_network_driver."""

    @data('eos', u'eos', 'fortios', 'ibm', 'ios', 'iosxr', 'IOS-XR', 'junos', 'nxos', 'pluribus', 'panos')
    def test_get_network_driver(self, driver):
        """Check that we can get the desired driver and is instance of NetworkDriver."""
        self.assertTrue(issubclass(get_network_driver(driver), NetworkDriver))

    @data('fake', 'network', 'driver')
    def test_get_wrong_network_driver(self, driver):
        """Check that inexisting driver throws ModuleImportError."""
        self.assertRaises(ModuleImportError, get_network_driver, driver)
