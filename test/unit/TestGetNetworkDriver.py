"""Test the method get_network_driver."""
from __future__ import print_function
from __future__ import unicode_literals

import unittest
from ddt import ddt, data

from napalm_base import get_network_driver
from napalm_base.base import NetworkDriver
from napalm_base.exceptions import ModuleImportError
from napalm_base.utils.py23_compat import PY2, PY3


@ddt
class TestGetNetworkDriver(unittest.TestCase):
    """Test the method get_network_driver."""

    drivers_common = ('eos', 'ios', 'iosxr', 'IOS-XR', 'junos', 'ros', 'nxos',
                      'pluribus', 'panos', 'vyos')
    drivers_py2_only = ('fortios', 'ibm')
    if PY2:
        # All drivers support python2
        network_drivers = drivers_common + drivers_py2_only
    elif PY3:
        # Drivers that support python2 and python3
        network_drivers = drivers_common

    @data(*network_drivers)
    def test_get_network_driver(self, driver):
        """Check that we can get the desired driver and is instance of NetworkDriver."""
        self.assertTrue(issubclass(get_network_driver(driver), NetworkDriver))

    @data('fake', 'network', 'driver')
    def test_get_wrong_network_driver(self, driver):
        """Check that inexisting driver throws ModuleImportError."""
        self.assertRaises(ModuleImportError, get_network_driver, driver)
