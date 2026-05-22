"""Test the method get_network_driver."""

import unittest
from ddt import ddt, data

import napalm

from napalm.base import get_network_driver
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ModuleImportError
from napalm.base import _validate_driver_name


@ddt
class TestGetNetworkDriver(unittest.TestCase):
    """Test the method get_network_driver."""

    @data(*napalm.SUPPORTED_DRIVERS)
    def test_get_network_driver(self, driver):
        """Check that we can get the desired driver and is instance of NetworkDriver."""
        self.assertTrue(issubclass(get_network_driver(driver), NetworkDriver))

    @data("fake", "network", "driver", "sys", 1)
    def test_get_wrong_network_driver(self, driver):
        """Check that inexisting driver throws ModuleImportError."""
        self.assertRaises(ModuleImportError, get_network_driver, driver, prepend=False)


@ddt
class TestValidateDriverName(unittest.TestCase):
    """Unit tests for _validate_driver_name."""

    # --- cases that must pass without raising ---

    @data(
        # plain identifiers — no dots at all
        "eos",
        "ios",
        "iosxr",
        "nxos",
        "nxosssh",
        "junos",
        "iosxr_netconf",
        # explicit napalm.<driver> form (documented in the docstring)
        "napalm.eos",
        "napalm.junos",
        "napalm.iosxr_netconf",
        # explicit custom_napalm.<driver> form
        "custom_napalm.mydriver",
        "custom_napalm.acme_os",
    )
    def test_valid_names(self, name):
        """_validate_driver_name must not raise for legitimate driver names."""
        # Should complete without raising
        _validate_driver_name(name, name)

    # --- cases that must raise ModuleImportError ---

    @data(
        # arbitrary dot — not under an allowed prefix
        "eos.eos",
        "some.module",
        # deep traversal under the napalm. prefix
        "napalm.eos.eos",
        "napalm.a.b.c",
        # deep traversal under the custom_napalm. prefix
        "custom_napalm.mydriver.sub",
        # leading dot
        ".eos",
        # arbitrary top-level package with dot
        "os.path",
        "subprocess.something",
    )
    def test_invalid_names(self, name):
        """_validate_driver_name must raise ModuleImportError for unsafe names."""
        self.assertRaises(ModuleImportError, _validate_driver_name, name, name)
