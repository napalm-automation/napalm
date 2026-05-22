"""Test the method get_network_driver."""

import types
import unittest
from unittest.mock import patch
from ddt import ddt, data

import napalm

from napalm.base import get_network_driver
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ModuleImportError
from napalm.base import _validate_driver_name


# ---------------------------------------------------------------------------
# Shared mock helpers
# ---------------------------------------------------------------------------


class _FakeDriver(NetworkDriver):
    """Minimal NetworkDriver subclass used as a stand-in by unit tests."""


_FAKE_MODULE = types.ModuleType("fake_driver_module")
_FAKE_MODULE.FakeDriver = _FakeDriver


def _fail_import(mod_name: str) -> None:
    """side_effect helper: always raises ImportError for the given module name."""
    raise ImportError(f"No module named {mod_name}")


# ---------------------------------------------------------------------------
# Integration tests — require all driver packages to be installed
# ---------------------------------------------------------------------------


@ddt
class TestGetNetworkDriverIntegration(unittest.TestCase):
    """Integration tests for get_network_driver: exercises real driver imports."""

    @data(*napalm.SUPPORTED_DRIVERS)
    def test_get_network_driver(self, driver):
        """Check that we can get the desired driver and it is a subclass of NetworkDriver."""
        self.assertTrue(issubclass(get_network_driver(driver), NetworkDriver))

    @data("fake00001", "network00001", "driver00001")
    def test_get_wrong_network_driver(self, driver):
        """Check that a non-existent driver raises ModuleImportError."""
        self.assertRaises(ModuleImportError, get_network_driver, driver, prepend=False)


# ---------------------------------------------------------------------------
# Unit tests — mock importlib.import_module; no driver installs required
# ---------------------------------------------------------------------------


@ddt
class TestGetNetworkDriverUnit(unittest.TestCase):
    """Unit tests for get_network_driver logic, independent of driver installation."""

    @data(*napalm.SUPPORTED_DRIVERS)
    def test_get_network_driver(self, driver):
        """get_network_driver returns a NetworkDriver subclass and calls import_module."""
        with patch("napalm.base.importlib.import_module", return_value=_FAKE_MODULE) as mock_import:
            result = get_network_driver(driver)
        self.assertTrue(issubclass(result, NetworkDriver))
        mock_import.assert_called()

    @data("fake00001", "network00001", "driver00001")
    def test_get_wrong_network_driver(self, driver):
        """get_network_driver raises ModuleImportError when all candidate imports fail."""
        with patch("napalm.base.importlib.import_module", side_effect=_fail_import):
            self.assertRaises(ModuleImportError, get_network_driver, driver, prepend=False)

    # --- prepend=False behaviour ---

    @data("eos", "ios", "junos", "fake00001")
    def test_prepend_false_without_napalm_raises(self, driver):
        """prepend=False with a bare name (no 'napalm' in it) must raise immediately."""
        self.assertRaises(ModuleImportError, get_network_driver, driver, prepend=False)

    @data("napalm.eos", "napalm_eos", "napalm.junos", "napalm_junos")
    def test_prepend_false_with_napalm_name_accepted(self, driver):
        """prepend=False with a name that already contains 'napalm' is accepted."""
        with patch("napalm.base.importlib.import_module", return_value=_FAKE_MODULE) as mock_import:
            result = get_network_driver(driver, prepend=False)
        self.assertTrue(issubclass(result, NetworkDriver))
        mock_import.assert_called()


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
