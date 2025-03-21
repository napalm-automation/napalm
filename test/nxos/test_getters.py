"""Tests for getters."""

from unittest.mock import patch

from napalm.base.test.getters import BaseTestGetters, wrap_test_cases
from napalm.base.test import helpers
from napalm.base import models

import pytest


def mock_time():
    return 1500000000.000000


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""

    @patch("time.time", mock_time)
    @wrap_test_cases
    def test_get_interfaces(self, test_case):
        """Test get_interfaces."""
        get_interfaces = self.device.get_interfaces()
        assert len(get_interfaces) > 0

        for interface, interface_data in get_interfaces.items():
            assert helpers.test_model(models.InterfaceDict, interface_data)

        return get_interfaces
