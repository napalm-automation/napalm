"""Tests for getters."""

from napalm.base.test.getters import BaseTestGetters, wrap_test_cases
from napalm.base.test import helpers
from napalm.base.test import models

import pytest
from mock import patch


def mock_time():
    return 1500000000.000000


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""
    @patch('time.time', mock_time)
    @wrap_test_cases
    def test_get_interfaces(self, test_case):
        """Test get_interfaces."""
        get_interfaces = self.device.get_interfaces()
        assert len(get_interfaces) > 0

        for interface, interface_data in get_interfaces.items():
            assert helpers.test_model(models.interface, interface_data)

        return get_interfaces

    @wrap_test_cases
    def test_get_interfaces_ip_multiple_ipv6(self, test_case):
        """Test get_interfaces_ip. Covers cases when multiple IPv6 addresses are returned"""
        get_interfaces_ip = self.device.get_interfaces_ip()
        assert len(get_interfaces_ip) > 0

        for interface, interface_details in get_interfaces_ip.items():
            ipv4 = interface_details.get('ipv4', {})
            ipv6 = interface_details.get('ipv6', {})
            for ip, ip_details in ipv4.items():
                assert helpers.test_model(models.interfaces_ip, ip_details)
            for ip, ip_details in ipv6.items():
                assert helpers.test_model(models.interfaces_ip, ip_details)

        return get_interfaces_ip
