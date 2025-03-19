"""Tests for getters."""

from napalm.base.test.getters import BaseTestGetters

import pytest
from mock import patch


def mock_time():
    return 1500000000.000000


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""

    test_get_interfaces = patch("time.time", mock_time)(
        BaseTestGetters.test_get_interfaces
    )
