"""Tests for getters."""
from __future__ import print_function
from __future__ import unicode_literals

from napalm.base.test.getters import BaseTestGetters


import pytest


# @pytest.mark.usefixtures("set_device_parameters")
# @pytest.mark.parametrize("set_device_parameters", [1])
# class TestGetter(BaseTestGetters):
#    """Test get_* methods."""


@pytest.mark.usefixtures("set_device_parameters")
class TestGetterCanonical(BaseTestGetters):
    """Test get_* methods."""
