"""Tests for getters."""
from __future__ import print_function
from __future__ import unicode_literals

from napalm_base.test.getters import BaseTestGetters


import pytest


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    """Test get_* methods."""
