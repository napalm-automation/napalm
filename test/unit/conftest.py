"""Test fixtures."""
from builtins import super

import pytest
from napalm_base.test import conftest as parent_conftest
from napalm_base.test.double import BaseTestDouble

from napalm_fortios import FortiOSDriver as OriginalDriver
from pyFG.fortios import FortiConfig


@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = OriginalDriver
    request.cls.patched_driver = PatchedDriver
    request.cls.vendor = 'fortios'
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedDriver(OriginalDriver):
    """Patched Driver."""
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(hostname, username, password, timeout, optional_args)
        self.patched_attrs = ['device']
        self.device = FakeDevice()

    def open(self):
        pass

    def close(self):
        pass

    def is_alive(self):
        return({'is_alive': True})


class FakeDevice(BaseTestDouble):
    """Device test double."""

    def open(self):
        pass

    def close(self):
        pass

    def execute_command(self, command):
        filename = '{}.txt'.format(self.sanitize_text(command))
        full_path = self.find_file(filename)
        return self.read_txt_file(full_path).splitlines()

    def load_config(self, config_block):
        filename = '{}.txt'.format(self.sanitize_text(config_block))
        full_path = self.find_file(filename)

        self.running_config = FortiConfig('running')
        self.running_config.parse_config_output(self.read_txt_file(full_path))
