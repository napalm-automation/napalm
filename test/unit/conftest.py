"""Test fixtures."""
from builtins import super

import pytest
from napalm_base.test import conftest as parent_conftest
from napalm_base.test.double import BaseTestDouble

from napalm_panos import PANOSDriver as OriginalDriver


@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = OriginalDriver
    request.cls.patched_driver = PatchedDriver
    request.cls.vendor = 'panos'
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

    def __init__(self):
        self.cmd = ''

    @staticmethod
    def read_txt_file(filename):
        """Read a txt file and return its content."""
        with open(filename) as data_file:
            return data_file.read()

    def xml_root(self):
        tmp_str = self.cmd.replace('<', '_').replace('>', '_')
        filename = tmp_str.replace('/', '_').replace('\n', '').replace(' ', '')
        full_path = self.find_file('{}.xml'.format(filename))
        xml_string = self.read_txt_file(full_path)
        return xml_string

    def op(self, cmd=''):
        self.cmd = cmd
        return True

    def show(self, cmd=''):
        self.cmd = 'running_config'
        return True
