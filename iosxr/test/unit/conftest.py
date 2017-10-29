"""Test fixtures."""
from __future__ import print_function
from __future__ import unicode_literals

from builtins import super

import pytest
from napalm_base.test import conftest as parent_conftest

from napalm_base.test.double import BaseTestDouble

from napalm_iosxr import iosxr


@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = iosxr.IOSXRDriver
    request.cls.patched_driver = PatchedIOSXRDriver
    request.cls.vendor = 'iosxr'
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedIOSXRDriver(iosxr.IOSXRDriver):
    """Patched IOS Driver."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):

        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ['device']
        self.device = FakeIOSXRDevice()

    def is_alive(self):
        return {
            'is_alive': True  # In testing everything works..
        }

    def open(self):
        pass


class FakeIOSXRDevice(BaseTestDouble):
    """IOSXR device test double."""

    def close(self):
        pass

    def make_rpc_call(self, rpc_call, encoded=True):
        filename = '{}.txt'.format(self.sanitize_text(rpc_call))
        full_path = self.find_file(filename)
        result = self.read_txt_file(full_path)
        if encoded:
            return str.encode(result)
        else:
            return result

    def show_lldp_neighbors(self):
        filename = 'show_lldp_neighbors.txt'
        full_path = self.find_file(filename)
        result = self.read_txt_file(full_path)
        return result

    def _execute_config_show(self, show_command):
        rpc_request = '<CLI><Configuration>{show_command}</Configuration></CLI>'.format(
            show_command=show_command
        )
        return self.make_rpc_call(rpc_request, encoded=False)
