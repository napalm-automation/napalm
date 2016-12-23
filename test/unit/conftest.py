"""Test fixtures."""
from builtins import super

import pytest
from napalm_base.test import conftest as parent_conftest

from napalm_base.test.double import BaseTestDouble

from napalm_nxos import nxos


@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = nxos.NXOSDriver
    request.cls.patched_driver = PatchedNXOSDriver
    request.cls.vendor = 'nxos'
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedNXOSDriver(nxos.NXOSDriver):
    """Patched NXOS Driver."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ['device']
        self.device = FakeNXOSDevice()

    def disconnect(self):
        pass

    def is_alive(self):
        return {
            'is_alive': True  # In testing everything works..
        }

    def open(self):
        pass


class FakeNXOSDevice(BaseTestDouble):
    """NXOS device test double."""
    def __init__(self):
        super().__init__()
        full_path = self.find_file('test_get_facts/normal/facts.json')
        self.facts = self.read_json_file(full_path)

    def show(self, command, raw_text=False):
        """Fake show."""
        filename = '{}.json'.format(command.replace(' ', '_'))
        full_path = self.find_file(filename)

        if raw_text:
            result = self.read_txt_file(full_path)
        else:
            result = self.read_json_file(full_path)

        return result

    def config_list(self, command):
        """Fake config_list."""
        pass
