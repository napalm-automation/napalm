"""Test fixtures."""

from builtins import super

import pytest

from napalm.base.test import conftest as parent_conftest

from napalm.base.test.double import BaseTestDouble

from napalm.eos import eos


@pytest.fixture(scope="class")
def set_device_parameters(request):
    """Set up the class."""

    def fin():
        request.cls.device.close()

    request.addfinalizer(fin)

    request.cls.driver = eos.EOSDriver
    request.cls.patched_driver = PatchedEOSDriver
    request.cls.vendor = "eos"
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedEOSDriver(eos.EOSDriver):
    """Patched EOS Driver."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):

        optional_args = {"transport": "ssh"}

        super().__init__(
            hostname, username, password, timeout, optional_args=optional_args
        )

        self.patched_attrs = ["device"]
        self.device = FakeEOSDevice()

    def _obtain_lock(self, wait_time=None):
        pass

    def close(self):
        pass

    def open(self):
        pass


class FakeEOSDevice(BaseTestDouble):
    """EOS device test double."""

    def __init__(self):
        super(FakeEOSDevice, self).__init__()
        self.connection = object()

    def send_command_expect(self, command, **kwargs):
        return self.send_config_set([command])

    def send_config_set(self, commands, **kwargs):
        return self.run_commands(commands)
