"""Test fixtures."""

import pytest
from napalm_base.test import conftest as parent_conftest
from napalm_base.test.double import BaseTestDouble

from napalm_pluribus import PluribusDriver


@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = PluribusDriver
    request.cls.patched_driver = PatchedPluribusDriver
    request.cls.vendor = 'panos'
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedPluribusDriver(PluribusDriver):

    """Patched Pluribus Driver."""
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super(self.__class__, self).__init__(hostname, username, password, timeout, optional_args)
        self.patched_attrs = ['device']
        self.device = FakePluribusDevice()

    def open(self):
        pass

    def close(self):
        pass

    def is_alive(self):
        return({'is_alive': True})


class FakePluribusDevice(BaseTestDouble):

    def __init__(self):
        self.config = FakePluribusConfigHandler(self)

    def execute_show(self, command):
        filename = '{safe_command}.txt'.format(safe_command=self.sanitize_text(command))
        fielpath = self.find_file(filename)
        return self.read_txt_file(fielpath)

    def show(self, command, delim='@$@'):
        if not command.endswith('-show'):
            command += '-show'
        command = command.replace(' ', '-')
        return self.execute_show(command)

    def cli(self, command):
        return self.execute_show(command)


class FakePluribusConfigHandler:

    def __init__(self, device):
        self._device = device

    def _download_running_config(self):
        return self._device.show('running config')
