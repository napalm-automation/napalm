"""Test fixtures."""
from builtins import super

import StringIO
import datetime

import pytest
from napalm_base.test import conftest as parent_conftest

from napalm_base.test.double import BaseTestDouble

from napalm_ros import ros


@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = ros.ROSDriver
    request.cls.patched_driver = PatchedROSDevice
    request.cls.vendor = 'ros'
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedROSDevice(ros.ROSDriver):
    """ROS device test double."""
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ['paramiko_transport', 'mikoshell', 'api']

    def open(self):
        self.paramiko_transport = FakeParamikoTransport()
        self.mikoshell = FakeMikoShell()
        self._datetime_offset = datetime.datetime.now() - datetime.datetime.now()
        self.api = FakeApi()


class FakeApi(BaseTestDouble):

    def __call__(self, command, **kwargs):
        full_path = self.find_file(self.sanitize_text(command) + '.json')
        return tuple(self.read_json_file(full_path)['data'])

    def close(self):
        pass


class FakeParamikoTransport(BaseTestDouble):
    def open_session(self):
        return FakeParamikoChannel()

    def close(self):
        pass

    def is_active(self):
        return True


class FakeMikoShell(BaseTestDouble):

    def command(self, command, *args, **kwargs):
        full_path = self.find_file(self.sanitize_text(command))
        return self.read_txt_file(full_path).splitlines()

    def exit(self, cmd):
        pass


class FakeParamikoChannel(BaseTestDouble):

    def close(self):
        pass

    def exec_command(self, command):
        self._exec_command = command

    def makefile(self, *args):
        return StringIO.StringIO(self.read_txt_file(self._exec_command))

    @staticmethod
    def set_combine_stderr(*args):
        pass

    @staticmethod
    def shutdown(*args):
        pass
