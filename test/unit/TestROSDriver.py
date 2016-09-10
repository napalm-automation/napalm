import datetime
import unittest
import StringIO

from napalm_ros import ros
from napalm_base.test.base import TestConfigNetworkDriver, TestGettersNetworkDriver

def command_to_filename(command):
    return 'ros/mock_data/{}.out'.format(command.lstrip('/').replace(' ', '_').replace('/', '-').replace('"', ''))

def get_mock_data(command):
    filename = command_to_filename(command)
    with open(filename) as f:
        return f.read()

#class TestConfigROSDriver(unittest.TestCase, TestConfigNetworkDriver):
#    @classmethod
#    def setUpClass(cls):
#        """Executed when the class is instantiated."""
#        ip_addr = '192.168.144.222'
#        username = 'admin'
#        password = 'banana12'
#        cls.vendor = 'ros'
#
#        cls.device = ros.ROSDriver(ip_addr, username, password)
#        cls.device.open()


class TestGetterROSDriver(unittest.TestCase, TestGettersNetworkDriver):
    @classmethod
    def setUpClass(cls):
        cls.mock = True

        hostname = '127.0.0.1'
        username = 'vagrant'
        password = 'vagrant'
        cls.vendor = 'ros'

        optional_args = {'snmp_community': 'public',}
        cls.device = ros.ROSDriver(hostname, username, password, timeout=60, optional_args=optional_args)

        if cls.mock:
            cls.device.paramiko_transport = FakeParamikoTransport()
            cls.device.mikoshell = FakeMikoShell()
            cls.device._datetime_offset = datetime.datetime.now() - datetime.datetime.now()
        else:
            cls.device.open()


class FakeParamikoTransport(object):
    def open_session(self):
        return FakeParamikoChannel()


class FakeMikoShell(object):
    @staticmethod
    def command(command, *args, **kwargs):
        return get_mock_data(command).splitlines()


class FakeParamikoChannel(object):
    @staticmethod
    def close():
        pass

    def exec_command(self, command):
        self._exec_command = command

    def makefile(self, *args):
        return StringIO.StringIO(get_mock_data(self._exec_command))

    @staticmethod
    def set_combine_stderr(*args):
        pass

    @staticmethod
    def shutdown(*args):
        pass


if __name__ == '__main__':
    unittest.main()
