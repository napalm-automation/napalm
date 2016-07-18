import datetime
import json
import re
import unittest

from napalm_ros import ros
from napalm_base.test.base import TestGettersNetworkDriver
from yandc import ROS_Client


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
            cls.device.device = FakeROSDevice()
        else:
            cls.device.open()


class FakeROSDevice(ROS_Client):
    def __init__(self):
        self._datetime_offset = datetime.datetime.now() - datetime.datetime.now()
        self.ssh_client = FakeSSHClient()

    @staticmethod
    def read_cmd_out(filename):
        with open(filename) as f:
            return f.read().splitlines()

    @staticmethod
    def cli_command(command, *args, **kwargs):
        filename = 'ros/mock_data/{}.out'.format(command.lstrip('/').replace(' ', '_').replace('/', '-').replace('"', ''))
        with open(filename) as f:
            output = f.read().splitlines()
            return output


class FakeSSHClient(object):
    @staticmethod
    def exec_command(command):
        return FakeROSDevice.cli_command(command)


if __name__ == '__main__':
    unittest.main()
