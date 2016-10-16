import datetime
import unittest
import StringIO

from napalm_ros import ros
from napalm_base.test.base import TestConfigNetworkDriver, TestGettersNetworkDriver  # noqa


class TestConfigROSDriver(unittest.TestCase, TestConfigNetworkDriver):
    @classmethod
    def setUpClass(cls):
        """Executed when the class is instantiated."""
        ip_addr = '192.168.144.222'
        username = 'admin'
        password = 'banana12'
        cls.vendor = 'ros'

        cls.device = ros.ROSDriver(ip_addr, username, password)
        cls.device.open()
