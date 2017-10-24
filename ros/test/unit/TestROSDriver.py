import unittest

from napalm_ros import ros
from napalm_base.test.base import TestConfigNetworkDriver, TestGettersNetworkDriver  # noqa


class TestConfigROSDriver(unittest.TestCase, TestConfigNetworkDriver):
    @classmethod
    def setUpClass(cls):
        """Executed when the class is instantiated."""
        cls.vendor = 'ros'
        cls.device = ros.ROSDriver(
            '127.0.0.1',
            'vagrant',
            'vagrant',
            timeout=60,
            optional_args={
                'port': 12205,
            }
        )
        cls.device.open()
