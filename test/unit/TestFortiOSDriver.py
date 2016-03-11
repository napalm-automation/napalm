# Copyright 2015 Spotify AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

import unittest

from napalm_fortios.fortios import FortiOSDriver
from napalm_base.test.base import TestConfigNetworkDriver, TestGettersNetworkDriver
from pyFG.fortios import FortiConfig


class TestConfigFortiOSDriver(unittest.TestCase, TestConfigNetworkDriver):

    @classmethod
    def setUpClass(cls):
        hostname = '192.168.76.13'
        username = 'dbarroso'
        password = 'this_is_not_a_secure_password'
        cls.vendor = 'fortios'

        cls.device = FortiOSDriver(hostname, username, password, timeout=60)
        cls.device.open()


class TestGetterFortiOSDriver(unittest.TestCase, TestGettersNetworkDriver):

    @classmethod
    def setUpClass(cls):
        cls.mock = True

        hostname = '192.168.56.201'
        username = 'vagrant'
        password = 'vagrant'
        cls.vendor = 'eos'

        cls.device = FortiOSDriver(hostname, username, password, timeout=60)

        if cls.mock:
            cls.device.device = FakeFortiOSDevice()
        else:
            cls.device.open()


class FakeFortiOSDevice:

    @staticmethod
    def read_txt_file(filename):
        with open(filename.lower()) as data_file:
            return data_file.read().splitlines()

    def execute_command(self, command):
        return self.read_txt_file(
            'fortios/mock_data/{}.txt'.format(command.replace(' ', '_').replace('|', '').replace(':', '')))

    def load_config(self, config_block):
        self.running_config = FortiConfig('running')
        self.running_config.parse_config_output(self.read_txt_file('fortios/mock_data/{}.txt'.format(
            config_block.replace(' ', '_'))))
