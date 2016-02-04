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

from napalm.iosxr import IOSXRDriver
from base import TestConfigNetworkDriver, TestGettersNetworkDriver


class TestConfigIOSXRDriver(unittest.TestCase, TestConfigNetworkDriver):

    @classmethod
    def setUpClass(cls):
        hostname = '192.168.56.202'
        username = 'vagrant'
        password = 'vagrant'
        cls.vendor = 'iosxr'

        cls.device = IOSXRDriver(hostname, username, password, timeout=60)
        cls.device.open()
        cls.device.load_replace_candidate(filename='%s/initial.conf' % cls.vendor)
        cls.device.commit_config()


class TestGetterIOSXRDriver(unittest.TestCase, TestGettersNetworkDriver):

    @classmethod
    def setUpClass(cls):
        cls.mock = True

        hostname = '192.168.56.202'
        username = 'vagrant'
        password = 'vagrant'
        cls.vendor = 'iosxr'

        cls.device = IOSXRDriver(hostname, username, password, timeout=60)

        if cls.mock:
            cls.device.device = FakeIOSXRDevice()
        else:
            cls.device.open()


class FakeIOSXRDevice:
    @staticmethod
    def read_txt_file(filename):
        with open(filename) as data_file:
            return data_file.read()

    def show_version(self):
        return self.read_txt_file('iosxr/mock_data/show_version.txt')

    def show_interfaces(self):
        return self.read_txt_file('iosxr/mock_data/show_interfaces.txt')

    def show_interface_description(self):
        return self.read_txt_file('iosxr/mock_data/show_interface_description.txt')

    def show_lldp_neighbors(self):
        return self.read_txt_file('iosxr/mock_data/show_lldp_neighbors.txt')

    def make_rpc_call(self, rpc_call):
        rpc_call = \
            rpc_call.replace('<', '_').replace('>', '_').replace('/', '_').replace('\n', '').replace(' ', '')
        return self.read_txt_file('iosxr/mock_data/{}.rpc'.format(rpc_call[0:150]))
