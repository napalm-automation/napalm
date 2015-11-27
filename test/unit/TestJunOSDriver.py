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

from napalm.junos import JunOSDriver
from base import TestConfigNetworkDriver, TestGettersNetworkDriver

import lxml


class TestConfigJunOSDriver(unittest.TestCase, TestConfigNetworkDriver):

    @classmethod
    def setUpClass(cls):
        hostname = '192.168.56.203'
        username = 'vagrant'
        password = 'vagrant123'
        cls.vendor = 'junos'

        cls.device = JunOSDriver(hostname, username, password, timeout=60)
        cls.device.open()


class TestGetterJunOSDriver(unittest.TestCase, TestGettersNetworkDriver):

    @classmethod
    def setUpClass(cls):
        cls.mock = False

        hostname = '192.168.56.203'
        username = 'vagrant'
        password = 'vagrant123'
        cls.vendor = 'junos'

        cls.device = JunOSDriver(hostname, username, password, timeout=60)

        if cls.mock:
            cls.device.device = FakeJunOSDevice()
        else:
            cls.device.open()


class FakeJunOSDevice:
    def __init__(self):
        self.rpc = FakeRPCObject()
        self.facts = {'domain': None, 'hostname': 'vsrx', 'ifd_style': 'CLASSIC', '2RE': False, 'serialnumber': 'beb914a9cca3', 'fqdn': 'vsrx', 'virtual': True, 'switch_style': 'NONE', 'version': '12.1X47-D20.7', 'HOME': '/cf/var/home/vagrant', 'srx_cluster': False, 'model': 'FIREFLY-PERIMETER', 'RE0': {'status': 'Testing', 'last_reboot_reason': 'Router rebooted after a normal shutdown.', 'model': 'FIREFLY-PERIMETER RE', 'up_time': '1 hour, 13 minutes, 37 seconds'}, 'vc_capable': False, 'personality': 'SRX_BRANCH'}


class FakeRPCObject:

    def __init__(self):
        pass

    @staticmethod
    def read_txt_file(filename):
        with open(filename) as data_file:
            return data_file.read()

    def __getattr__(self, item):
        self.xml_string = self.read_txt_file('junos/mock_data/{}.txt'.format(item))
        return self

    def response(self, **rpc_args):
        return lxml.etree.fromstring(self.xml_string)

    __call__ = response
