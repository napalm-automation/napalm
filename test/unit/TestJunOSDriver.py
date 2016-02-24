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
        hostname = '127.0.0.1'
        username = 'vagrant'
        password = 'vagrant123'
        cls.vendor = 'junos'

        optional_args = {'port': 12203,}
        cls.device = JunOSDriver(hostname, username, password, timeout=60, optional_args=optional_args)
        cls.device.open()


class TestGetterJunOSDriver(unittest.TestCase, TestGettersNetworkDriver):

    @classmethod
    def setUpClass(cls):
        cls.mock = True

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
        self.ON_JUNOS = True # necessary for fake devices
        self.facts = {
            'domain': None,
            'hostname': 'vsrx',
            'ifd_style': 'CLASSIC',
            '2RE': False,
            'serialnumber': 'beb914a9cca3',
            'fqdn': 'vsrx',
            'virtual': True,
            'switch_style': 'NONE',
            'version': '12.1X47-D20.7',
            'HOME': '/cf/var/home/vagrant',
            'srx_cluster': False,
            'model': 'FIREFLY-PERIMETER',
            'RE0': {
                'status': 'Testing',
                'last_reboot_reason': 'Router rebooted after a normal shutdown.',
                'model': 'FIREFLY-PERIMETER RE',
                'up_time': '1 hour, 13 minutes, 37 seconds'
            },
            'vc_capable': False,
            'personality': 'SRX_BRANCH'
        }
        self.rpc = FakeRPCObject(self.facts)

    @staticmethod
    def read_txt_file(filename):
        with open(filename) as data_file:
            return data_file.read()

    def cli(self, command = ''):
        return self.read_txt_file(
            'junos/mock_data/{parsed_command}_{version}_{fqdn}.txt'.format(
                parsed_command = command.replace(' ', '_'),
                version=self.facts.get('version'),
                fqdn=self.facts.get('fqdn')
            )
        )
        # no platform-related tests needed here


class FakeRPCObject:

    def __init__(self, facts):
        self._facts = facts

    @staticmethod
    def read_txt_file(filename):
        with open(filename) as data_file:
            return data_file.read()

    def __getattr__(self, item):
        self.item = item
        return self

    def response(self, **rpc_args):
        instance = rpc_args.pop('instance', '')

        xml_string = self.read_txt_file(
            'junos/mock_data/{}{}_{}_{}.xml'.format(
                self.item,
                instance,
                self._facts.get('version'),
                self._facts.get('fqdn')
            )
        )
        return lxml.etree.fromstring(xml_string)

    def get_config(self, get_cmd = '', options = {}):

        # get_cmd is an XML tree that requests a specific part of the config
        # E.g.: <configuration><protocols><bgp><group/></bgp></protocols></configuration>

        get_cmd_str = lxml.etree.tostring(get_cmd)
        filename = get_cmd_str.replace('<', '_').replace('>', '_').replace('/', '_').replace('\n', '').replace(' ', '')

        xml_string = self.read_txt_file(
            'junos/mock_data/{filename}_{version}_{fqdn}.xml'.format(
                filename=filename[0:150],
                version=self._facts.get('version'),
                fqdn=self._facts.get('fqdn')
            )
        )
        return lxml.etree.fromstring(xml_string)

    __call__ = response
