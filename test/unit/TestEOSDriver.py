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

from napalm import eos
from base import TestConfigNetworkDriver, TestGettersNetworkDriver
import json
import re


class TestConfigEOSDriver(unittest.TestCase, TestConfigNetworkDriver):

    @classmethod
    def setUpClass(cls):
        hostname = '127.0.0.1'
        username = 'vagrant'
        password = 'vagrant'
        cls.vendor = 'eos'

        optional_args = {'port': 12443,}
        cls.device = eos.EOSDriver(hostname, username, password, timeout=60, optional_args=optional_args)
        cls.device.open()

        cls.device.load_replace_candidate(filename='%s/initial.conf' % cls.vendor)
        cls.device.commit_config()


class TestGetterEOSDriver(unittest.TestCase, TestGettersNetworkDriver):

    @classmethod
    def setUpClass(cls):
        cls.mock = True

        hostname = '127.0.0.1'
        username = 'vagrant'
        password = 'vagrant'
        cls.vendor = 'eos'

        optional_args = {'port': 12443,}
        cls.device = eos.EOSDriver(hostname, username, password, timeout=60, optional_args=optional_args)

        if cls.mock:
            cls.device.device = FakeEOSDevice()
        else:
            cls.device.open()


class FakeEOSDevice:

    @staticmethod
    def read_json_file(filename):
        with open(filename) as data_file:
            return json.load(data_file)

    @staticmethod
    def read_txt_file(filename):
        with open(filename) as data_file:
            return data_file.read()

    def run_commands(self, command_list, encoding='json'):
        result = list()

        for command in command_list:
            if encoding == 'json':
                result.append(self.read_json_file('eos/mock_data/{}.json'.format(command.replace(' ', '_'))))
            else:
                cmd = re.sub(r'[^a-zA-Z0-9]+', '_', command)
                result.append({'output': self.read_txt_file('eos/mock_data/{}.txt'.format(cmd))})

        return result
