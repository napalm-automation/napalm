# Copyright 2016 CloudFlare, Inc. All rights reserved.
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

from napalm_pluribus import pluribus
from napalm_base.test.base import TestConfigNetworkDriver, TestGettersNetworkDriver
import re


class TestConfigPluribusDriver(unittest.TestCase, TestConfigNetworkDriver):

    @classmethod
    def setUpClass(cls):
        hostname = '172.17.17.1'
        username = 'mircea'
        password = 'password'
        cls.vendor = 'pluribus'

        cls.device = pluribus.PluribusDriver(hostname, username, password, timeout=60)
        cls.device.open()


class TestGetterPluribusDriver(unittest.TestCase, TestGettersNetworkDriver):

    @classmethod
    def setUpClass(cls):
        cls.mock = True

        hostname = '172.17.17.1'
        username = 'mircea'
        password = 'password'
        cls.vendor = 'pluribus'

        cls.device = pluribus.PluribusDriver(hostname, username, password, timeout=60)

        if cls.mock:
            cls.device.device = FakePluribusDevice()
        else:
            cls.device.open()


class FakePluribusConfig:


    def __init__(self, device):
        self._device = device


    def _download_running_config(self):
        return self._device.show('running config')


class FakePluribusDevice:

    def __init__(self):
        self.config = FakePluribusConfig(self)


    @staticmethod
    def read_txt_file(filename):
        with open(filename) as data_file:
            return data_file.read()


    def execute_show(self, command):

        cmd = re.sub(r'[\[\]\*\^\+\s\|]', '_', command)
        return self.read_txt_file('pluribus/mock_data/{}.txt'.format(cmd))

    def show(self, command, delim='@$@'):
        if not command.endswith('-show'):
            command += '-show'
        command = command.replace(' ', '-')

        return self.execute_show(command)

    def cli(self, command):
        return self.execute_show(command)
