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

from napalm import pluribus
from base import TestConfigNetworkDriver, TestGettersNetworkDriver
import re


class TestConfigPluribusriver(unittest.TestCase, TestConfigNetworkDriver):

    @classmethod
    def setUpClass(cls):
        hostname = '172.17.17.1'
        username = 'mircea'
        password = 'password'
        cls.vendor = 'pluribus'

        cls.device = pluribus.PluribusDriver(hostname, username, password, timeout=60)
        cls.device.open()


class TestGetterPluribusriver(unittest.TestCase, TestGettersNetworkDriver):

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


class FakePluribusDevice:

    @staticmethod
    def read_txt_file(filename):
        with open(filename) as data_file:
            return data_file.read()

    def execute_show(self, command):

        cmd = re.sub(r'[\[\]\*\^\+\s\|]', '_', command)
        return self.read_txt_file('pluribus/mock_data/{}.txt'.format(cmd))
