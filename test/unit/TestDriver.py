# Copyright 2016 Dravetech AB. All rights reserved.
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

"""Tests."""
import unittest

from napalm_panos import panos
from napalm_base.test.base import TestConfigNetworkDriver, TestGettersNetworkDriver
from napalm_base import exceptions

class TestConfigDriver(unittest.TestCase, TestConfigNetworkDriver):
    """Group of tests that test Configuration related methods."""

    @classmethod
    def setUpClass(cls):
        hostname = '1.2.3.4'
        username = 'test'
        password = 'test'
        cls.vendor = 'panos'

        cls.device = panos.PANOSDriver(hostname, username, password, timeout=60)
        cls.device.open()

        cls.device.load_replace_candidate(filename='%s/initial.conf' % cls.vendor)
        cls.device.commit_config()


class TestGetterDriver(unittest.TestCase, TestGettersNetworkDriver):

    @classmethod
    def setUpClass(cls):
        cls.mock = True

        hostname = '1.2.3.4'
        username = 'test'
        password = 'test'
        cls.vendor = 'panos'

        cls.device = panos.PANOSDriver(hostname, username, password, timeout=60)

        if cls.mock:
            cls.device.device = FakePANOSDevice()
        else:
            cls.device.open()


class FakePANOSDevice:

    def __init__(self):
        self.cmd = ''

    @staticmethod
    def read_txt_file(filename):
        """Read a txt file and return its content."""
        with open(filename) as data_file:
            return data_file.read()

    def xml_root(self):
        filename = self.cmd.replace('<', '_').replace('>', '_').replace('/', '_').replace('\n', '').replace(' ', '')
        xml_string = self.read_txt_file(
            'panos/mock_data/{filename}.txt'.format(filename=filename[0:150]))
        return xml_string

    def op(self, cmd=''):
        self.cmd = cmd
        return True
