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

from napalm_nxos.nxos import NXOSDriver
from napalm_base.test.base import TestConfigNetworkDriver, TestGettersNetworkDriver
import re

# class TestConfigNXOSDriver(unittest.TestCase, TestConfigNetworkDriver):

#     @classmethod
#     def setUpClass(cls):
#         hostname = 'n9k1'
#         username = 'user'
#         password = 'pass'
#         cls.vendor = 'nxos'

#         cls.device = NXOSDriver(hostname, username, password, timeout=60)
#         cls.device.open()

#     def test_replacing_config_with_typo(self)


class TestGetterNXOSDriver(unittest.TestCase, TestGettersNetworkDriver):

    @classmethod
    def setUpClass(cls):
        cls.mock = True

        hostname = '172.17.17.1'
        username = 'mircea'
        password = 'mircea'
        cls.vendor = 'nxos'

        cls.device = NXOSDriver(hostname, username, password, timeout=60)

        if cls.mock:
            cls.device.device = FakeNXOSDevice()
        else:
            cls.device.open()

    @staticmethod
    def read_txt_file(filename):
        with open(filename) as data_file:
            return data_file.read()

class FakeNXOSDevice(object):

    def __init__(self):
        pass

    @staticmethod
    def read_txt_file(filename):
        with open(filename) as data_file:
            return data_file.read()

    def show(self, command, fmat = 'xml', text = False):

        extension = fmat
        if text:
            extension = 'txt'

        filename = re.sub(r'[\[\]\*\^\+\s\|\/]', '_', command)
        mock_file = 'nxos/mock_data/{filename}.{extension}'.format(
            filename  = filename[0:150],
            extension = extension
        )
        mock_data = self.read_txt_file(mock_file)
        if text:
            mock_data = {
                'ins_api':{
                    'outputs': {
                        'output': {
                            'msg'   : 'Success',
                            'code'  : 200,
                            'input' : command,
                            'body'  : mock_data
                        }
                    }
                }
            }
        return (self, str(mock_data))
