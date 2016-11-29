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
from napalm_base.test.base import TestConfigNetworkDriver


class TestConfigFortiOSDriver(unittest.TestCase, TestConfigNetworkDriver):

    @classmethod
    def setUpClass(cls):
        hostname = '192.168.76.13'
        username = 'dbarroso'
        password = 'this_is_not_a_secure_password'
        cls.vendor = 'fortios'

        cls.device = FortiOSDriver(hostname, username, password, timeout=60)
        cls.device.open()
