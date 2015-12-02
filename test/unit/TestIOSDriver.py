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

from napalm.ios import IOSDriver
from base import TestNetworkDriver


class TestIOSDriver(unittest.TestCase, TestNetworkDriver):

    @classmethod
    def setUpClass(cls):
        hostname = '192.168.56.201'
        username = 'gabriele'
        password = 'gabriele'
        cls.vendor = 'ios'

        cls.device = IOSDriver(hostname, username, password, timeout=60)
        cls.device.open()
        cls.device.get_facts()