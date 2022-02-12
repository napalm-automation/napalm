# Copyright 2022 NANOG84 Hackathon contributors
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

from napalm.gnmi import gnmi
from napalm.base.test.base import TestConfigNetworkDriver


class TestConfiggNMIDriver(unittest.TestCase, TestConfigNetworkDriver):
    @classmethod
    def setUpClass(cls):
        hostname = "127.0.0.1"
        username = "admin"
        password = "admin"
        # cls.vendor = "eos" # auto discovered

        # optional_args = {"port": 12443}
        cls.device = gnmi.gNMIDriver(
            hostname, username, password, timeout=60, optional_args={}
        )
        cls.device.open()

        cls.device.load_replace_candidate(filename="./initial.conf")
        cls.device.commit_config()

        interfaces = cls.device.get_interfaces()
        print( interfaces )
        bgp_neighbors = cls.device.get_bgp_neighbors()
        print( bgp_neighbors )
