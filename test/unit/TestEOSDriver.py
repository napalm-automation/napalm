# Copyright 2014 Spotify AB. All rights reserved.
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

from drivers.eos import EOSDriver
from objects.facts import Facts
from objects.interface import Interface
from objects.bgp import BGPInstance

import config

class TestEOSDriver(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.device = EOSDriver(config.hostname, config.username, config.password)
        cls.device.open()

        with open(config.config_file_1, 'r') as f:
            cls.config_1 = f.readlines()

    @classmethod
    def tearDownClass(cls):
        cls.device.close()

    def test_loading_config(self):
        self.device.load_candidate_config(filename=config.config_file_1)
        self.device.commit_config()
        diff = self.device.compare_config()
        self.assertEqual(len(diff), 0)

    def test_loading_modified_config_and_diff(self):
        self.device.load_candidate_config(filename=config.config_file_2)
        diff = self.device.compare_config()
        self.assertGreater(len(diff), 0)

    def test_loading_modified_config_replace_config_and_rollback(self):
        self.device.load_candidate_config(filename=config.config_file_2)
        orig_diff = self.device.compare_config()
        self.device.commit_config()
        replace_config_diff = self.device.compare_config()
        self.device.rollback()
        last_diff = self.device.compare_config()

        result = (orig_diff == last_diff) and (len(replace_config_diff) == 0)

        self.assertTrue(result)

    def test_get_facts(self):
        facts = self.device.get_facts()
        self.assertIsInstance(facts, Facts)

    def test_get_bgp_neighbors(self):
        bgp_table = self.device.get_bgp_neighbors()
        self.assertIsInstance(bgp_table[0], BGPInstance)

    def test_get_interface(self):
        interface = self.device.get_interface('Ethernet1')
        self.assertIsInstance(interface, Interface)



