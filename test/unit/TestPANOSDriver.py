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
from napalm_base.test.base import TestConfigNetworkDriver


class TestConfigPANOSDriver(unittest.TestCase, TestConfigNetworkDriver):
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

    def test_custom_replacing_config_and_diff_and_discard(self):
        intended_diff = self.read_file('%s/new_good.diff' % self.vendor)

        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        commit_diff = self.device.compare_config()

        self.device.discard_config()
        discard_diff = self.device.compare_config()
        self.device.discard_config()

        result = (commit_diff.strip() == intended_diff.strip()) and (discard_diff == '')
        self.assertTrue(result)

    def test_custom_merge_configuration(self):
        intended_diff = self.read_file('%s/merge_good.diff' % self.vendor)

        xpath = '/config/devices/entry[@name="localhost.localdomain"]/network/vlan'
        mode = 'replace'
        filename = '%s/merge_good.xml' % self.vendor
        self.device.load_merge_candidate(filename=filename, from_xpath=xpath,
                                         to_xpath=xpath, mode=mode)
        self.device.commit_config()

        # Reverting changes
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
        diff = self.device.compare_config()

        self.device.commit_config()

        result = (diff.strip() == intended_diff.strip())
        self.assertTrue(result)
