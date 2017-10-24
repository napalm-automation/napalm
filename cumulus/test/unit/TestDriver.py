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

from napalm_cumulus import cumulus
from napalm_base import exceptions
from napalm_base.test.base import TestConfigNetworkDriver


class TestConfigCumulusDriver(unittest.TestCase, TestConfigNetworkDriver):
    """Group of tests that test Configuration related methods."""

    @classmethod
    def setUpClass(cls):
        """Run before starting the tests."""
        hostname = '127.0.0.1'
        username = 'test'
        password = 'test'
        cls.vendor = 'cumulus'

        optional_args = {"sudo_pwd": "test"}
        cls.device = cumulus.CumulusDriver(hostname, username, password, timeout=60,
                                           optional_args=optional_args)
        cls.device.open()

    def test_merge_configuration(self):
        intended_diff = self.read_file('%s/merge_good.diff' % self.vendor)

        self.device.load_merge_candidate(filename='%s/merge_good.conf' % self.vendor)
        self.device.commit_config()

        # Reverting changes
        self.device.load_merge_candidate(filename='%s/revert_merge_good.conf' % self.vendor)
        diff = self.device.compare_config()
        # Removing timestamps
        fixed_diff = diff.split("net add/del commands since the last 'net commit'")[0]
        fixed_diff = fixed_diff.split(" # and how to activate them. For more information"
                                      ", see interfaces(5).")[1].strip()

        print(fixed_diff)
        self.device.commit_config()

        self.assertEqual(fixed_diff, intended_diff)

    def test_merge_configuration_typo_and_rollback(self):
        result = False
        try:
            self.device.load_merge_candidate(filename='%s/merge_typo.conf' % self.vendor)
            self.device.compare_config()
            self.device.commit_config()
            raise Exception("We shouldn't be here")
        except exceptions.MergeConfigException:
            result = self.device.compare_config() == ''
            self.device.discard_config()

        self.assertTrue(result)
