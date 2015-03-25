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

from napalm import exceptions

class TestNetworkDriver:

    @classmethod
    def tearDownClass(cls):
        cls.device.close()

    @staticmethod
    def read_file(filename):
        with open(filename, 'r') as f:
            return f.read()

    def test_loading_and_committing_config(self):
        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        self.device.commit_config()

        # The diff should be empty as the configuration has been committed already
        diff = self.device.compare_config()

        # Reverting changes
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
        self.device.commit_config()

        self.assertEqual(len(diff), 0)

    def test_loading_config_with_typo(self):
        self.device.load_replace_candidate(filename='%s/new_typo.conf' % self.vendor)
        self.assertRaises(exceptions.ReplaceConfigException, self.device.commit_config)

    def test_loading_modified_config_and_diff_and_discard(self):
        intended_diff = self.read_file('%s/new_good.diff' % self.vendor)

        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        commit_diff = self.device.compare_config()
        self.device.discard_config()
        discard_diff = self.device.compare_config()

        result = (commit_diff == intended_diff) and (discard_diff == '')
        self.assertTrue(result)

    def test_loading_modified_config_replace_config_and_rollback(self):
        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        orig_diff = self.device.compare_config()
        self.device.commit_config()
        replace_config_diff = self.device.compare_config()
        self.device.rollback()
        last_diff = self.device.compare_config()

        result = (orig_diff == last_diff) and ( len(replace_config_diff) == 0 )

        self.assertTrue(result)

    def test_merge_configuration(self):
        intended_diff = self.read_file('%s/merge_good.diff' % self.vendor)

        self.device.load_merge_candidate(filename='%s/merge_good.conf' % self.vendor)
        self.device.commit_config()

        # Reverting changes
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
        diff = self.device.compare_config()
        self.device.commit_config()

        self.assertEqual(diff, intended_diff)

    def test_merge_configuration_typo_and_rollback(self):
        self.device.load_merge_candidate(filename='%s/merge_typo.conf' % self.vendor)
        diff = self.device.compare_config()

        try:
            self.device.commit_config()
            result = False
        except exceptions.MergeConfigException:
            # We load the original config as candidate. If the commit failed cleanly the compare_config should be empty
            self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
            result = (diff > 0) and ( self.device.compare_config() == '')

        self.assertTrue(result)
