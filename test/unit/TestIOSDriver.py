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
from napalm import get_network_driver
from base import TestConfigNetworkDriver
from getpass import getpass

class TestIOSDriver(unittest.TestCase, TestConfigNetworkDriver):
    '''
    Tests

    Core file operations:
    load_replace_candidate  Tested
    load_merge_candidate    Tested
    compare_config          Tested 
    commit_config           Tested
    discard_config          Tested
    rollback                Tested

    Get operations:
    get_lldp_neighbors
    get_facts
    get_interfaces
    get_bgp_neighbors
    get_interfaces_counters

    Internal methods:
    _enable_confirm         Tested
    _disable_confirm        Tested
    _gen_rollback_cfg       Tested as part of rollback
    _check_file_exists      Tested

    Misc methods:
    open                        Tested
    close                       Skipped
    normalize_compare_config    Tested (indirectly)
    scp_file                    Tested
    gen_full_path               Tested
    '''

    @classmethod
    def setUpClass(cls):
        username = 'pyclass'
        ip_addr = raw_input("Enter device ip or hostname: ")
        ip_addr = ip_addr.strip()
        password = getpass()
        cls.vendor = 'ios'
        driver = get_network_driver(cls.vendor)
        optional_args = {}
        optional_args['dest_file_system'] = 'flash:'
        optional_args['global_delay_factor'] = .7

        cls.device = driver(ip_addr, username, password, optional_args=optional_args)
        cls.device.open()
        cls.device.get_facts()

    def test_replacing_and_committing_config(self):
        '''Test load_replace_candidate(), compare_config(), and commit_config()'''
        intended_diff = self.read_file('%s/test_replace.diff' % self.vendor)

        # Set initial device configuration
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
        self.device.commit_config()

        # Install new config with a configuration change
        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        self.device.commit_config()

        # The diff should be empty as the configuration has been committed already
        diff = self.device.compare_config()
        diff = diff.strip()
        self.assertEqual(diff, '')

        # Load initial.conf into candidate_config so you can compare
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
        diff = self.device.compare_config()
        self.assertEqual(diff, intended_diff)

    def test_replacing_config_and_diff_and_discard(self):
        '''Handled via other tests'''
        self.assertTrue(True)

    def test_discard(self):
        '''Test discard_config()'''
        # Set initial device configuration
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
        self.device.commit_config()

        # Load new candidate config
        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        commit_diff = self.device.compare_config()
        self.assertNotEqual(commit_diff, '')

        # Discard the config
        self.device.discard_config()
        discard_diff = self.device.compare_config()
        self.assertEqual(discard_diff, '')

    def test_replacing_config_and_rollback(self):
        '''Test rollback'''
        # Set initial device configuration
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
        self.device.commit_config()

        # Load a new config
        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        orig_diff = self.device.compare_config()
        self.device.commit_config()

        # Now we rollback changes
        replace_config_diff = self.device.compare_config()
        self.assertEqual(replace_config_diff, '')
        self.device.rollback()

        # Try to load config again. New diff should be the same as the original diff
        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        last_diff = self.device.compare_config()
        self.assertEqual(orig_diff, last_diff)

        # Discard the config
        self.device.discard_config()

    def test_merge_configuration(self):
        '''Test load_merge_candidate(), compare_config(), and commit_config()'''
        debug = False
        intended_diff = self.read_file('%s/merge_good.diff' % self.vendor)
        if debug:
            print "intended_diff: \n{}".format(intended_diff)

        # Set initial device configuration
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
        self.device.commit_config()

        # Merge change
        self.device.load_merge_candidate(filename='%s/merge_good.conf' % self.vendor)
        self.device.commit_config()

        # Perform diff (verify merge occurred)
        diff = self.device.compare_config()
        if debug:
            print "diff: \n{}".format(diff)

        self.assertEqual(diff, intended_diff)

    def test_confirm(self):
        '''
        Test _disable_confirm() and _enable_confirm()

        _disable_confirm() changes router config so it doesn't prompt for confirmation
        _enable_confirm() reenables this
        '''
        # Set initial device configuration
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
        self.device.commit_config()

        # Verify initial state
        output = self.device.device.send_command('show run | inc file prompt')
        output = output.strip()
        self.assertEqual(output, '')

        # Disable confirmation
        self.device._disable_confirm()
        output = self.device.device.send_command('show run | inc file prompt')
        output = output.strip()
        self.assertEqual(output, 'file prompt quiet')

        # Reenable confirmation
        self.device._enable_confirm()
        output = self.device.device.send_command('show run | inc file prompt')
        output = output.strip()
        self.assertEqual(output, '')

    def test_gen_full_path(self):
        '''Test gen_full_path() method'''
        output = self.device.gen_full_path(self.device.candidate_cfg)
        self.assertEqual(output, 'flash:/candidate_config.txt')

        output = self.device.gen_full_path(self.device.rollback_cfg)
        self.assertEqual(output, 'flash:/rollback_config.txt')

        output = self.device.gen_full_path(self.device.merge_cfg)
        self.assertEqual(output, 'flash:/merge_config.txt')

        output = self.device.gen_full_path(filename='running-config', file_system='system:')
        self.assertEqual(output, 'system:/running-config')

    def test_check_file_exists(self):
        '''Test _check_file_exists() method'''
        # Locate file at flash:/candidate_config.txt
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)

        valid_file = self.device._check_file_exists('flash:/candidate_config.txt')
        self.assertTrue(valid_file)

        invalid_file = self.device._check_file_exists('flash:/bogus_999.txt')
        self.assertFalse(invalid_file)

    def test_replacing_config_with_typo(self):
        '''
        Cisco IOS using 'configure replace' will accept the config with a typo
        command, but will just reject the relevant command.

        Consequently, this test is N/A
        '''
        self.assertTrue(True)

    def test_merge_configuration_typo_and_rollback(self):
        '''
        Cisco IOS using 'configure replace' will accept the config with a typo
        command, but will just reject the relevant command.

        Consequently, this test is N/A
        '''
        self.assertTrue(True)

if __name__ == '__main__':
    print
    print "Starting tests: "
    unittest.main()

