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

"""Tests for IOSDriver."""

import unittest
from napalm.ios import ios
from napalm.base.utils import py23_compat
from napalm.base.test.base import TestConfigNetworkDriver, TestGettersNetworkDriver
import re


class TestConfigIOSDriver(unittest.TestCase, TestConfigNetworkDriver):
    """Configuration Tests for IOSDriver.

    Core file operations:
    load_replace_candidate  Tested
    load_merge_candidate    Tested
    compare_config          Tested
    commit_config           Tested
    discard_config          Tested
    rollback                Tested

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
    """

    @classmethod
    def setUpClass(cls):
        """Executed when the class is instantiated."""
        ip_addr = "127.0.0.1"
        username = "vagrant"
        password = "vagrant"
        cls.vendor = "ios"
        optional_args = {"port": 12204, "dest_file_system": "bootflash:"}

        cls.device = ios.IOSDriver(
            ip_addr, username, password, optional_args=optional_args
        )
        cls.device.open()

        # Setup initial state
        cls.device.load_replace_candidate(filename="%s/initial.conf" % cls.vendor)
        cls.device.commit_config()

    def test_ios_only_confirm(self):
        """Test _disable_confirm() and _enable_confirm().

        _disable_confirm() changes router config so it doesn't prompt for confirmation
        _enable_confirm() reenables this
        """
        # Set initial device configuration
        self.device.load_replace_candidate(filename="%s/initial.conf" % self.vendor)
        self.device.commit_config()

        # Verify initial state
        output = self.device.device.send_command("show run | inc file prompt")
        output = output.strip()
        self.assertEqual(output, "")

        # Disable confirmation
        self.device._disable_confirm()
        output = self.device.device.send_command("show run | inc file prompt")
        output = output.strip()
        self.assertEqual(output, "file prompt quiet")

        # Reenable confirmation
        self.device._enable_confirm()
        output = self.device.device.send_command("show run | inc file prompt")
        output = output.strip()
        self.assertEqual(output, "")

    def test_ios_only_gen_full_path(self):
        """Test gen_full_path() method."""
        output = self.device._gen_full_path(self.device.candidate_cfg)
        self.assertEqual(output, self.device.dest_file_system + "/candidate_config.txt")

        output = self.device._gen_full_path(self.device.rollback_cfg)
        self.assertEqual(output, self.device.dest_file_system + "/rollback_config.txt")

        output = self.device._gen_full_path(self.device.merge_cfg)
        self.assertEqual(output, self.device.dest_file_system + "/merge_config.txt")

        output = self.device._gen_full_path(
            filename="running-config", file_system="system:"
        )
        self.assertEqual(output, "system:/running-config")

    def test_ios_only_check_file_exists(self):
        """Test _check_file_exists() method."""
        self.device.load_replace_candidate(filename="%s/initial.conf" % self.vendor)
        valid_file = self.device._check_file_exists(
            self.device.dest_file_system + "/candidate_config.txt"
        )
        self.assertTrue(valid_file)
        invalid_file = self.device._check_file_exists(
            self.device.dest_file_system + "/bogus_999.txt"
        )
        self.assertFalse(invalid_file)


class TestGetterIOSDriver(unittest.TestCase, TestGettersNetworkDriver):
    """Getters Tests for IOSDriver.

    Get operations:
    get_lldp_neighbors
    get_facts
    get_interfaces
    get_bgp_neighbors
    get_interfaces_counters
    """

    @classmethod
    def setUpClass(cls):
        """Executed when the class is instantiated."""
        cls.mock = True

        username = "vagrant"
        ip_addr = "192.168.0.234"
        password = "vagrant"
        cls.vendor = "ios"
        optional_args = {}
        optional_args["dest_file_system"] = "flash:"

        cls.device = ios.IOSDriver(
            ip_addr, username, password, optional_args=optional_args
        )

        if cls.mock:
            cls.device.device = FakeIOSDevice()
        else:
            cls.device.open()

    def test_ios_only_bgp_time_conversion(self):
        """Verify time conversion static method."""
        test_cases = {
            "1w0d": 604800,
            "00:14:23": 863,
            "00:13:40": 820,
            "00:00:21": 21,
            "00:00:13": 13,
            "00:00:49": 49,
            "1d11h": 126000,
            "1d17h": 147600,
            "8w5d": 5270400,
            "1y28w": 48470400,
            "never": -1,
        }

        for bgp_time, result in test_cases.items():
            self.assertEqual(self.device.bgp_time_conversion(bgp_time), result)


class FakeIOSDevice:
    """Class to fake a IOS Device."""

    @staticmethod
    def read_txt_file(filename):
        """Read a txt file and return its content."""
        with open(filename) as data_file:
            return data_file.read()

    def send_command_expect(self, command, **kwargs):
        """Fake execute a command in the device by just returning the content of a file."""
        cmd = re.sub(r"[\[\]\*\^\+\s\|]", "_", command)
        output = self.read_txt_file("ios/mock_data/{}.txt".format(cmd))
        return py23_compat.text_type(output)

    def send_command(self, command, **kwargs):
        """Fake execute a command in the device by just returning the content of a file."""
        return self.send_command_expect(command)


if __name__ == "__main__":
    unittest.main()
