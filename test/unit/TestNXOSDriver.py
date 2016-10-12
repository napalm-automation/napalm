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

# import stdlib
import re
import os
import unittest

# import NAPALM Base
# from napalm_base.test.base import TestConfigNetworkDriver
from napalm_base.test.base import TestGettersNetworkDriver

# import napalm-nxos
from napalm_nxos import NXOSDriver

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


class TestNXOSDriver_bgp_neighbors(unittest.TestCase):
    """Verify the mapping of Nexus data to NAPALM's expected output."""

    def setUp(self):
        self.driver = NXOSDriver('host', 'user', 'pass', timeout=60)
        self.fake = FakeNXOSDevice()
        self.driver.device = self.fake

    def set_bgp_return_data(self, mock_file_name):
        cmd_results = {
            'show bgp sessions vrf all': mock_file_name
        }
        self.fake.set_mock_file_overrides(cmd_results)

    def test_get_bgp_neighbors_mapping(self):
        """Validate the mapping of the data to the output structure."""
        self.set_bgp_return_data('show_bgp_sessions_vrf_all.json')

        actual_data = self.driver.get_bgp_neighbors()
        expected_data = {
            'default': {
                'router_id': u'10.10.10.10',
                'peers': {
                    u'40.40.40.40': {
                        'address_family': {
                            'ipv4': {
                                'accepted_prefixes': -1,
                                'received_prefixes': -1,
                                'sent_prefixes': -1}},
                        'description': u'',
                        'is_enabled': True,
                        'is_up': True,
                        'local_as': 11111,
                        'remote_as': 11111,
                        'remote_id': u'40.40.40.40',
                        'uptime': -1}}
            },  # End default
            'VRF_1': {
                'router_id': u'10.10.10.10',
                'peers': {
                    u'20.20.20.20': {
                        'address_family': {
                            'ipv4': {'accepted_prefixes': -1,
                                     'received_prefixes': -1,
                                     'sent_prefixes': -1}},
                        'description': u'',
                        'is_enabled': True,
                        'is_up': True,
                        'local_as': 11111,
                        'remote_as': 22222,
                        'remote_id': u'20.20.20.20',
                        'uptime': -1},
                    u'30.30.30.30': {
                        'address_family': {
                            'ipv4': {'accepted_prefixes': -1,
                                     'received_prefixes': -1,
                                     'sent_prefixes': -1}},
                        'description': u'',
                        'is_enabled': True,
                        'is_up': True,
                        'local_as': 11111,
                        'remote_as': 22222,
                        'remote_id': u'30.30.30.30',
                        'uptime': -1}}
            }  # End VRF_1
        }
        self.maxDiff = None
        self.assertEqual(actual_data, expected_data)

    def test_get_bgp_neighbors_with_no_data_works(self):
        # TODO: verify that Nexus devices with no BGP set up return
        # data as given in the sample file.
        self.set_bgp_return_data('show_bgp_sessions_with_no_bgp_setup.json')
        self.assertEqual(self.driver.get_bgp_neighbors(), {})

    def test_bad_returned_data_format(self):
        # TODO: discuss w/ team, verify that this is the expected
        # behaviour.  I had thought that bad returned data would throw
        # an exception, rather than silently swallowing the error.
        self.set_bgp_return_data('show_bgp_sessions_bad_return.json')
        self.assertEqual(self.driver.get_bgp_neighbors(), {})

    def test_single_neighbor_works(self):
        # TODO: discuss w/ team, verify that this is the expected
        # data format and behaviour.
        self.set_bgp_return_data('show_bgp_sessions_single_neighbor.json')
        expected_data = {
            'VRF_1': {
                'router_id': u'10.10.10.10',
                'peers': {
                    u'20.20.20.20': {
                        'address_family': {
                            'ipv4': {'accepted_prefixes': -1,
                                     'received_prefixes': -1,
                                     'sent_prefixes': -1}},
                        'description': u'',
                        'is_enabled': True,
                        'is_up': True,
                        'local_as': 11111,
                        'remote_as': 22222,
                        'remote_id': u'20.20.20.20',
                        'uptime': -1}
                    }
                }
            }
        self.assertEqual(self.driver.get_bgp_neighbors(), expected_data)


class TestNXOSDriver_get_interfaces_ip(unittest.TestCase):
    """Additional test cases for verification."""

    def setUp(self):
        self.driver = NXOSDriver('host', 'user', 'pass', timeout=60)
        self.fake = FakeNXOSDevice()
        self.driver.device = self.fake
        self.baseline_command_results = {
            'show ip interface': 'show_ip_interface.json',
            'show ipv6 interface': 'show_ipv6_interface.json'
        }
        self.fake.set_mock_file_overrides(self.baseline_command_results)

    def set_return_data(self, command, filename):
        cmd_results = self.baseline_command_results
        cmd_results[command] = filename
        self.fake.set_mock_file_overrides(cmd_results)

    def test_baseline_get_interfaces_ip(self):
        """Validate the mapping of the data to the output structure."""
        actual_data = self.driver.get_interfaces_ip()
        expected_data = {
            u'Vlan900': {
                u'ipv4': {u'192.168.0.1': {'prefix_length': 24}}
            },
            u'Vlan777': {
                u'ipv6': {u'2001:db8:85a3:8d3:1319:8a2e:370:7349': {u'prefix_length': 64}}
            }}
        self.assertEqual(actual_data, expected_data)

    def test_get_interfaces_ip_multiple_interfaces(self):
        self.set_return_data('show ip interface', 'show_ip_interface_multiple_ips.json')
        actual_data = self.driver.get_interfaces_ip()
        expected_data = {
            u'Vlan123': {
                u'ipv4': {u'10.1.2.4': {'prefix_length': 31}}
            },
            u'Ethernet2/1': {
                u'ipv4': {u'10.1.2.0': {'prefix_length': 31}}
            },
            u'Vlan777': {
                u'ipv6': {u'2001:db8:85a3:8d3:1319:8a2e:370:7349': {u'prefix_length': 64}}
            }}
        self.assertEqual(actual_data, expected_data)

    def test_get_interfaces_ip_no_ipv6(self):
        self.set_return_data('show ipv6 interface', 'show_ipv6_interface_no_interfaces.json')
        actual_data = self.driver.get_interfaces_ip()
        expected_data = {
            u'Vlan900': {
                u'ipv4': {u'192.168.0.1': {'prefix_length': 24}}
            }
        }
        self.assertEqual(actual_data, expected_data)


class FakeNXOSDevice(object):

    def __init__(self):
        self.data_overrides = {}

    @staticmethod
    def read_txt_file(filename):
        with open(filename) as data_file:
            return data_file.read()

    def set_mock_file_overrides(self, command_hash):
        """Set the returned data for different scenarios."""
        self.data_overrides = command_hash

    def get_filename(self, command, fmat='xml', text=False):
        if command in self.data_overrides:
            return self.data_overrides[command]

        # Build file from command.
        extension = fmat
        if text:
            extension = 'txt'
        filename = re.sub(r'[\[\]\*\^\+\s\|\/]', '_', command)
        mock_file = '{filename}.{extension}'.format(
            filename=filename[0:150],
            extension=extension
        )
        return mock_file

    def show(self, command, fmat='xml', text=False):
        curr_dir = os.path.dirname(os.path.abspath(__file__))
        mock_file = self.get_filename(command, fmat, text)
        mock_file = os.path.join(curr_dir, 'nxos', 'mock_data', mock_file)
        mock_data = self.read_txt_file(mock_file)
        if text:
            mock_data = {
                'ins_api': {
                    'outputs': {
                        'output': {
                            'msg': 'Success',
                            'code': 200,
                            'input': command,
                            'body': mock_data
                        }
                    }
                }
            }
        return (self, str(mock_data))
