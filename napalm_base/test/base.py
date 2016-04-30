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

from __future__ import print_function

from napalm_base import exceptions
import difflib
import models


class TestConfigNetworkDriver:

    @classmethod
    def tearDownClass(cls):
        cls.device.load_replace_candidate(filename='%s/initial.conf' % cls.vendor)
        cls.device.commit_config()
        cls.device.close()

    @staticmethod
    def read_file(filename):
        with open(filename, 'r') as f:
            return f.read().strip()

    @staticmethod
    def print_diff_strings(orig, new):
        for line in difflib.context_diff(orig.splitlines(), new.splitlines()):
            print(line)

    def test_replacing_and_committing_config(self):
        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        self.device.commit_config()

        # The diff should be empty as the configuration has been committed already
        diff = self.device.compare_config()

        # Reverting changes
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
        self.device.commit_config()

        self.assertEqual(len(diff), 0)

    def test_replacing_config_with_typo(self):
        result = False
        try:
            self.device.load_replace_candidate(filename='%s/new_typo.conf' % self.vendor)
            self.device.commit_config()
        except exceptions.ReplaceConfigException:
            self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
            diff = self.device.compare_config()
            self.device.discard_config()
            result = True and len(diff) == 0
        self.assertTrue(result)

    def test_replacing_config_and_diff_and_discard(self):
        intended_diff = self.read_file('%s/new_good.diff' % self.vendor)

        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        commit_diff = self.device.compare_config()

        print(commit_diff)

        self.device.discard_config()
        discard_diff = self.device.compare_config()
        self.device.discard_config()

        result = (commit_diff == intended_diff) and (discard_diff == '')
        self.assertTrue(result)

    def test_replacing_config_and_rollback(self):
        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        orig_diff = self.device.compare_config()
        self.device.commit_config()

        # Now we rollback changes
        replace_config_diff = self.device.compare_config()
        self.device.rollback()

        # We try to load again the config. If the rollback was successful new diff should be like the first one
        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        last_diff = self.device.compare_config()
        self.device.discard_config()

        result = (orig_diff == last_diff) and (len(replace_config_diff) == 0)

        self.assertTrue(result)

    def test_merge_configuration(self):
        intended_diff = self.read_file('%s/merge_good.diff' % self.vendor)

        self.device.load_merge_candidate(filename='%s/merge_good.conf' % self.vendor)
        self.device.commit_config()

        # Reverting changes
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
        diff = self.device.compare_config()

        print(diff)

        self.device.commit_config()

        self.assertEqual(diff, intended_diff)

    def test_merge_configuration_typo_and_rollback(self):
        result = False
        try:
            self.device.load_merge_candidate(filename='%s/merge_typo.conf' % self.vendor)
            diff = self.device.compare_config()
            self.device.commit_config()
            raise Exception("We shouldn't be here")
        except exceptions.MergeConfigException:
            # We load the original config as candidate. If the commit failed cleanly the compare_config should be empty
            self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
            result = self.device.compare_config() == ''
            self.device.discard_config()

        self.assertTrue(result)

    def test_load_template(self):
        """Test load_template method."""
        self.device.load_template('set_hostname', hostname='my-hostname')
        diff = self.device.compare_config()
        self.device.discard_config()
        self.assertTrue(diff is not '')

class TestGettersNetworkDriver:

    @staticmethod
    def _test_model(model, data):
        same_keys = set(model.keys()) == set(data.keys())

        if not same_keys:
            print("model_keys: {}\ndata_keys: {}".format(sorted(model.keys()), sorted(data.keys())))

        correct_class = True
        for key, instance_class in model.iteritems():
            same_class = isinstance(data[key], instance_class)
            correct_class = correct_class and same_class
            if not same_class:
                print("key: {}\nmodel_class: {}\ndata_class: {}".format(
                                                            key, instance_class, data[key].__class__))

        return correct_class and same_keys

    def test_get_facts(self):
        facts = self.device.get_facts()
        result = self._test_model(models.facts, facts)
        self.assertTrue(result)

    def test_get_interfaces(self):
        get_interfaces = self.device.get_interfaces()
        result = len(get_interfaces) > 0

        for interface, interface_data in get_interfaces.iteritems():
            result = result and self._test_model(models.interface, interface_data)

        self.assertTrue(result)

    def test_get_lldp_neighbors(self):
        get_lldp_neighbors = self.device.get_lldp_neighbors()
        result = len(get_lldp_neighbors) > 0

        for interface, neighbor_list in get_lldp_neighbors.iteritems():
            for neighbor in neighbor_list:
                result = result and self._test_model(models.lldp_neighbors, neighbor)

        self.assertTrue(result)

    def test_get_interfaces_counters(self):
        get_interfaces_counters = self.device.get_interfaces_counters()
        result = len(self.device.get_interfaces_counters()) > 0

        for interface, interface_data in get_interfaces_counters.iteritems():
            result = result and self._test_model(models.interface_counters, interface_data)

        self.assertTrue(result)

    def test_get_environment(self):
        environment = self.device.get_environment()
        result = len(environment) > 0

        for fan, fan_data in environment['fans'].iteritems():
            result = result and self._test_model(models.fan, fan_data)

        for power, power_data in environment['power'].iteritems():
            result = result and self._test_model(models.power, power_data)

        for temperature, temperature_data in environment['temperature'].iteritems():
            result = result and self._test_model(models.temperature, temperature_data)

        for cpu, cpu_data in environment['cpu'].iteritems():
            result = result and self._test_model(models.cpu, cpu_data)

        result = result and self._test_model(models.memory, environment['memory'])

        self.assertTrue(result)

    def test_get_bgp_neighbors(self):
        get_bgp_neighbors = self.device.get_bgp_neighbors()
        result = 'global' in get_bgp_neighbors.keys()

        if not result:
            print('global is not part of the returned vrfs')
        else:
            for vrf, vrf_data in get_bgp_neighbors.iteritems():
                result = result and isinstance(vrf_data['router_id'], unicode)
                if not result:
                    print('router_id is not unicode')

                for peer, peer_data in vrf_data['peers'].iteritems():
                    result = result and self._test_model(models.peer, peer_data)

                    for af, af_data in peer_data['address_family'].iteritems():
                        result = result and self._test_model(models.af, af_data)

            self.assertTrue(result)

    def test_get_lldp_neighbors_detail(self):

        get_lldp_neighbors_detail = self.device.get_lldp_neighbors_detail()
        result = len(get_lldp_neighbors_detail) > 0

        for interface, neighbor_list in get_lldp_neighbors_detail.iteritems():
            for neighbor in neighbor_list:
                result = result and self._test_model(models.lldp_neighbors_detail, neighbor)

        self.assertTrue(result)

    def test_get_bgp_config(self):

        get_bgp_config = self.device.get_bgp_config()
        result = len(get_bgp_config) > 0

        for bgp_group in get_bgp_config.values():
            result = result and self._test_model(models.bgp_config_group, bgp_group)
            for bgp_neighbor in bgp_group.get('neighbors', {}).values():
                result = result and self._test_model(models.bgp_config_neighbor, bgp_neighbor)

        self.assertTrue(result)

    def test_get_bgp_neighbors_detail(self):

        get_bgp_neighbors_detail = self.device.get_bgp_neighbors_detail()

        result = len(get_bgp_neighbors_detail) > 0

        for remote_as, neighbor_list in get_bgp_neighbors_detail.iteritems():
            for neighbor in neighbor_list:
                result = result and self._test_model(models.peer_details, neighbor)

        self.assertTrue(result)

    def test_get_arp_table(self):

        get_arp_table = self.device.get_arp_table()
        result = len(get_arp_table) > 0

        for arp_entry in get_arp_table:
            result = result and self._test_model(models.arp_table, arp_entry)

        self.assertTrue(result)

    def test_get_ntp_peers(self):

        get_ntp_peers = self.device.get_ntp_peers()
        result = len(get_ntp_peers) > 0

        for peer, peer_details in get_ntp_peers.iteritems():
            result = result and isinstance(peer, unicode)
            result = result and self._test_model(models.ntp_peer, peer_details)

        self.assertTrue(result)

    def test_get_ntp_stats(self):

        get_ntp_stats = self.device.get_ntp_stats()
        result = len(get_ntp_stats) > 0

        for ntp_peer_details in get_ntp_stats:
            result = result and self._test_model(models.ntp_stats, ntp_peer_details)

        self.assertTrue(result)

    def test_get_interfaces_ip(self):

        get_interfaces_ip = self.device.get_interfaces_ip()

        result = len(get_interfaces_ip) > 0

        for interface, interface_details in get_interfaces_ip.iteritems():
            ipv4 = interface_details.get('ipv4', {})
            ipv6 = interface_details.get('ipv6', {})
            for ip, ip_details in ipv4.iteritems():
                result = result and self._test_model(models.interfaces_ip, ip_details)
            for ip, ip_details in ipv6.iteritems():
                result = result and self._test_model(models.interfaces_ip, ip_details)

        self.assertTrue(result)

    def test_get_mac_address_table(self):
        get_mac_address_table = self.device.get_mac_address_table()

        result = len(get_mac_address_table) > 0

        for mac_table_entry in get_mac_address_table:
            result = result and self._test_model(models.mac_address_table, mac_table_entry)

        self.assertTrue(result)

    def test_get_route_to(self):

        destination  = '1.0.4.0/24'
        protocol = 'bgp'
        get_route_to = self.device.get_route_to(destination=destination, protocol=protocol)

        result = len(get_route_to) > 0

        for prefix, routes in get_route_to.iteritems():
            for route in routes:
                result = result and self._test_model(models.route, route)

        self.assertTrue(result)

    def test_get_snmp_information(self):

        get_snmp_information = self.device.get_snmp_information()
        result = len(get_snmp_information) > 0

        for snmp_entry in get_snmp_information:
            result = result and self._test_model(models.snmp, get_snmp_information)

        for community, community_data in get_snmp_information['community'].iteritems():
            result = result and self._test_model(models.snmp_community, community_data)

        self.assertTrue(result)

    def test_get_probes_config(self):

        get_probes_config = self.device.get_probes_config()
        result = len(get_probes_config) > 0

        for probe_name, probe_tests in get_probes_config.iteritems():
            for test_name, test_config in probe_tests.iteritems():
                result = result and self._test_model(models.probe_test, test_config)

        self.assertTrue(result)

    def test_get_probes_results(self):

        get_probes_results = self.device.get_probes_results()
        result = len(get_probes_results) > 0

        for probe_name, probe_tests in get_probes_results.iteritems():
            for test_name, test_results in probe_tests.iteritems():
                result = result and self._test_model(models.probe_test_results, test_results)

        self.assertTrue(result)

    def test_ping(self):

        destination = '8.8.8.8'
        get_ping = self.device.ping(destination)
        result = isinstance(get_ping.get('success'), dict)
        ping_results = get_ping.get('success', {})

        result = result and self._test_model(models.ping, ping_results)

        for ping_result in ping_results.get('results', []):
            result = result and self._test_model(models.ping_result, ping_result)

        self.assertTrue(result)

    def test_traceroute(self):

        destination = '8.8.8.8'
        get_traceroute = self.device.traceroute(destination)
        result = isinstance(get_traceroute.get('success'), dict)
        traceroute_results = get_traceroute.get('success', {})

        for hope_id, hop_result in traceroute_results.iteritems():
            for probe_id, probe_result in hop_result.get('probes', {}).iteritems():
                result = result and self._test_model(models.traceroute, probe_result)

        self.assertTrue(result)

    def test_get_users(self):

        get_users = self.device.get_users()
        result = len(get_users)

        for user, user_details in get_users.iteritems():
            result = result and self._test_model(models.users, user_details)
            result = result and (0 <= user_details.get('level') <= 15)

        self.assertTrue(result)
