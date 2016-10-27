"""Testing framework."""

from __future__ import print_function

import functools
import itertools
import json
import os


import helpers

import models


import pytest


NAPALM_TEST_MOCK = os.getenv('NAPALM_TEST_MOCK', default=True)


def list_dicts_diff(prv, nxt):
    """Compare two lists of dicts."""
    result = []
    for prv_element, nxt_element in itertools.izip_longest(prv, nxt, fillvalue={}):
        intermediate_result = dict_diff(prv_element, nxt_element)
        if intermediate_result:
            result.append(intermediate_result)
    return result


def dict_diff(prv, nxt):
    """Return a dict of keys that differ with another config object."""
    keys = set(prv.keys() + nxt.keys())
    result = {}

    for k in keys:
        if isinstance(prv.get(k), dict):
            if isinstance(nxt.get(k), dict):
                "If both are dicts we do a recursive call."
                diff = dict_diff(prv.get(k), nxt.get(k))
                if diff:
                    result[k] = diff
            else:
                "If only one is a dict they are clearly different"
                result[k] = {'result': prv.get(k), 'expected': nxt.get(k)}
        else:
            "Ellipsis is a wildcard."""
            if prv.get(k) != nxt.get(k) and nxt.get(k) != "...":
                result[k] = {'result': prv.get(k), 'expected': nxt.get(k)}
    return result


def wrap_test_cases(func):
    """Wrap test cases."""
    @functools.wraps(func)
    def wrapper(cls, test_case):
        for patched_attr in cls.device.patched_attrs:
            attr = getattr(cls.device, patched_attr)
            attr.current_test = func.__name__
            attr.current_test_case = test_case

        try:
            # This is an ugly, ugly, ugly hack because some python objects don't load
            # as expected. For example, dicts where integers are strings
            result = json.loads(json.dumps(func(cls)))
        except IOError:
            if test_case == "no_test_case_found":
                pytest.fail("No test case for '{}' found".format(func.__name__))
            else:
                raise
        except NotImplementedError:
            pytest.skip("Method not implemented")
            return

        # This is an ugly, ugly, ugly hack because some python objects don't load
        # as expected. For example, dicts where integers are strings

        if NAPALM_TEST_MOCK:
            try:
                expected_result = attr.expected_result
            except IOError as e:
                raise Exception("{}. Actual result was: {}".format(e, json.dumps(result)))
            if isinstance(result, list):
                diff = list_dicts_diff(result, expected_result)
            else:
                diff = dict_diff(result, expected_result)
            if diff:
                print("Resulting JSON object was: {}".format(json.dumps(result)))
                raise AssertionError("Expected result varies on some keys {}".format(
                                                                            json.dumps(diff)))

        for patched_attr in cls.device.patched_attrs:
            attr = getattr(cls.device, patched_attr)
            attr.current_test = ''   # Empty them to avoid side effects
            attr.current_test_case = ''   # Empty them to avoid side effects

        return result

    return wrapper


class BaseTestGetters:
    """Base class for testing drivers."""

    @wrap_test_cases
    def test_get_facts(self):
        """Test get_facts method."""
        facts = self.device.get_facts()
        assert helpers.test_model(models.facts, facts)
        return facts

    @wrap_test_cases
    def test_get_interfaces(self):
        """Test get_interfaces."""
        get_interfaces = self.device.get_interfaces()
        assert len(get_interfaces) > 0

        for interface, interface_data in get_interfaces.iteritems():
            assert helpers.test_model(models.interface, interface_data)

        return get_interfaces

    @wrap_test_cases
    def test_get_lldp_neighbors(self):
        """Test get_lldp_neighbors."""
        get_lldp_neighbors = self.device.get_lldp_neighbors()
        assert len(get_lldp_neighbors) > 0

        for interface, neighbor_list in get_lldp_neighbors.iteritems():
            for neighbor in neighbor_list:
                assert helpers.test_model(models.lldp_neighbors, neighbor)

        return get_lldp_neighbors

    @wrap_test_cases
    def test_get_interfaces_counters(self):
        """Test get_interfaces_counters."""
        get_interfaces_counters = self.device.get_interfaces_counters()
        assert len(self.device.get_interfaces_counters()) > 0

        for interface, interface_data in get_interfaces_counters.iteritems():
            assert helpers.test_model(models.interface_counters, interface_data)

        return get_interfaces_counters

    @wrap_test_cases
    def test_get_environment(self):
        """Test get_environment."""
        environment = self.device.get_environment()
        assert len(environment) > 0

        for fan, fan_data in environment['fans'].iteritems():
            assert helpers.test_model(models.fan, fan_data)

        for power, power_data in environment['power'].iteritems():
            assert helpers.test_model(models.power, power_data)

        for temperature, temperature_data in environment['temperature'].iteritems():
            assert helpers.test_model(models.temperature, temperature_data)

        for cpu, cpu_data in environment['cpu'].iteritems():
            assert helpers.test_model(models.cpu, cpu_data)

        assert helpers.test_model(models.memory, environment['memory'])

        return environment

    @wrap_test_cases
    def test_get_bgp_neighbors(self):
        """Test get_bgp_neighbors."""
        get_bgp_neighbors = self.device.get_bgp_neighbors()
        assert 'global' in get_bgp_neighbors.keys()

        for vrf, vrf_data in get_bgp_neighbors.iteritems():
            assert isinstance(vrf_data['router_id'], unicode)

            for peer, peer_data in vrf_data['peers'].iteritems():
                assert helpers.test_model(models.peer, peer_data)

                for af, af_data in peer_data['address_family'].iteritems():
                    assert helpers.test_model(models.af, af_data)

        return get_bgp_neighbors

    @wrap_test_cases
    def test_get_lldp_neighbors_detail(self):
        """Test get_lldp_neighbors_detail."""
        get_lldp_neighbors_detail = self.device.get_lldp_neighbors_detail()
        assert len(get_lldp_neighbors_detail) > 0

        for interface, neighbor_list in get_lldp_neighbors_detail.iteritems():
            for neighbor in neighbor_list:
                assert helpers.test_model(models.lldp_neighbors_detail, neighbor)

        return get_lldp_neighbors_detail

    @wrap_test_cases
    def test_get_bgp_config(self):
        """Test get_bgp_config."""
        get_bgp_config = self.device.get_bgp_config()
        assert len(get_bgp_config) > 0

        for bgp_group in get_bgp_config.values():
            assert helpers.test_model(models.bgp_config_group, bgp_group)
            for bgp_neighbor in bgp_group.get('neighbors', {}).values():
                assert helpers.test_model(models.bgp_config_neighbor, bgp_neighbor)

        return get_bgp_config

    @wrap_test_cases
    def test_get_bgp_neighbors_detail(self):
        """Test get_bgp_neighbors_detail."""
        get_bgp_neighbors_detail = self.device.get_bgp_neighbors_detail()

        assert len(get_bgp_neighbors_detail) > 0

        for vrf, vrf_ases in get_bgp_neighbors_detail.iteritems():
            assert isinstance(vrf, unicode)
            for remote_as, neighbor_list in vrf_ases.iteritems():
                assert isinstance(remote_as, int)
                for neighbor in neighbor_list:
                    assert helpers.test_model(models.peer_details, neighbor)

        return get_bgp_neighbors_detail

    @wrap_test_cases
    def test_get_arp_table(self):
        """Test get_arp_table."""
        get_arp_table = self.device.get_arp_table()
        assert len(get_arp_table) > 0

        for arp_entry in get_arp_table:
            assert helpers.test_model(models.arp_table, arp_entry)

        return get_arp_table

    @wrap_test_cases
    def test_get_ntp_peers(self):
        """Test get_ntp_peers."""
        get_ntp_peers = self.device.get_ntp_peers()
        assert len(get_ntp_peers) > 0

        for peer, peer_details in get_ntp_peers.iteritems():
            assert isinstance(peer, unicode)
            assert helpers.test_model(models.ntp_peer, peer_details)

        return get_ntp_peers

    @wrap_test_cases
    def test_get_ntp_stats(self):
        """Test get_ntp_stats."""
        get_ntp_stats = self.device.get_ntp_stats()
        assert len(get_ntp_stats) > 0

        for ntp_peer_details in get_ntp_stats:
            assert helpers.test_model(models.ntp_stats, ntp_peer_details)

        return get_ntp_stats

    @wrap_test_cases
    def test_get_interfaces_ip(self):
        """Test get_interfaces_ip."""
        get_interfaces_ip = self.device.get_interfaces_ip()
        assert len(get_interfaces_ip) > 0

        for interface, interface_details in get_interfaces_ip.iteritems():
            ipv4 = interface_details.get('ipv4', {})
            ipv6 = interface_details.get('ipv6', {})
            for ip, ip_details in ipv4.iteritems():
                assert helpers.test_model(models.interfaces_ip, ip_details)
            for ip, ip_details in ipv6.iteritems():
                assert helpers.test_model(models.interfaces_ip, ip_details)

        return get_interfaces_ip

    @wrap_test_cases
    def test_get_mac_address_table(self):
        """Test get_mac_address_table."""
        get_mac_address_table = self.device.get_mac_address_table()
        assert len(get_mac_address_table) > 0

        for mac_table_entry in get_mac_address_table:
            assert helpers.test_model(models.mac_address_table, mac_table_entry)

        return get_mac_address_table

    @wrap_test_cases
    def test_get_route_to(self):
        """Test get_route_to."""
        destination = '1.0.4.0/24'
        protocol = 'bgp'
        get_route_to = self.device.get_route_to(destination=destination, protocol=protocol)

        assert len(get_route_to) > 0

        for prefix, routes in get_route_to.iteritems():
            for route in routes:
                assert helpers.test_model(models.route, route)

        return get_route_to

    @wrap_test_cases
    def test_get_snmp_information(self):
        """Test get_snmp_information."""
        get_snmp_information = self.device.get_snmp_information()

        assert len(get_snmp_information) > 0

        for snmp_entry in get_snmp_information:
            assert helpers.test_model(models.snmp, get_snmp_information)

        for community, community_data in get_snmp_information['community'].iteritems():
            assert helpers.test_model(models.snmp_community, community_data)

        return get_snmp_information

    @wrap_test_cases
    def test_get_probes_config(self):
        """Test get_probes_config."""
        get_probes_config = self.device.get_probes_config()

        assert len(get_probes_config) > 0

        for probe_name, probe_tests in get_probes_config.iteritems():
            for test_name, test_config in probe_tests.iteritems():
                assert helpers.test_model(models.probe_test, test_config)

        return get_probes_config

    @wrap_test_cases
    def test_get_probes_results(self):
        """Test get_probes_results."""
        get_probes_results = self.device.get_probes_results()
        assert len(get_probes_results) > 0

        for probe_name, probe_tests in get_probes_results.iteritems():
            for test_name, test_results in probe_tests.iteritems():
                assert helpers.test_model(models.probe_test_results, test_results)

        return get_probes_results

    @wrap_test_cases
    def test_ping(self):
        """Test ping."""
        destination = '8.8.8.8'
        get_ping = self.device.ping(destination)
        assert isinstance(get_ping.get('success'), dict)
        ping_results = get_ping.get('success', {})

        assert helpers.test_model(models.ping, ping_results)

        for ping_result in ping_results.get('results', []):
            assert helpers.test_model(models.ping_result, ping_result)

        return get_ping

    @wrap_test_cases
    def test_traceroute(self):
        """Test traceroute."""
        destination = '8.8.8.8'
        get_traceroute = self.device.traceroute(destination)
        assert isinstance(get_traceroute.get('success'), dict)
        traceroute_results = get_traceroute.get('success', {})

        for hope_id, hop_result in traceroute_results.iteritems():
            for probe_id, probe_result in hop_result.get('probes', {}).iteritems():
                assert helpers.test_model(models.traceroute, probe_result)

        return get_traceroute

    @wrap_test_cases
    def test_get_users(self):
        """Test get_users."""
        get_users = self.device.get_users()
        assert len(get_users)

        for user, user_details in get_users.iteritems():
            assert helpers.test_model(models.users, user_details)
            assert (0 <= user_details.get('level') <= 15)

        return get_users

    @wrap_test_cases
    def test_get_optics(self):
        """Test get_optics."""
        get_optics = self.device.get_optics()
        assert isinstance(get_optics, dict)

        for iface, iface_data in get_optics.iteritems():
            assert isinstance(iface, unicode)
            for channel in iface_data['physical_channels']['channel']:
                assert len(channel) == 2
                assert isinstance(channel['index'], int)
                for field in ['input_power', 'output_power',
                              'laser_bias_current']:

                    assert len(channel['state'][field]) == 4
                    assert isinstance(channel['state'][field]['instant'],
                                      float)
                    assert isinstance(channel['state'][field]['avg'], float)
                    assert isinstance(channel['state'][field]['min'], float)
                    assert isinstance(channel['state'][field]['max'], float)

        return get_optics

    @wrap_test_cases
    def test_get_config(self):
        """Test get_config method."""
        get_config = self.device.get_config()

        assert isinstance(get_config, dict)
        assert helpers.test_model(models.config, get_config)

        return get_config

    @wrap_test_cases
    def test_get_config_filtered(self):
        """Test get_config method."""
        for config in ['running', 'startup', 'candidate']:
            get_config = self.device.get_config(retrieve=config)

            assert get_config['candidate'] == "" if config != "candidate" else True
            assert get_config['startup'] == "" if config != "startup" else True
            assert get_config['running'] == "" if config != "running" else True

        return get_config
