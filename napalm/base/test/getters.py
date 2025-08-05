"""Testing framework."""

import functools
from itertools import zip_longest
import inspect
import json

import pytest
from napalm.base.test import helpers
from napalm.base import models
from napalm.base import NetworkDriver
from napalm.base.test import conftest


def list_dicts_diff(prv, nxt):
    """Compare two lists of dicts."""
    result = []
    for prv_element, nxt_element in zip_longest(prv, nxt, fillvalue={}):
        intermediate_result = dict_diff(prv_element, nxt_element)
        if intermediate_result:
            result.append(intermediate_result)
    return result


def dict_diff(prv, nxt):
    """Return a dict of keys that differ with another config object."""
    keys = set(list(prv.keys()) + list(nxt.keys()))
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
                result[k] = {"result": prv.get(k), "expected": nxt.get(k)}
        else:
            "Ellipsis is a wildcard." ""
            if prv.get(k) != nxt.get(k) and nxt.get(k) != "...":
                result[k] = {"result": prv.get(k), "expected": nxt.get(k)}
    return result


def wrap_test_cases(func):
    """Wrap test cases."""
    func.__dict__["build_test_cases"] = True

    @functools.wraps(func)
    def mock_wrapper(cls, test_case):
        for patched_attr in cls.device.patched_attrs:
            attr = getattr(cls.device, patched_attr)
            attr.current_test = func.__name__
            attr.current_test_case = test_case

        try:
            # This is an ugly, ugly, ugly hack because some python objects don't load
            # as expected. For example, dicts where integers are strings
            result = json.loads(json.dumps(func(cls, test_case)))
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
            raise AssertionError(
                "Expected result varies on some keys {}".format(json.dumps(diff))
            )

        for patched_attr in cls.device.patched_attrs:
            attr = getattr(cls.device, patched_attr)
            attr.current_test = ""  # Empty them to avoid side effects
            attr.current_test_case = ""  # Empty them to avoid side effects

        return None

    @functools.wraps(func)
    def real_wrapper(cls, test_case):
        try:
            return func(cls, test_case)
        except NotImplementedError:
            pytest.skip("Method not implemented")
            return

    if conftest.NAPALM_TEST_MOCK:
        return mock_wrapper
    else:
        return real_wrapper


class BaseTestGetters(object):
    """Base class for testing drivers."""

    def test_method_signatures(self):
        """
        Test that all methods have the same signature.

        The type hint annotations are ignored here because the import paths might differ.
        """
        errors = {}
        cls = self.driver
        # Create fictional driver instance (py3 needs bound methods)
        tmp_obj = cls(hostname="test", username="admin", password="pwd")
        attrs = [m for m, v in inspect.getmembers(tmp_obj)]
        for attr in attrs:
            func = getattr(tmp_obj, attr)
            if attr.startswith("_") or not inspect.ismethod(func):
                continue
            try:
                orig = getattr(NetworkDriver, attr)
                orig_spec = inspect.getfullargspec(orig)[:4]
            except AttributeError:
                orig_spec = "Method does not exist in napalm.base"
            func_spec = inspect.getfullargspec(func)[:4]
            if orig_spec != func_spec:
                errors[attr] = (orig_spec, func_spec)

        EXTRA_METHODS = ["__init__"]
        for method in EXTRA_METHODS:
            orig_spec = inspect.getfullargspec(getattr(NetworkDriver, method))[:4]
            func_spec = inspect.getfullargspec(getattr(cls, method))[:4]
            if orig_spec != func_spec:
                errors[attr] = (orig_spec, func_spec)

        assert not errors, "Some methods vary. \n{}".format(errors.keys())

    @wrap_test_cases
    def test_is_alive(self, test_case):
        """Test is_alive method."""
        alive = self.device.is_alive()
        assert helpers.test_model(models.AliveDict, alive)
        return alive

    @wrap_test_cases
    def test_get_facts(self, test_case):
        """Test get_facts method."""
        facts = self.device.get_facts()
        assert helpers.test_model(models.FactsDict, facts)
        return facts

    @wrap_test_cases
    def test_get_interfaces(self, test_case):
        """Test get_interfaces."""
        get_interfaces = self.device.get_interfaces()
        assert len(get_interfaces) > 0

        for interface, interface_data in get_interfaces.items():
            assert helpers.test_model(models.InterfaceDict, interface_data)

        return get_interfaces

    @wrap_test_cases
    def test_get_lldp_neighbors(self, test_case):
        """Test get_lldp_neighbors."""
        get_lldp_neighbors = self.device.get_lldp_neighbors()
        assert len(get_lldp_neighbors) > 0

        for interface, neighbor_list in get_lldp_neighbors.items():
            for neighbor in neighbor_list:
                assert helpers.test_model(models.LLDPNeighborDict, neighbor)

        return get_lldp_neighbors

    @wrap_test_cases
    def test_get_interfaces_counters(self, test_case):
        """Test get_interfaces_counters."""
        get_interfaces_counters = self.device.get_interfaces_counters()
        assert len(self.device.get_interfaces_counters()) > 0

        for interface, interface_data in get_interfaces_counters.items():
            assert helpers.test_model(models.InterfaceCounterDict, interface_data)

        return get_interfaces_counters

    @wrap_test_cases
    def test_get_environment(self, test_case):
        """Test get_environment."""
        environment = self.device.get_environment()
        assert len(environment) > 0

        for fan, fan_data in environment["fans"].items():
            assert helpers.test_model(models.FanDict, fan_data)

        for power, power_data in environment["power"].items():
            assert helpers.test_model(models.PowerDict, power_data)

        for temperature, temperature_data in environment["temperature"].items():
            assert helpers.test_model(models.TemperatureDict, temperature_data)

        for cpu, cpu_data in environment["cpu"].items():
            assert helpers.test_model(models.CPUDict, cpu_data)

        assert helpers.test_model(models.MemoryDict, environment["memory"])

        return environment

    @wrap_test_cases
    def test_get_bgp_neighbors(self, test_case):
        """Test get_bgp_neighbors."""
        get_bgp_neighbors = self.device.get_bgp_neighbors()
        if len(get_bgp_neighbors) > 0:
            assert "global" in get_bgp_neighbors.keys()

        for vrf, vrf_data in get_bgp_neighbors.items():
            assert isinstance(vrf_data["router_id"], str)

            for peer, peer_data in vrf_data["peers"].items():
                assert helpers.test_model(models.PeerDict, peer_data)

                for af, af_data in peer_data["address_family"].items():
                    assert helpers.test_model(models.AFDict, af_data)

        return get_bgp_neighbors

    @wrap_test_cases
    def test_get_lldp_neighbors_detail(self, test_case):
        """Test get_lldp_neighbors_detail."""
        get_lldp_neighbors_detail = self.device.get_lldp_neighbors_detail()
        assert len(get_lldp_neighbors_detail) > 0

        for interface, neighbor_list in get_lldp_neighbors_detail.items():
            for neighbor in neighbor_list:
                assert helpers.test_model(models.LLDPNeighborDetailDict, neighbor)

        return get_lldp_neighbors_detail

    @wrap_test_cases
    def test_get_bgp_config(self, test_case):
        """Test get_bgp_config."""
        get_bgp_config = self.device.get_bgp_config()
        assert get_bgp_config == {} or len(get_bgp_config) > 0

        for bgp_group in get_bgp_config.values():
            assert helpers.test_model(models.BGPConfigGroupDict, bgp_group)
            for bgp_neighbor in bgp_group.get("neighbors", {}).values():
                assert helpers.test_model(models.BGPConfigNeighborDict, bgp_neighbor)

        return get_bgp_config

    @wrap_test_cases
    def test_get_bgp_neighbors_detail(self, test_case):
        """Test get_bgp_neighbors_detail."""
        get_bgp_neighbors_detail = self.device.get_bgp_neighbors_detail()

        assert len(get_bgp_neighbors_detail) > 0

        for vrf, vrf_ases in get_bgp_neighbors_detail.items():
            assert isinstance(vrf, str)
            for remote_as, neighbor_list in vrf_ases.items():
                assert isinstance(remote_as, int)
                for neighbor in neighbor_list:
                    assert helpers.test_model(models.PeerDetailsDict, neighbor)

        return get_bgp_neighbors_detail

    @wrap_test_cases
    def test_get_arp_table(self, test_case):
        """Test get_arp_table."""
        get_arp_table = self.device.get_arp_table()
        assert len(get_arp_table) > 0

        for arp_entry in get_arp_table:
            assert helpers.test_model(models.ARPTableDict, arp_entry)

        return get_arp_table

    @wrap_test_cases
    def test_get_arp_table_with_vrf(self, test_case):
        """Test get_arp_table."""
        get_arp_table = self.device.get_arp_table(vrf="TEST")
        assert len(get_arp_table) > 0

        for arp_entry in get_arp_table:
            assert helpers.test_model(models.ARPTableDict, arp_entry)

        return get_arp_table

    @wrap_test_cases
    def test_get_ipv6_neighbors_table(self, test_case):
        """Test get_ipv6_neighbors_table."""
        get_ipv6_neighbors_table = self.device.get_ipv6_neighbors_table()

        for entry in get_ipv6_neighbors_table:
            assert helpers.test_model(models.IPV6NeighborDict, entry)

        return get_ipv6_neighbors_table

    @wrap_test_cases
    def test_get_ntp_peers(self, test_case):
        """Test get_ntp_peers."""
        get_ntp_peers = self.device.get_ntp_peers()
        assert len(get_ntp_peers) > 0

        for peer, peer_details in get_ntp_peers.items():
            assert isinstance(peer, str)
            assert helpers.test_model(
                models.NTPPeerDict, peer_details, allow_subset=True
            )

        return get_ntp_peers

    @wrap_test_cases
    def test_get_ntp_servers(self, test_case):
        """Test get_ntp_servers."""
        get_ntp_servers = self.device.get_ntp_servers()
        assert len(get_ntp_servers) > 0

        for server, server_details in get_ntp_servers.items():
            assert isinstance(server, str)
            assert helpers.test_model(
                models.NTPServerDict, server_details, allow_subset=True
            )

        return get_ntp_servers

    @wrap_test_cases
    def test_get_ntp_stats(self, test_case):
        """Test get_ntp_stats."""
        get_ntp_stats = self.device.get_ntp_stats()
        assert len(get_ntp_stats) > 0

        for ntp_peer_details in get_ntp_stats:
            assert helpers.test_model(models.NTPStats, ntp_peer_details)

        return get_ntp_stats

    @wrap_test_cases
    def test_get_interfaces_ip(self, test_case):
        """Test get_interfaces_ip."""
        get_interfaces_ip = self.device.get_interfaces_ip()
        assert len(get_interfaces_ip) > 0

        for interface, interface_details in get_interfaces_ip.items():
            ipv4 = interface_details.get("ipv4", {})
            ipv6 = interface_details.get("ipv6", {})
            for ip, ip_details in ipv4.items():
                assert helpers.test_model(models.InterfacesIPDictEntry, ip_details)
            for ip, ip_details in ipv6.items():
                assert helpers.test_model(models.InterfacesIPDictEntry, ip_details)

        return get_interfaces_ip

    @wrap_test_cases
    def test_get_mac_address_table(self, test_case):
        """Test get_mac_address_table."""
        get_mac_address_table = self.device.get_mac_address_table()
        assert len(get_mac_address_table) > 0

        for mac_table_entry in get_mac_address_table:
            assert helpers.test_model(models.MACAdressTable, mac_table_entry)

        return get_mac_address_table

    @wrap_test_cases
    def test_get_route_to(self, test_case):
        """Test get_route_to."""
        destination = "1.0.4.0/24"
        protocol = "bgp"
        get_route_to = self.device.get_route_to(
            destination=destination, protocol=protocol
        )

        assert len(get_route_to) > 0

        for prefix, routes in get_route_to.items():
            for route in routes:
                assert helpers.test_model(models.RouteDict, route)

        return get_route_to

    @wrap_test_cases
    def test_get_route_to_longer(self, test_case):
        """Test get_route_to with longer=True"""
        destination = "1.0.4.0/24"
        protocol = "bgp"

        get_route_to = self.device.get_route_to(
            destination=destination, protocol=protocol, longer=True
        )

        assert len(get_route_to) > 0

        for prefix, routes in get_route_to.items():
            for route in routes:
                assert helpers.test_model(models.RouteDict, route)

        return get_route_to

    @wrap_test_cases
    def test_get_snmp_information(self, test_case):
        """Test get_snmp_information."""
        get_snmp_information = self.device.get_snmp_information()

        assert len(get_snmp_information) > 0

        for snmp_entry in get_snmp_information:
            assert helpers.test_model(models.SNMPDict, get_snmp_information)

        for community, community_data in get_snmp_information["community"].items():
            assert helpers.test_model(models.SNMPCommunityDict, community_data)

        return get_snmp_information

    @wrap_test_cases
    def test_get_probes_config(self, test_case):
        """Test get_probes_config."""
        get_probes_config = self.device.get_probes_config()

        assert len(get_probes_config) > 0

        for probe_name, probe_tests in get_probes_config.items():
            for test_name, test_config in probe_tests.items():
                assert helpers.test_model(models.ProbeTestDict, test_config)

        return get_probes_config

    @wrap_test_cases
    def test_get_probes_results(self, test_case):
        """Test get_probes_results."""
        get_probes_results = self.device.get_probes_results()
        assert len(get_probes_results) > 0

        for probe_name, probe_tests in get_probes_results.items():
            for test_name, test_results in probe_tests.items():
                assert helpers.test_model(models.ProbeTestResultDict, test_results)

        return get_probes_results

    @wrap_test_cases
    def test_ping(self, test_case):
        """Test ping."""
        destination = "8.8.8.8"
        get_ping = self.device.ping(destination)
        assert isinstance(get_ping.get("success"), dict)
        ping_results = get_ping.get("success", {})

        assert helpers.test_model(models.PingDict, ping_results)

        for ping_result in ping_results.get("results", []):
            assert helpers.test_model(models.PingResultDictEntry, ping_result)

        return get_ping

    @wrap_test_cases
    def test_traceroute(self, test_case):
        """Test traceroute."""
        destination = "8.8.8.8"
        get_traceroute = self.device.traceroute(destination)
        assert isinstance(get_traceroute.get("success"), dict)
        traceroute_results = get_traceroute.get("success", {})

        for hope_id, hop_result in traceroute_results.items():
            for probe_id, probe_result in hop_result.get("probes", {}).items():
                assert helpers.test_model(models.TracerouteDict, probe_result)

        return get_traceroute

    @wrap_test_cases
    def test_get_users(self, test_case):
        """Test get_users."""
        get_users = self.device.get_users()
        assert len(get_users)

        for user, user_details in get_users.items():
            assert helpers.test_model(models.UsersDict, user_details)
            assert (0 <= user_details.get("level") <= 15) or (
                user_details.get("level") == 20
            )

        return get_users

    @wrap_test_cases
    def test_get_optics(self, test_case):
        """Test get_optics."""
        get_optics = self.device.get_optics()
        assert isinstance(get_optics, dict)

        for iface, iface_data in get_optics.items():
            assert isinstance(iface, str)
            for channel in iface_data["physical_channels"]["channel"]:
                assert len(channel) == 2
                assert isinstance(channel["index"], int)
                for field in ["input_power", "output_power", "laser_bias_current"]:
                    assert len(channel["state"][field]) == 4
                    assert isinstance(channel["state"][field]["instant"], float)
                    assert isinstance(channel["state"][field]["avg"], float)
                    assert isinstance(channel["state"][field]["min"], float)
                    assert isinstance(channel["state"][field]["max"], float)

        return get_optics

    @wrap_test_cases
    def test_get_config(self, test_case):
        """Test get_config method."""
        get_config = self.device.get_config()

        assert isinstance(get_config, dict)
        assert helpers.test_model(models.ConfigDict, get_config)

        return get_config

    @wrap_test_cases
    def test_get_config_filtered(self, test_case):
        """Test get_config method."""
        if self.device.platform == "iosxr_netconf":
            pytest.skip("This test is not implemented on {self.device.platform}")
        for config in ["running", "startup", "candidate"]:
            get_config = self.device.get_config(retrieve=config)

            assert get_config["candidate"] == "" if config != "candidate" else True
            assert get_config["startup"] == "" if config != "startup" else True
            assert get_config["running"] == "" if config != "running" else True

        return get_config

    @wrap_test_cases
    def test_get_config_sanitized(self, test_case):
        """Test get_config method."""
        get_config = self.device.get_config(sanitized=True)

        assert isinstance(get_config, dict)
        assert helpers.test_model(models.ConfigDict, get_config)

        return get_config

    @wrap_test_cases
    def test_get_network_instances(self, test_case):
        """Test get_network_instances method."""
        get_network_instances = self.device.get_network_instances()

        assert isinstance(get_network_instances, dict)
        for network_instance_name, network_instance in get_network_instances.items():
            assert helpers.test_model(models.NetworkInstanceDict, network_instance)
            assert helpers.test_model(
                models.NetworkInstanceStateDict, network_instance["state"]
            )
            assert helpers.test_model(
                models.NetworkInstanceInterfacesDict, network_instance["interfaces"]
            )

        return get_network_instances

    @wrap_test_cases
    def test_get_firewall_policies(self, test_case):
        """Test get_firewall_policies method."""
        get_firewall_policies = self.device.get_firewall_policies()
        assert len(get_firewall_policies) > 0
        for policy_name, policy_details in get_firewall_policies.items():
            for policy_term in policy_details:
                assert helpers.test_model(models.FirewallPolicyDict, policy_term)
        return get_firewall_policies

    @wrap_test_cases
    def test_get_vlans(self, test_case):
        """Test get_vlans."""
        get_vlans = self.device.get_vlans()

        assert len(get_vlans) > 0

        for vlan, vlan_data in get_vlans.items():
            assert helpers.test_model(models.VlanDict, vlan_data)

        return get_vlans
