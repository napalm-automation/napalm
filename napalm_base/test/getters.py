"""Testing framework."""

from __future__ import print_function

import json

import models
import pytest

import functools

import helpers

from double import BaseTestDouble


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
        cls.device.device.current_test = func.__name__
        cls.device.device.current_test_case = test_case

        try:
            result = func(cls)
            not_implemented = False

            if isinstance(cls.device.device, BaseTestDouble):
                diff = dict_diff(result, cls.device.device.expected_result)
                try:
                    assert not diff, "Expected result varies on some keys {}".format(diff)
                except AssertionError:
                    print("Resulting JSON object was: {}".format(json.dumps(result)))
                    raise

        except NotImplementedError:
            not_implemented = True

        cls.device.device.current_test = ''
        cls.device.device.current_test_case = ''

        if not_implemented:
            pytest.skip("Method not implemented")
        else:
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
        """Test get_interfaces method."""
        get_interfaces = self.device.get_interfaces()
        assert len(get_interfaces) > 0

        for interface, interface_data in get_interfaces.iteritems():
            assert helpers.test_model(models.interface, interface_data)

        return get_interfaces

    @wrap_test_cases
    def test_get_bgp_neighbors(self):
        """Test get_bgp_neighbors method."""
        get_bgp_neighbors = self.device.get_bgp_neighbors()
        assert 'global' in get_bgp_neighbors.keys(), "global is not part of the returned vrfs"

        for vrf, vrf_data in get_bgp_neighbors.iteritems():
            assert isinstance(vrf_data['router_id'], unicode), "router_id is not unicode"

            for peer, peer_data in vrf_data['peers'].iteritems():
                assert helpers.test_model(models.peer, peer_data)

                for af, af_data in peer_data['address_family'].iteritems():
                    assert helpers.test_model(models.af, af_data)

        return get_bgp_neighbors

    @wrap_test_cases
    def test_get_bgp_neighbors_detail(self):
        """Test get_bgp_neighbors_detail method."""
        get_bgp_neighbors_detail = self.device.get_bgp_neighbors_detail()

        assert len(get_bgp_neighbors_detail) > 0

        for remote_as, neighbor_list in get_bgp_neighbors_detail.iteritems():
            for neighbor in neighbor_list:
                assert helpers.test_model(models.peer_details, neighbor)

        return get_bgp_neighbors_detail
