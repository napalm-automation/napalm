"""Testing framework."""

from __future__ import print_function

import models
import pytest

import functools

import helpers


def wrap_test_cases(func):
    """Wrap test cases."""
    @functools.wraps(func)
    def wrapper(cls, test_case):
        cls.device.device.current_test = func.__name__
        cls.device.device.current_test_case = test_case

        try:
            result = func(cls)
            not_implented = False
        except NotImplementedError:
            not_implented = True

        cls.device.device.current_test = ''
        cls.device.device.current_test_case = ''

        if not_implented:
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
        result = helpers.test_model(models.facts, facts)
        assert result

    @wrap_test_cases
    def test_get_interfaces(self):
        """Test get_interfaces method."""
        get_interfaces = self.device.get_interfaces()
        result = len(get_interfaces) > 0

        for interface, interface_data in get_interfaces.iteritems():
            result = result and helpers.test_model(models.interface, interface_data)

        assert result

    @wrap_test_cases
    def test_get_bgp_neighbors(self):
        """Test get_bgp_neighbors method."""
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
                    result = result and helpers.test_model(models.peer, peer_data)

                    for af, af_data in peer_data['address_family'].iteritems():
                        result = result and helpers.test_model(models.af, af_data)

            assert result

    @wrap_test_cases
    def test_get_bgp_neighbors_detail(self):
        """Test get_bgp_neighbors_detail method."""
        get_bgp_neighbors_detail = self.device.get_bgp_neighbors_detail()

        result = len(get_bgp_neighbors_detail) > 0

        for remote_as, neighbor_list in get_bgp_neighbors_detail.iteritems():
            for neighbor in neighbor_list:
                result = result and helpers.test_model(models.peer_details, neighbor)

        assert result
