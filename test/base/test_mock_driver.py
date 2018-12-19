"""
Test base helpers.
"""

# Python3 support
from __future__ import print_function
from __future__ import unicode_literals


# NAPALM base
from napalm.base import get_network_driver
import napalm.base.exceptions
from napalm.base.utils import py23_compat

import pytest

import os


BASE_PATH = os.path.dirname(__file__)


driver = get_network_driver("mock")
optional_args = {
    "path": os.path.join(BASE_PATH, "test_mock_driver"),
    "profile": ["eos"],
}
fail_args = {
    "path": os.path.join(BASE_PATH, "test_mock_driver"),
    "profile": ["eos"],
    "fail_on_open": True,
}


class TestMockDriver(object):
    """Test Mock Driver."""

    def test_basic(self):
        d = driver("blah", "bleh", "blih", optional_args=optional_args)
        assert d.is_alive() == {"is_alive": False}
        d.open()
        assert d.is_alive() == {"is_alive": True}
        d.close()
        assert d.is_alive() == {"is_alive": False}

        with pytest.raises(napalm.base.exceptions.ConnectionClosedException) as excinfo:
            d.get_facts()
        assert "connection closed" in py23_compat.text_type(excinfo.value)

    def test_context_manager(self):
        with pytest.raises(napalm.base.exceptions.ConnectionException) as e, driver(
            "blah", "bleh", "blih", optional_args=fail_args
        ) as d:
            pass
        assert "You told me to do this" in py23_compat.text_type(e.value)
        with pytest.raises(AttributeError) as e, driver(
            "blah", "bleh", "blih", optional_args=optional_args
        ) as d:
            assert d.is_alive() == {"is_alive": True}
            d.__fake_call()
        assert d.is_alive() == {"is_alive": False}
        assert "object has no attribute" in py23_compat.text_type(e.value)

    def test_mocking_getters(self):
        d = driver("blah", "bleh", "blih", optional_args=optional_args)
        d.open()
        assert d.get_facts()["hostname"] == "localhost"
        assert d.get_facts()["hostname"] == "changed_hostname"
        d.close()

    def test_not_mocking_getters(self):
        d = driver("blah", "bleh", "blih", optional_args=optional_args)
        d.open()

        with pytest.raises(NotImplementedError) as excinfo:
            d.get_route_to()
        expected = "You can provide mocked data in {}".format(
            os.path.join(optional_args["path"], "get_route_to.1")
        )
        assert expected in py23_compat.text_type(excinfo.value)

        with pytest.raises(NotImplementedError) as excinfo:
            d.get_route_to()
        expected = "You can provide mocked data in {}".format(
            os.path.join(optional_args["path"], "get_route_to.2")
        )
        assert expected in py23_compat.text_type(excinfo.value)

        d.close()

    def test_arguments(self):
        d = driver("blah", "bleh", "blih", optional_args=optional_args)
        d.open()

        with pytest.raises(TypeError) as excinfo:
            d.get_route_to(1, 2, 3)
        assert (
            "get_route_to: expected at most 3 arguments, got 4"
            in py23_compat.text_type(excinfo.value)
        )

        with pytest.raises(TypeError) as excinfo:
            d.get_route_to(1, 1, protocol=2)
        assert (
            "get_route_to: expected at most 3 arguments, got 3"
            in py23_compat.text_type(excinfo.value)
        )

        with pytest.raises(TypeError) as excinfo:
            d.get_route_to(proto=2)
        assert (
            "get_route_to got an unexpected keyword argument 'proto'"
            in py23_compat.text_type(excinfo.value)
        )

        d.close()

    def test_mock_error(self):
        d = driver("blah", "bleh", "blih", optional_args=optional_args)
        d.open()

        with pytest.raises(KeyError) as excinfo:
            d.get_bgp_neighbors()
        assert "Something" in py23_compat.text_type(excinfo.value)

        with pytest.raises(napalm.base.exceptions.ConnectionClosedException) as excinfo:
            d.get_bgp_neighbors()
        assert "Something" in py23_compat.text_type(excinfo.value)

        with pytest.raises(TypeError) as excinfo:
            d.get_bgp_neighbors()
            assert (
                "Couldn't resolve exception NoIdeaException"
                in py23_compat.text_type(excinfo.value)
            )

        d.close()

    def test_cli(self):
        d = driver("blah", "bleh", "blih", optional_args=optional_args)
        d.open()
        result = d.cli(["a_command", "b_command"])
        assert result == {
            "a_command": "result command a\n",
            "b_command": "result command b\n",
        }
        d.close()

    def test_configuration_merge(self):
        d = driver("blah", "bleh", "blih", optional_args=optional_args)
        d.open()
        d.load_merge_candidate(config="asdasdasd")
        assert d.merge is True
        d.compare_config() == "a_diff"
        d.commit_config()
        d.close()

    def test_configuration_replace(self):
        d = driver("blah", "bleh", "blih", optional_args=optional_args)
        d.open()
        d.load_replace_candidate(config="asdasdasd")
        assert d.merge is False
        d.compare_config() == "a_diff"
        d.commit_config()
        d.close()
