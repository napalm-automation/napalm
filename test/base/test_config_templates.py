"""
Ensure the shipped per-driver configuration templates render under Python 3.

These templates (snmp_config, set_probes, set_users, ...) used ``dict.iteritems``
which does not exist on Python 3, so every one of them raised at render time.
This test renders each shipped template the same way ``load_template`` does
(FileSystemLoader over the driver's ``templates`` dir plus the NAPALM custom
Jinja filters) and asserts it produces output, guarding against a regression.
"""

import os

import jinja2
import pytest

import napalm
from napalm.base.utils.jinja_filters import CustomJinjaFilters

NAPALM_DIR = os.path.dirname(os.path.abspath(napalm.__file__))

_NTP_PEERS = {"peers": ["192.0.2.1", "192.0.2.2"]}
_NTP_SERVERS = {"servers": ["192.0.2.10", "192.0.2.11"]}
_SNMP = {
    "location": "DC1",
    "contact": "noc",
    "chassis_id": "ch1",
    "community": {
        "public": {"mode": "ro"},
        "private": {"mode": "rw", "acl": "10"},
    },
}
_PROBES = {
    "probes": {
        "probe1": {
            "test1": {
                "probe_type": "icmp-ping",
                "target": "192.0.2.1",
                "probe_count": 5,
                "test_interval": 3,
                "source": "192.0.2.2",
            }
        }
    }
}
_USERS = {
    "users": {
        "admin": {
            "level": 15,
            "password": "$1$abc$0123456789abcdef",
            "sshkeys": ["ssh-rsa AAAAB3Nza example@host"],
        }
    }
}
_HOSTNAME = {"hostname": "router1"}

# Sample render variables keyed by template name (matches what the napalm_*
# helper functions pass through load_template).
VARS_BY_TEMPLATE = {
    "snmp_config": _SNMP,
    "delete_snmp_config": _SNMP,
    "set_probes": _PROBES,
    "delete_probes": _PROBES,
    "schedule_probes": _PROBES,
    "set_users": _USERS,
    "delete_users": _USERS,
    "set_ntp_peers": _NTP_PEERS,
    "delete_ntp_peers": _NTP_PEERS,
    "set_ntp_servers": _NTP_SERVERS,
    "delete_ntp_servers": _NTP_SERVERS,
    "set_hostname": _HOSTNAME,
}


def _discover_cases():
    cases = []
    for driver in sorted(os.listdir(NAPALM_DIR)):
        templates_dir = os.path.join(NAPALM_DIR, driver, "templates")
        if not os.path.isdir(templates_dir):
            continue
        for entry in sorted(os.listdir(templates_dir)):
            if not entry.endswith(".j2"):
                continue
            name = entry[: -len(".j2")]
            if name in VARS_BY_TEMPLATE:
                cases.append((driver, name))
    return cases


CASES = _discover_cases()


def _render(driver, template_name, variables):
    search_path = [os.path.join(NAPALM_DIR, driver, "templates")]
    environment = jinja2.Environment(
        loader=jinja2.FileSystemLoader(search_path),
    )
    for filter_name, filter_function in CustomJinjaFilters.filters().items():
        environment.filters[filter_name] = filter_function
    template = environment.get_template(f"{template_name}.j2")
    return template.render(**variables)


def test_cases_discovered():
    # Guard against the discovery silently finding nothing (e.g. a layout change).
    assert CASES, "no shipped config templates were discovered"


@pytest.mark.parametrize("driver, template_name", CASES)
def test_config_template_renders(driver, template_name):
    # The property under test is that the template renders under Python 3 at all
    # (the bugs -- ``dict.iteritems`` and a mis-nested ``endfor`` -- raised).
    # Some templates are intentionally empty (e.g. junos schedule_probes), so an
    # empty result is fine; a raised exception is not.
    rendered = _render(driver, template_name, VARS_BY_TEMPLATE[template_name])
    assert isinstance(rendered, str)
