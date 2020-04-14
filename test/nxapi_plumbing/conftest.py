#!/usr/bin/env python
"""py.test fixtures to be used in netmiko test suite."""
from os import path
import sys
import pytest
import yaml
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from napalm.nxapi_plumbing import Device
from mock_device import MockDevice

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


PWD = path.dirname(path.realpath(__file__))


def parse_yaml(yaml_file):
    """Parses a yaml file, returning its contents as a dict."""
    try:
        with open(yaml_file) as f:
            return yaml.safe_load(f)
    except IOError:
        sys.exit("Unable to open YAML file: {}".format(yaml_file))


def pytest_addoption(parser):
    """Add test_device option to py.test invocations."""
    parser.addoption(
        "--test_device",
        action="store",
        dest="test_device",
        type=str,
        help="Specify the platform type to test on",
    )


@pytest.fixture(scope="module")
def mock_pynxos_device(request):
    """Create a mock pynxos test device."""
    device = {
        "host": "nxos1.fake.com",
        "username": "admin",
        "password": "foo",
        "transport": "https",
        "api_format": "jsonrpc",
        "port": 8443,
        "timeout": 60,
        "verify": False,
    }
    conn = MockDevice(**device)
    return conn


@pytest.fixture(scope="module")
def mock_pynxos_device_xml(request):
    """Create a mock pynxos test device."""
    device = {
        "host": "nxos1.fake.com",
        "username": "admin",
        "password": "foo",
        "transport": "https",
        "api_format": "xml",
        "port": 8443,
        "timeout": 60,
        "verify": False,
    }
    conn = MockDevice(**device)
    return conn


@pytest.fixture(scope="module")
def pynxos_device(request):
    """Create a real pynxos test device."""
    device_under_test = request.config.getoption("test_device")
    test_devices = parse_yaml(PWD + "/etc/test_devices.yml")
    device = test_devices[device_under_test]
    conn = Device(**device)
    return conn
