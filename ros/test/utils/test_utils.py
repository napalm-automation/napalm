import pytest
from napalm_ros import utils


@pytest.mark.parametrize('passed, expected', (
        ('60s', 60),
        ('6s', 6),
        ('1m10s', 70),
        ('1h1m10s', 3670),
        ('1d1h1m10s', 90070),
        ('1w1d1h1m10s', 694870),
    ))
def test_to_seconds(passed, expected):
    assert utils.to_seconds(passed) == expected


@pytest.mark.parametrize('passed, expected', (
        (
            ({'interface': 'ether1', 'address': '192.168.1.1/24'},),
            {'192.168.1.1': {'prefix_length': 24}},
        ),
    ))
def test_iface_addresses(passed, expected):
    assert utils.iface_addresses(passed, 'ether1') == expected


def test_iface_addresses_empty():
    rows = ({'interface': 'ether1', 'address': '192.168.1.1/24'},)
    assert utils.iface_addresses(rows, 'ether2') == {}
