"""Tests for uptime utils"""

from napalm.nxos_ssh import NXOSSSHDriver


def test_parse_uptime():
    """
    Test uptime parsing
    """
    assert (
        NXOSSSHDriver.parse_uptime("0 day(s), 0 hour(s), 0 minute(s), 1 second(s)") == 1
    )
    assert (
        NXOSSSHDriver.parse_uptime("1 day(s), 0 hour(s), 0 minute(s), 0 second(s)")
        == 86400
    )
    assert (
        NXOSSSHDriver.parse_uptime("4 day(s), 15 hour(s), 48 minute(s), 52 second(s)")
        == 402532
    )
