"""
Tests for EOS cli_syntax
"""
from napalm.eos.utils.cli_syntax import cli_convert


def test_cli_no_change_v2():
    """
    Test no change for basic commands in version 2
    :return:
    """
    commands = ["show version", "show interfaces"]

    for c in commands:
        assert c == cli_convert(c, 2)
        assert c == cli_convert(c, 1)


def test_cli_no_change_non_exist_version():
    """
    Test no change for basic commands and non-existing versions
    :return:
    """
    commands = ["show version", "show interfaces"]

    for c in commands:
        assert c == cli_convert(c, 100000)


def test_cli_change_exact():
    """
    Test cli change for exact commands
    """
    commands = ["show ipv6 bgp neighbors", "show lldp traffic"]
    expect = ["show ipv6 bgp peers", "show lldp counters"]

    for c, e in zip(commands, expect):
        assert e == cli_convert(c, 2)
        assert c == cli_convert(e, 1)


def test_cli_change_long_commands():
    """
    Test cli change for long commands
    """
    commands = ["show ipv6 bgp neighbors vrf all", "show lldp traffic | include test"]
    expect = ["show ipv6 bgp peers vrf all", "show lldp counters | include test"]

    for c, e in zip(commands, expect):
        assert e == cli_convert(c, 2)
        assert c == cli_convert(e, 1)
