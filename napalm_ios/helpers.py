"""Helper functions for the NAPALM base."""

# Python3 support
from __future__ import print_function
from __future__ import unicode_literals

# third party libs
from netaddr import IPAddress

# local modules
from napalm_base.utils import py23_compat


def ip(addr, version=None):
    """
    Converts a raw string to a valid IP address. This function replaces napalm_base.helpers.ip() \
    to provide support for IP version checking.
    Motivation: the groups of the IP addreses may contain leading zeros. IPv6 addresses can \
    contain sometimes uppercase characters. E.g.: 2001:0dB8:85a3:0000:0000:8A2e:0370:7334 has \
    the same logical value as 2001:db8:85a3::8a2e:370:7334. However, their values as strings are \
    not the same.
    :param addr: the raw string containing the value of the IP Address
    :param version: (optional) insist on a specific IP address version.
    :type version: int.
    :return: a string containing the IP Address in a standard format (no leading zeros, \
    zeros-grouping, lowercase)
    Example:
    .. code-block:: python
        >>> ip('2001:0dB8:85a3:0000:0000:8A2e:0370:7334')
        u'2001:db8:85a3::8a2e:370:7334'
    """
    obj = IPAddress(addr)
    if version and obj.version != version:
        raise ValueError("%s is not an ipv%d address" % (addr, version))
    return py23_compat.text_type(obj)
