"""Some common jinja filters."""


class CustomJinjaFilters(object):
    """Utility filters for jinja2."""

    @classmethod
    def filters(cls):
        """Return jinja2 filters that this module provide."""
        return {
            "oc_attr_isdefault": oc_attr_isdefault,
            "openconfig_to_cisco_af": openconfig_to_cisco_af,
            "openconfig_to_eos_af": openconfig_to_eos_af,
        }


def oc_attr_isdefault(o):
    """Return wether an OC attribute has been defined or not."""
    if not o._changed() and not o.default():
        return True
    if o == o.default():
        return True
    return False


def openconfig_to_cisco_af(value):
    """Translate openconfig AF name to Cisco AFI name."""
    if ":" in value:
        value = value.split(":")[1]

    mapd = {
        "IPV4_UNICAST": "ipv4 unicast",
        "IPV6_UNICAST": "ipv6 unicast",
        "IPV4_LABELED_UNICAST": "ipv4 unicast",
        "IPV6_LABELED_UNICAST": "ipv6 unicast",
        "L3VPN_IPV4_UNICAST": "vpnv4",
        "L3VPN_IPV6_UNICAST": "vpnv6",
    }
    return mapd[value]


def openconfig_to_eos_af(value):
    """Translate openconfig AF name to EOS AFI name."""
    if ":" in value:
        value = value.split(":")[1]

    mapd = {"IPV4_UNICAST": "ipv4", "IPV6_UNICAST": "ipv6"}
    return mapd[value]
