"""Constants for the JunOS driver."""

from napalm.base.constants import *  # noqa

# OpenConfig mapping
# ref: https://github.com/openconfig/public/blob/master/release/models/network-instance/openconfig-network-instance-types.yang  # noqa
OC_NETWORK_INSTANCE_TYPE_MAP = {
    "default": "DEFAULT_INSTANCE",
    "l2vpn": "L2VPN",
    "vrf": "L3VRF",
    "evpn": "BGP_EVPN",
    "vpls": "BGP_VPLS",
    "forwarding": "L2P2P",
}
# OPTICS_NULL_LEVEL_SPC matches infinite light level '- Inf'
# reading on some versions of JUNOS
# https://github.com/napalm-automation/napalm/issues/491
OPTICS_NULL_LEVEL_SPC = "- Inf"

LLDP_CAPAB_TRANFORM_TABLE = {
    "other": "other",
    "repeater": "repeater",
    "bridge": "bridge",
    "wlan access point": "wlan-access-point",
    "router": "router",
    "telephone": "telephone",
    "docsis cable device": "docsis-cable-device",
    "station only": "station",
}
