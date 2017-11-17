"""Constants for the JunOS driver."""

from __future__ import unicode_literals

from napalm.base.constants import *  # noqa

# OpenConfig mapping
# ref: https://github.com/openconfig/public/blob/master/release/models/network-instance/openconfig-network-instance-types.yang  # noqa
OC_NETWORK_INSTANCE_TYPE_MAP = {
    'default': 'DEFAULT_INSTANCE',
    'l2vpn': 'L2VPN',
    'vrf': 'L3VRF',
    'evpn': 'BGP_EVPN',
    'vpls': 'BGP_VPLS',
    'forwarding': 'L2P2P'
}
# OPTICS_NULL_LEVEL_SPC matches infinite light level '- Inf'
# reading on some versions of JUNOS
# https://github.com/napalm-automation/napalm/issues/491
OPTICS_NULL_LEVEL_SPC = '- Inf'
