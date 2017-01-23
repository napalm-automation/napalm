"""Constants to be used across NAPALM drivers."""

from __future__ import unicode_literals

CONFIG_LOCK = True  # must be changed soon!
TIMEOUT = 60  # seconds

INTERFACE_NULL_SPEED = -1

ACTION_TYPE_METHODS = ('ping', 'traceroute', )

BGP_NEIGHBOR_NULL_COUNTER = -1

SNMP_AUTHORIZATION_MODE_MAP = {
  'read-only': 'ro',
  'read-write': 'rw'
}

ROUTE_COMMON_PROTOCOL_FIELDS = [
    'destination',
    'prefix_length',
    'protocol',
    'current_active',
    'last_active',
    'age',
    'next_hop',
    'outgoing_interface',
    'selected_next_hop',
    'preference',
    'inactive_reason',
    'routing_table'
]  # identifies the list of fileds common for all protocols
ROUTE_PROTOCOL_SPECIFIC_FIELDS = {
    'bgp': [
        'local_as',
        'remote_as',
        'as_path',
        'communities',
        'local_preference',
        'preference2',
        'remote_address',
        'metric',
        'metric2'
    ],
    'isis': [
        'level',
        'metric',
        'local_as'
    ],
    'static': [  # nothing specific to static routes
    ]
}

TRACEROUTE_TTL = 255
TRACEROUTE_SOURCE = ''
TRACEROUTE_TIMEOUT = 2
TRACEROUTE_NULL_HOST_NAME = '*'
TRACEROUTE_NULL_IP_ADDRESS = '*'
TRACEROUTE_VRF = ''

OPTICS_NULL_LEVEL = '-Inf'

PING_SOURCE = ''
PING_TTL = 255
PING_TIMEOUT = 2
PING_SIZE = 100
PING_COUNT = 5
PING_VRF = ''
