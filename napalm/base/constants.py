"""Constants to be used across NAPALM drivers."""

CONFIG_LOCK = True  # must be changed soon!
TIMEOUT = 60  # seconds

INTERFACE_NULL_SPEED = -1

ACTION_TYPE_METHODS = ("ping", "traceroute")

BGP_NEIGHBOR_NULL_COUNTER = -1

SNMP_AUTHORIZATION_MODE_MAP = {"read-only": "ro", "read-write": "rw"}

ROUTE_COMMON_PROTOCOL_FIELDS = [
    "destination",
    "prefix_length",
    "protocol",
    "current_active",
    "last_active",
    "age",
    "next_hop",
    "outgoing_interface",
    "selected_next_hop",
    "preference",
    "inactive_reason",
    "routing_table",
]  # identifies the list of fileds common for all protocols

ROUTE_PROTOCOL_SPECIFIC_FIELDS = {
    "bgp": [
        "local_as",
        "remote_as",
        "as_path",
        "communities",
        "local_preference",
        "preference2",
        "remote_address",
        "metric",
        "metric2",
    ],
    "isis": ["level", "metric", "local_as"],
    "static": [],  # nothing specific to static routes
}

TRACEROUTE_TTL = 255
TRACEROUTE_SOURCE = ""
TRACEROUTE_TIMEOUT = 2
TRACEROUTE_NULL_HOST_NAME = "*"
TRACEROUTE_NULL_IP_ADDRESS = "*"
TRACEROUTE_VRF = ""

OPTICS_NULL_LEVEL = "-Inf"

PING_SOURCE = ""
PING_TTL = 255
PING_TIMEOUT = 2
PING_SIZE = 100
PING_COUNT = 5
PING_VRF = ""

NETMIKO_MAP = {
    "ios": "cisco_ios",
    "nxos": "cisco_nxos",
    "nxos_ssh": "cisco_nxos",
    "iosxr": "cisco_iosxr",
    "eos": "arista_eos",
    "junos": "juniper_eos",
}
LLDP_CAPAB_TRANFORM_TABLE = {
    "o": "other",
    "p": "repeater",
    "b": "bridge",
    "w": "wlan-access-point",
    "r": "router",
    "t": "telephone",
    "c": "docsis-cable-device",
    "s": "station",
}

CISCO_SANITIZE_FILTERS = {
    r"^(snmp-server community).*$": r"\1 <removed>",
    r"^(snmp-server host \S+( vrf \S+)?( version (1|2c|3))?)\s+\S+((\s+\S*)*)\s*$": r"\1 <removed> \5",  # noqa
    r"^(snmp-server user \S+( \S+)? auth md5) \S+ (priv) \S+ (localizedkey( engineID \S+)?)\s*$": r"\1 <removed> \3 <removed> \4\5",  # noqa
    r"^(username .+ (password|secret) \d) .+$": r"\1 <removed>",
    r"^(enable (password|secret)( level \d+)? \d) .+$": r"\1 <removed>",
    r"^(\s+(?:password|secret)) (?:\d )?\S+$": r"\1 <removed>",
    r"^(.*wpa-psk ascii \d) (\S+)$": r"\1 <removed>",
    r"^(.*key 7) (\d.+)$": r"\1 <removed>",
    r"^(tacacs-server (.+ )?key) .+$": r"\1 <removed>",
    r"^(crypto isakmp key) (\S+) (.*)$": r"\1 <removed> \3",
    r"^(\s+ip ospf message-digest-key \d+ md5) .+$": r"\1 <removed>",
    r"^(\s+ip ospf authentication-key) .+$": r"\1 <removed>",
    r"^(\s+neighbor \S+ password) .+$": r"\1 <removed>",
    r"^(\s+vrrp \d+ authentication text) .+$": r"\1 <removed>",
    r"^(\s+standby \d+ authentication) .{1,8}$": r"\1 <removed>",
    r"^(\s+standby \d+ authentication md5 key-string) .+?( timeout \d+)?$": r"\1 <removed> \2",
    r"^(\s+key-string) .+$": r"\1 <removed>",
    r"^((tacacs|radius) server [^\n]+\n(\s+[^\n]+\n)*\s+key) [^\n]+$": r"\1 <removed>",
    r"^(\s+ppp (chap|pap) password \d) .+$": r"\1 <removed>",
}
