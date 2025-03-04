from typing import Dict, List

from typing_extensions import TypedDict

ConfigurationDict = TypedDict(
    "ConfigurationDict", {"running": str, "candidate": str, "startup": str}
)

AliveDict = TypedDict("AliveDict", {"is_alive": bool})

FactsDict = TypedDict(
    "FactsDict",
    {
        "os_version": str,
        "uptime": float,
        "interface_list": List,
        "vendor": str,
        "serial_number": str,
        "model": str,
        "hostname": str,
        "fqdn": str,
    },
)

InterfaceDict = TypedDict(
    "InterfaceDict",
    {
        "is_up": bool,
        "is_enabled": bool,
        "description": str,
        "last_flapped": float,
        "mtu": int,
        "speed": float,
        "mac_address": str,
    },
)

LLDPNeighborDict = TypedDict("LLDPNeighborDict", {"hostname": str, "port": str})

LLDPNeighborDetailDict = TypedDict(
    "LLDPNeighborDetailDict",
    {
        "parent_interface": str,
        "remote_port": str,
        "remote_chassis_id": str,
        "remote_port_description": str,
        "remote_system_name": str,
        "remote_system_description": str,
        "remote_system_capab": List,
        "remote_system_enable_capab": List,
    },
)

LLDPNeighborsDetailDict = Dict[str, List[LLDPNeighborDetailDict]]

InterfaceCounterDict = TypedDict(
    "InterfaceCounterDict",
    {
        "tx_errors": int,
        "rx_errors": int,
        "tx_discards": int,
        "rx_discards": int,
        "tx_octets": int,
        "rx_octets": int,
        "tx_unicast_packets": int,
        "rx_unicast_packets": int,
        "tx_multicast_packets": int,
        "rx_multicast_packets": int,
        "tx_broadcast_packets": int,
        "rx_broadcast_packets": int,
    },
)

TemperatureDict = TypedDict(
    "TemperatureDict", {"is_alert": bool, "is_critical": bool, "temperature": float}
)

PowerDict = TypedDict("PowerDict", {"status": bool, "output": float, "capacity": float})

MemoryDict = TypedDict("MemoryDict", {"used_ram": int, "available_ram": int})

FanDict = TypedDict("FanDict", {"status": bool})

CPUDict = TypedDict("CPUDict", {"%usage": float})

EnvironmentDict = TypedDict(
    "EnvironmentDict",
    {
        "fans": Dict[str, FanDict],
        "temperature": Dict[str, TemperatureDict],
        "power": Dict[str, PowerDict],
        "cpu": Dict[int, CPUDict],
        "memory": MemoryDict,
    },
)

PeerDict = TypedDict(
    "PeerDict",
    {
        "is_enabled": bool,
        "uptime": int,
        "remote_as": int,
        "description": str,
        "remote_id": str,
        "local_as": int,
        "is_up": bool,
        "address_family": dict,
    },
)

PeerDetailsDict = TypedDict(
    "PeerDetailsDict",
    {
        "up": bool,
        "local_as": int,
        "remote_as": int,
        "router_id": str,
        "local_address": str,
        "routing_table": str,
        "local_address_configured": bool,
        "local_port": int,
        "remote_address": str,
        "remote_port": int,
        "multihop": bool,
        "multipath": bool,
        "remove_private_as": bool,
        "import_policy": str,
        "export_policy": str,
        "input_messages": int,
        "output_messages": int,
        "input_updates": int,
        "output_updates": int,
        "messages_queued_out": int,
        "connection_state": str,
        "previous_connection_state": str,
        "last_event": str,
        "suppress_4byte_as": bool,
        "local_as_prepend": bool,
        "holdtime": int,
        "configured_holdtime": int,
        "keepalive": int,
        "configured_keepalive": int,
        "active_prefix_count": int,
        "received_prefix_count": int,
        "accepted_prefix_count": int,
        "suppressed_prefix_count": int,
        "advertised_prefix_count": int,
        "flap_count": int,
    },
)

AFDict = TypedDict(
    "AFDict", {"sent_prefixes": int, "accepted_prefixes": int, "received_prefixes": int}
)

BGPConfigGroupDict = TypedDict(
    "BGPConfigGroupDict",
    {
        "type": str,
        "description": str,
        "apply_groups": List,
        "multihop_ttl": int,
        "multipath": bool,
        "local_address": str,
        "local_as": int,
        "remote_as": int,
        "import_policy": str,
        "export_policy": str,
        "remove_private_as": bool,
        "prefix_limit": dict,
        "neighbors": dict,
    },
)

BGPConfigNeighborDict = TypedDict(
    "BGPConfigNeighborDict",
    {
        "description": str,
        "import_policy": str,
        "export_policy": str,
        "local_address": str,
        "authentication_key": str,
        "nhs": bool,
        "route_reflector_client": bool,
        "local_as": int,
        "remote_as": int,
        "prefix_limit": dict,
    },
)

BGPStateAddressFamilyDict = TypedDict(
    "BGPStateAddressFamilyDict",
    {"received_prefixes": int, "accepted_prefixes": int, "sent_prefixes": int},
)

BGPStateNeighborDict = TypedDict(
    "BGPStateNeighborDict",
    {
        "local_as": int,
        "remote_as": int,
        "remote_id": str,
        "is_up": bool,
        "is_enabled": bool,
        "description": str,
        "uptime": int,
        "address_family": Dict[str, BGPStateAddressFamilyDict],
    },
)

BGPStateNeighborsPerVRFDict = TypedDict(
    "BGPStateNeighborsPerVRFDict",
    {"router_id": str, "peers": Dict[str, BGPStateNeighborDict]},
)

ARPTableDict = TypedDict(
    "ARPTableDict", {"interface": str, "mac": str, "ip": str, "age": float}
)

IPV6NeighborDict = TypedDict(
    "IPV6NeighborDict",
    {"interface": str, "mac": str, "ip": str, "age": float, "state": str},
)

NTPPeerDict = TypedDict(
    "NTPPeerDict",
    {},
    total=False,
)

NTPServerDict = TypedDict(
    "NTPServerDict",
    {
        "address": str,
        "port": int,
        "version": int,
        "association_type": str,
        "iburst": bool,
        "prefer": bool,
        "network_instance": str,
        "source_address": str,
        "key_id": int,
    },
    total=False,
)

NTPStats = TypedDict(
    "NTPStats",
    {
        "remote": str,
        "referenceid": str,
        "synchronized": bool,
        "stratum": int,
        "type": str,
        "when": str,
        "hostpoll": int,
        "reachability": int,
        "delay": float,
        "offset": float,
        "jitter": float,
    },
)

InterfacesIPDictEntry = TypedDict(
    "InterfacesIPDictEntry", {"prefix_length": int}, total=False
)

InterfacesIPDict = TypedDict(
    "InterfacesIPDict",
    {
        "ipv4": Dict[str, InterfacesIPDictEntry],
        "ipv6": Dict[str, InterfacesIPDictEntry],
    },
    total=False,
)

MACAdressTable = TypedDict(
    "MACAdressTable",
    {
        "mac": str,
        "interface": str,
        "vlan": int,
        "static": bool,
        "active": bool,
        "moves": int,
        "last_move": float,
    },
)

RouteDict = TypedDict(
    "RouteDict",
    {
        "protocol": str,
        "current_active": bool,
        "last_active": bool,
        "age": int,
        "next_hop": str,
        "outgoing_interface": str,
        "selected_next_hop": bool,
        "preference": int,
        "inactive_reason": str,
        "routing_table": str,
        "protocol_attributes": dict,
    },
)

SNMPDict = TypedDict(
    "SNMPDict", {"chassis_id": str, "community": dict, "contact": str, "location": str}
)

SNMPCommunityDict = TypedDict("SNMPCommunityDict", {"acl": str, "mode": str})

ProbeTestDict = TypedDict(
    "ProbeTestDict",
    {
        "probe_type": str,
        "target": str,
        "source": str,
        "probe_count": int,
        "test_interval": int,
    },
)

ProbeTestResultDict = TypedDict(
    "ProbeTestResultDict",
    {
        "target": str,
        "source": str,
        "probe_type": str,
        "probe_count": int,
        "rtt": float,
        "round_trip_jitter": float,
        "last_test_loss": int,
        "current_test_min_delay": float,
        "current_test_max_delay": float,
        "current_test_avg_delay": float,
        "last_test_min_delay": float,
        "last_test_max_delay": float,
        "last_test_avg_delay": float,
        "global_test_min_delay": float,
        "global_test_max_delay": float,
        "global_test_avg_delay": float,
    },
)

PingResultDictEntry = TypedDict(
    "PingResultDictEntry", {"ip_address": str, "rtt": float}
)

PingDict = TypedDict(
    "PingDict",
    {
        "probes_sent": int,
        "packet_loss": int,
        "rtt_min": float,
        "rtt_max": float,
        "rtt_avg": float,
        "rtt_stddev": float,
        "results": list,
    },
)

PingResultDict = TypedDict(
    "PingResultDict",
    {"success": PingDict, "error": str},
    total=False,
)

TracerouteDict = TypedDict(
    "TracerouteDict", {"rtt": float, "ip_address": str, "host_name": str}
)

TracerouteResultDictEntry = TypedDict(
    "TracerouteResultDictEntry", {"probes": Dict[int, TracerouteDict]}, total=False
)

TracerouteResultDict = TypedDict(
    "TracerouteResultDict",
    {"success": Dict[int, TracerouteResultDictEntry], "error": str},
    total=False,
)

UsersDict = TypedDict("UsersDict", {"level": int, "password": str, "sshkeys": List})

OpticsStateDict = TypedDict(
    "OpticsStateDict", {"instant": float, "avg": float, "min": float, "max": float}
)

OpticsStatePerChannelDict = TypedDict(
    "OpticsStatePerChannelDict",
    {
        "input_power": OpticsStateDict,
        "output_power": OpticsStateDict,
        "laser_bias_current": OpticsStateDict,
    },
)

OpticsPerChannelDict = TypedDict(
    "OpticsPerChannelDict", {"index": int, "state": OpticsStatePerChannelDict}
)

OpticsPhysicalChannelsDict = TypedDict(
    "OpticsPhysicalChannelsDict", {"channels": OpticsPerChannelDict}
)

OpticsDict = TypedDict("OpticsDict", {"physical_channels": OpticsPhysicalChannelsDict})

ConfigDict = TypedDict("ConfigDict", {"running": str, "startup": str, "candidate": str})

NetworkInstanceDict = TypedDict(
    "NetworkInstanceDict", {"name": str, "type": str, "state": dict, "interfaces": dict}
)

NetworkInstanceStateDict = TypedDict(
    "NetworkInstanceStateDict", {"route_distinguisher": str}
)

NetworkInstanceInterfacesDict = TypedDict(
    "NetworkInstanceInterfacesDict", {"interface": dict}
)

FirewallPolicyDict = TypedDict(
    "FirewallPolicyDict",
    {
        "position": int,
        "packet_hits": int,
        "byte_hits": int,
        "id": str,
        "enabled": bool,
        "schedule": str,
        "log": str,
        "l3_src": str,
        "l3_dst": str,
        "service": str,
        "src_zone": str,
        "dst_zone": str,
        "action": str,
    },
)

VlanDict = TypedDict("VlanDict", {"name": str, "interfaces": List})

DictValidationResult = TypedDict(
    "DictValidationResult",
    {"complies": bool, "present": Dict, "missing": List, "extra": List},
)

ListValidationResult = TypedDict(
    "ListValidationResult",
    {"complies": bool, "present": List, "missing": List, "extra": List},
)

ReportResult = TypedDict("ReportResult", {"complies": bool, "skipped": List})
