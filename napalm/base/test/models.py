alive = {"is_alive": bool}

facts = {
    "os_version": str,
    "uptime": int,
    "interface_list": list,
    "vendor": str,
    "serial_number": str,
    "model": str,
    "hostname": str,
    "fqdn": str,
}

interface = {
    "is_up": bool,
    "is_enabled": bool,
    "description": str,
    "last_flapped": float,
    "mtu": int,
    "speed": int,
    "mac_address": str,
}

lldp_neighbors = {"hostname": str, "port": str}

interface_counters = {
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
}

temperature = {"is_alert": bool, "is_critical": bool, "temperature": float}

power = {"status": bool, "output": float, "capacity": float}

memory = {"used_ram": int, "available_ram": int}

fan = {"status": bool}

cpu = {"%usage": float}

peer = {
    "is_enabled": bool,
    "uptime": int,
    "remote_as": int,
    "description": str,
    "remote_id": str,
    "local_as": int,
    "is_up": bool,
    "address_family": dict,
}

af = {"sent_prefixes": int, "accepted_prefixes": int, "received_prefixes": int}

lldp_neighbors_detail = {
    "parent_interface": str,
    "remote_port": str,
    "remote_chassis_id": str,
    "remote_port_description": str,
    "remote_system_name": str,
    "remote_system_description": str,
    "remote_system_capab": list,
    "remote_system_enable_capab": list,
}

bgp_config_group = {
    "type": str,
    "description": str,
    "apply_groups": list,
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
}

bgp_config_neighbor = {
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
}

peer_details = {
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
}

arp_table = {"interface": str, "mac": str, "ip": str, "age": float}

ipv6_neighbor = {"interface": str, "mac": str, "ip": str, "age": float, "state": str}

ntp_peer = {
    # will populate it in the future wit potential keys
}

ntp_server = {
    # will populate it in the future wit potential keys
}

ntp_stats = {
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
}

interfaces_ip = {"prefix_length": int}

mac_address_table = {
    "mac": str,
    "interface": str,
    "vlan": int,
    "static": bool,
    "active": bool,
    "moves": int,
    "last_move": float,
}

route = {
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
}

snmp = {"chassis_id": str, "community": dict, "contact": str, "location": str}

snmp_community = {"acl": str, "mode": str}

probe_test = {
    "probe_type": str,
    "target": str,
    "source": str,
    "probe_count": int,
    "test_interval": int,
}

probe_test_results = {
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
}

ping = {
    "probes_sent": int,
    "packet_loss": int,
    "rtt_min": float,
    "rtt_max": float,
    "rtt_avg": float,
    "rtt_stddev": float,
    "results": list,
}

ping_result = {"ip_address": str, "rtt": float}

traceroute = {"rtt": float, "ip_address": str, "host_name": str}

users = {"level": int, "password": str, "sshkeys": list}

optics_state = {"instant": float, "avg": float, "min": float, "max": float}

config = {"running": str, "startup": str, "candidate": str}

network_instance = {"name": str, "type": str, "state": dict, "interfaces": dict}

network_instance_state = {"route_distinguisher": str}

network_instance_interfaces = {"interface": dict}

firewall_policies = {
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
}

vlan = {"name": str, "interfaces": list}
