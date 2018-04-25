
# text_type is 'unicode' for py2 and 'str' for py3
from napalm.base.utils.py23_compat import text_type

alive = {
    'is_alive': bool
}

facts = {
    'os_version': text_type,
    'uptime': int,
    'interface_list': list,
    'vendor': text_type,
    'serial_number': text_type,
    'model': text_type,
    'hostname': text_type,
    'fqdn': text_type
}

interface = {
    'is_up': bool,
    'is_enabled': bool,
    'description': text_type,
    'last_flapped': float,
    'speed': int,
    'mac_address': text_type,
}

lldp_neighbors = {
    'hostname': text_type,
    'port': text_type,
}

interface_counters = {
    'tx_errors': int,
    'rx_errors': int,
    'tx_discards': int,
    'rx_discards': int,
    'tx_octets': int,
    'rx_octets': int,
    'tx_unicast_packets': int,
    'rx_unicast_packets': int,
    'tx_multicast_packets': int,
    'rx_multicast_packets': int,
    'tx_broadcast_packets': int,
    'rx_broadcast_packets': int,
}

temperature = {
    'is_alert': bool,
    'is_critical': bool,
    'temperature': float,
}

power = {
    'status': bool,
    'output': float,
    'capacity': float
}

memory = {
    'used_ram': int,
    'available_ram': int,
}

fan = {
    'status': bool,
}

cpu = {
    '%usage': float,
}

peer = {
    'is_enabled': bool,
    'uptime': int,
    'remote_as': int,
    'description': text_type,
    'remote_id': text_type,
    'local_as': int,
    'is_up': bool,
    'address_family': dict,
}

af = {
    'sent_prefixes': int,
    'accepted_prefixes': int,
    'received_prefixes': int
}

lldp_neighbors_detail = {
    'parent_interface': text_type,
    'remote_port': text_type,
    'remote_chassis_id': text_type,
    'remote_port_description': text_type,
    'remote_system_name': text_type,
    'remote_system_description': text_type,
    'remote_system_capab': text_type,
    'remote_system_enable_capab': text_type
}

bgp_config_group = {
    'type': text_type,
    'description': text_type,
    'apply_groups': list,
    'multihop_ttl': int,
    'multipath': bool,
    'local_address': text_type,
    'local_as': int,
    'remote_as': int,
    'import_policy': text_type,
    'export_policy': text_type,
    'remove_private_as': bool,
    'prefix_limit': dict,
    'neighbors': dict
}

bgp_config_neighbor = {
    'description': text_type,
    'import_policy': text_type,
    'export_policy': text_type,
    'local_address': text_type,
    'authentication_key': text_type,
    'nhs': bool,
    'route_reflector_client': bool,
    'local_as': int,
    'remote_as': int,
    'prefix_limit': dict
}

peer_details = {
    'up': bool,
    'local_as': int,
    'remote_as': int,
    'router_id': text_type,
    'local_address': text_type,
    'routing_table': text_type,
    'local_address_configured': bool,
    'local_port': int,
    'remote_address': text_type,
    'remote_port': int,
    'multihop': bool,
    'multipath': bool,
    'remove_private_as': bool,
    'import_policy': text_type,
    'export_policy': text_type,
    'input_messages': int,
    'output_messages': int,
    'input_updates': int,
    'output_updates': int,
    'messages_queued_out': int,
    'connection_state': text_type,
    'previous_connection_state': text_type,
    'last_event': text_type,
    'suppress_4byte_as': bool,
    'local_as_prepend': bool,
    'holdtime': int,
    'configured_holdtime': int,
    'keepalive': int,
    'configured_keepalive': int,
    'active_prefix_count': int,
    'received_prefix_count': int,
    'accepted_prefix_count': int,
    'suppressed_prefix_count': int,
    'advertised_prefix_count': int,
    'flap_count': int
}

arp_table = {
    'interface': text_type,
    'mac': text_type,
    'ip': text_type,
    'age': float
}

ipv6_neighbor = {
    'interface': text_type,
    'mac': text_type,
    'ip': text_type,
    'age': float,
    'state': text_type
}

ntp_peer = {
    # will populate it in the future wit potential keys
}

ntp_server = {
    # will populate it in the future wit potential keys
}

ntp_stats = {
    'remote': text_type,
    'referenceid': text_type,
    'synchronized': bool,
    'stratum': int,
    'type': text_type,
    'when': text_type,
    'hostpoll': int,
    'reachability': int,
    'delay': float,
    'offset': float,
    'jitter': float
}

interfaces_ip = {
    'prefix_length': int
}

mac_address_table = {
    'mac': text_type,
    'interface': text_type,
    'vlan': int,
    'static': bool,
    'active': bool,
    'moves': int,
    'last_move': float
}

route = {
    'protocol': text_type,
    'current_active': bool,
    'last_active': bool,
    'age': int,
    'next_hop': text_type,
    'outgoing_interface': text_type,
    'selected_next_hop': bool,
    'preference': int,
    'inactive_reason': text_type,
    'routing_table': text_type,
    'protocol_attributes': dict
}

snmp = {
    'chassis_id': text_type,
    'community': dict,
    'contact': text_type,
    'location': text_type
}

snmp_community = {
    'acl': text_type,
    'mode': text_type,
}

probe_test = {
    'probe_type': text_type,
    'target': text_type,
    'source': text_type,
    'probe_count': int,
    'test_interval': int
}

probe_test_results = {
    'target': text_type,
    'source': text_type,
    'probe_type': text_type,
    'probe_count': int,
    'rtt': float,
    'round_trip_jitter': float,
    'last_test_loss': int,
    'current_test_min_delay': float,
    'current_test_max_delay': float,
    'current_test_avg_delay': float,
    'last_test_min_delay': float,
    'last_test_max_delay': float,
    'last_test_avg_delay': float,
    'global_test_min_delay': float,
    'global_test_max_delay': float,
    'global_test_avg_delay': float
}

ping = {
    'probes_sent': int,
    'packet_loss': int,
    'rtt_min': float,
    'rtt_max': float,
    'rtt_avg': float,
    'rtt_stddev': float,
    'results': list
}

ping_result = {
    'ip_address': text_type,
    'rtt': float
}

traceroute = {
    'rtt': float,
    'ip_address': text_type,
    'host_name': text_type
}

users = {
    'level': int,
    'password': text_type,
    'sshkeys': list
}

optics_state = {
    'instant': float,
    'avg': float,
    'min': float,
    'max': float
}

config = {
    'running': text_type,
    'startup': text_type,
    'candidate': text_type,
}

network_instance = {
    'name': text_type,
    'type': text_type,
    'state': dict,
    'interfaces': dict,
}

network_instance_state = {
    'route_distinguisher': text_type,
}

network_instance_interfaces = {
    'interface': dict,
}

firewall_policies = {
    'position': int,
    'packet_hits': int,
    'byte_hits': int,
    'id': text_type,
    'enabled': bool,
    'schedule': text_type,
    'log': text_type,
    'l3_src': text_type,
    'l3_dst': text_type,
    'service': text_type,
    'src_zone': text_type,
    'dst_zone': text_type,
    'action': text_type
}
