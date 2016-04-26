facts = {
    'os_version': unicode,
    'uptime': int,
    'interface_list': list,
    'vendor': unicode,
    'serial_number': unicode,
    'model': unicode,
    'hostname': unicode,
    'fqdn': unicode
}
interface = {
    'is_up': bool,
    'is_enabled': bool,
    'description': unicode,
    'last_flapped': float,
    'speed': int,
    'mac_address': unicode,
}

lldp_neighbors = {
    'hostname': unicode,
    'port': unicode,
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
    'description': unicode,
    'remote_id': unicode,
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
    'parent_interface'          : unicode,
    'remote_port'               : unicode,
    'remote_chassis_id'         : unicode,
    'remote_port'               : unicode,
    'remote_port_description'   : unicode,
    'remote_system_name'        : unicode,
    'remote_system_description' : unicode,
    'remote_system_capab'       : unicode,
    'remote_system_enable_capab': unicode
}

bgp_config_group = {
    'type'              : unicode,
    'description'       : unicode,
    'apply_groups'      : list,
    'multihop_ttl'      : int,
    'multipath'         : bool,
    'local_address'     : unicode,
    'local_as'          : int,
    'remote_as'         : int,
    'import_policy'     : unicode,
    'export_policy'     : unicode,
    'remove_private_as' : bool,
    'prefix_limit'      : dict,
    'neighbors'         : dict
}

bgp_config_neighbor = {
    'description'           : unicode,
    'import_policy'         : unicode,
    'export_policy'         : unicode,
    'local_address'         : unicode,
    'authentication_key'    : unicode,
    'nhs'                   : bool,
    'route_reflector_client': bool,
    'local_as'              : int,
    'remote_as'             : int,
    'prefix_limit'          : dict
}

peer_details = {
    'up'                        : bool,
    'local_as'                  : int,
    'remote_as'                 : int,
    'local_address'             : unicode,
    'routing_table'             : unicode,
    'local_address_configured'  : bool,
    'local_port'                : int,
    'remote_address'            : unicode,
    'remote_port'               : int,
    'multihop'                  : bool,
    'multipath'                 : bool,
    'remove_private_as'         : bool,
    'import_policy'             : unicode,
    'export_policy'             : unicode,
    'input_messages'            : int,
    'output_messages'           : int,
    'input_updates'             : int,
    'output_updates'            : int,
    'messages_queued_out'       : int,
    'connection_state'          : unicode,
    'previous_connection_state' : unicode,
    'last_event'                : unicode,
    'suppress_4byte_as'         : bool,
    'local_as_prepend'          : bool,
    'holdtime'                  : int,
    'configured_holdtime'       : int,
    'keepalive'                 : int,
    'configured_keepalive'      : int,
    'active_prefix_count'       : int,
    'received_prefix_count'     : int,
    'accepted_prefix_count'     : int,
    'suppressed_prefix_count'   : int,
    'advertise_prefix_count'    : int,
    'flap_count'                : int
}

arp_table = {
    'interface' : unicode,
    'mac'       : unicode,
    'ip'        : unicode,
    'age'       : float
}

ntp_peer = {
    # will populate it in the future wit potential keys
}

ntp_stats = {
    'remote'        : unicode,
    'referenceid'   : unicode,
    'synchronized'  : bool,
    'stratum'       : int,
    'type'          : unicode,
    'when'          : unicode,
    'hostpoll'      : int,
    'reachability'  : int,
    'delay'         : float,
    'offset'        : float,
    'jitter'        : float
}

interfaces_ip = {
    'prefix_length': int
}

mac_address_table = {
    'mac'       : unicode,
    'interface' : unicode,
    'vlan'      : int,
    'static'    : bool,
    'active'    : bool,
    'moves'     : int,
    'last_move' : float
}

route = {
    'protocol'           : unicode,
    'current_active'     : bool,
    'last_active'        : bool,
    'age'                : int,
    'next_hop'           : unicode,
    'outgoing_interface' : unicode,
    'selected_next_hop'  : bool,
    'preference'         : int,
    'inactive_reason'    : unicode,
    'routing_table'      : unicode,
    'protocol_attributes': dict
}

snmp = {
    'chassis_id'        : unicode,
    'community'         : dict,
    'contact'           : unicode,
    'location'          : unicode
}

snmp_community = {
    'acl'               : unicode,
    'mode'              : unicode,
}

probe_test = {
    'probe_type'    : unicode,
    'target'        : unicode,
    'source'        : unicode,
    'probe_count'   : int,
    'test_interval' : int
}

probe_test_results = {
    'target'                : unicode,
    'source'                : unicode,
    'probe_type'            : unicode,
    'probe_count'           : int,
    'rtt'                   : float,
    'round_trip_jitter'     : float,
    'last_test_loss'        : int,
    'current_test_min_delay': float,
    'current_test_max_delay': float,
    'current_test_avg_delay': float,
    'last_test_min_delay'   : float,
    'last_test_max_delay'   : float,
    'last_test_avg_delay'   : float,
    'global_test_min_delay' : float,
    'global_test_max_delay' : float,
    'global_test_avg_delay' : float
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
    'ip_address': unicode,
    'rtt': float
}

traceroute = {
    'rtt': float,
    'ip_address': unicode,
    'host_name': unicode
}

users = {
    'level': int,
    'password': str,
    'sshkeys': list
}
