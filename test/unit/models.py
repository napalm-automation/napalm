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
