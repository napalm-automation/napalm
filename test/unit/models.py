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