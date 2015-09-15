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
