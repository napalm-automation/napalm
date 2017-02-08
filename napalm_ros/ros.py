"""NAPALM driver for Mikrotik RouterBoard OS (ROS)"""
from __future__ import unicode_literals

# Import third party libs
from librouteros import connect
from librouteros.exceptions import TrapError
from librouteros.exceptions import FatalError
from librouteros.exceptions import ConnectionError
from librouteros.exceptions import MultiTrapError

# Import NAPALM base
from napalm_base import NetworkDriver
import napalm_base.utils.string_parsers
import napalm_base.constants as C
from napalm_base.helpers import ip as cast_ip
from napalm_base.helpers import mac as cast_mac
from napalm_base.exceptions import ConnectionException

# Import local modules
from napalm_ros.utils import to_seconds
from napalm_ros.utils import iface_addresses


class ROSDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        optional_args = optional_args or dict()
        self.port = optional_args.get('port', 8728)
        self.api = None

    def close(self):
        self.api.close()

    def is_alive(self):
        '''No ping method is exposed from API'''
        return {'is_alive': True}

    def get_arp_table(self):
        arp_table = []
        for entry in self.api('/ip/arp/print'):
            arp_table.append(
                {
                    'interface': entry['interface'],
                    'mac': cast_mac(entry['mac-address']),
                    'ip': cast_ip(entry['address']),
                    'age': float(-1),
                }
            )
        return arp_table

    def get_environment(self):
        environment = {
            'fans': {},
            'temperature': {},
            'power': {},
            'cpu': {},
            'memory': {},
        }

        system_health = self.api('/system/health/print')[0]

        if system_health.get('active-fan', 'none') != 'none':
            environment['fans'][system_health['active-fan']] = {
                'status': int(system_health.get('fan-speed', '0RPM').replace('RPM', '')) != 0,
            }

        if 'temperature' in system_health:
            environment['temperature']['board'] = {
                'temperature': float(system_health['temperature']),
                'is_alert': False,
                'is_critical': False,
            }

        if 'cpu-temperature' in system_health:
            environment['temperature']['cpu'] = {
                'temperature': float(system_health['cpu-temperature']),
                'is_alert': False,
                'is_critical': False,
            }

        for cpu_values in self.api('/system/resource/cpu/print'):
            environment['cpu'][cpu_values['cpu']] = {
                '%usage': float(cpu_values['load']),
            }

        system_resource = self.api('/system/resource/print')[0]

        total_memory = system_resource.get('total-memory')
        free_memory = system_resource.get('free-memory')
        environment['memory'] = {
            'available_ram': total_memory,
            'used_ram': int(total_memory - free_memory),
        }

        return environment

    def get_facts(self):
        resource = self.api('/system/resource/print')[0]
        identity = self.api('/system/identity/print')[0]
        routerboard = self.api('/system/routerboard/print')[0]
        interfaces = self.api('/interface/print')
        return {
            'uptime': to_seconds(resource['uptime']),
            'vendor': resource['platform'],
            'model': resource['board-name'],
            'hostname': identity['name'],
            'fqdn': u'',
            'os_version': resource['version'],
            'serial_number': routerboard.get('serial_number', ''),
            'interface_list': napalm_base.utils.string_parsers.sorted_nicely(
                tuple(iface['name'] for iface in interfaces)
            ),
        }

    def get_interfaces(self):
        interfaces = {}
        for entry in self.api('/interface/print'):
            interfaces[entry['name']] = {
                'is_up': entry['running'],
                'is_enabled': not entry['disabled'],
                'description': entry.get('comment', ''),
                'last_flapped': -1.0,
                'speed': -1,
                'mac_address': cast_mac(entry['mac-address'])
                if entry.get('mac-address') else u'',
            }
        return interfaces

    def get_interfaces_ip(self):
        interfaces_ip = {}

        ipv4_addresses = self.api('/ip/address/print')
        for ifname in (row['interface'] for row in ipv4_addresses):
            interfaces_ip.setdefault(ifname, dict())
            interfaces_ip[ifname]['ipv4'] = iface_addresses(ipv4_addresses, ifname)

        ipv6_addresses = self.api('/ip6/address/print')
        for ifname in (row['interface'] for row in ipv6_addresses):
            interfaces_ip.setdefault(ifname, dict())
            interfaces_ip[ifname]['ipv6'] = iface_addresses(ipv6_addresses, ifname)

        return interfaces_ip

    def get_ntp_servers(self):
        ntp_servers = {}
        ntp_client_values = self.api('/system/ntp/client/print')[0]
        for ntp_peer in ntp_client_values.get('server-dns-names', '').split(','):
            ntp_servers[ntp_peer] = {}
        return ntp_servers

    def get_snmp_information(self):
        communities = {}
        for row in self.api('/snmp/community/print'):
            communities[row['name']] = {
                'acl': row.get('addresses', u''),
                'mode': u'ro' if row.get('read-access') else 'rw',
            }

        snmp_values = self.api('/snmp/print')[0]

        return {
            'chassis_id': snmp_values['engine-id'],
            'community': communities,
            'contact': snmp_values['contact'],
            'location': snmp_values['location'],
        }

    def get_users(self):
        users = {}
        for row in self.api('/user/print'):
            users[row['name']] = {
                'level': 15 if row['group'] == 'full' else 0,
                'password': u'',
                'sshkeys': list()
            }
        return users

    def open(self):
        try:
            self.api = connect(
                    host=self.hostname,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout
                    )
        except (TrapError, FatalError, ConnectionError, MultiTrapError) as exc:
            raise ConnectionException(
                'Could not connect to {}:{} - [{!r}]'.format(self.hostname, self.port, exc)
            )

    def ping(self,
             destination,
             source=C.PING_SOURCE,
             ttl=C.PING_TTL,
             timeout=C.PING_TIMEOUT,
             size=C.PING_SIZE,
             count=C.PING_COUNT,
             vrf=C.PING_VRF):
        params = {
                'count': count,
                'address': destination,
                'ttl': ttl,
                'size': size,
                'count': count,
        }
        if source:
            params['src-address'] = source
        if vrf:
            params['routing-instance'] = vrf

        results = self.api('/ping', **params)

        ping_results = {
            'probes_sent': max(row['sent'] for row in results),
            'packet_loss': max(row['packet-loss'] for row in results),
            'rtt_min': min(float(row.get('min-rtt', '-1ms').replace('ms', '')) for row in results),
            'rtt_max': max(float(row.get('max-rtt', '-1ms').replace('ms', '')) for row in results),
            # Last result has calculated avg
            'rtt_avg': float(results[-1:][0]['avg-rtt'].replace('ms', '')),
            'rtt_stddev': float(-1),
            'results': []
        }

        for row in results:
            ping_results['results'].append(
                {
                    'ip_address': cast_ip(row['host']),
                    'rtt': float(row.get('time', '-1ms').replace('ms', '')),
                }
            )

        return dict(success=ping_results)

    def _system_package_enabled(self, package):
        enabled = (pkg['name'] for pkg in self.api('/system/package/print') if not pkg['disabled'])
        return package in enabled
