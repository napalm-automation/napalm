from napalm_base.base import NetworkDriver
from napalm_base.exceptions import ConnectionException, SessionLockedException, MergeConfigException, ReplaceConfigException, CommandErrorException
import napalm_base.utils
import yandc.mikrotik
import json
import re

class ROSDriver(NetworkDriver):
	def __init__(self, hostname, username, password, timeout=60, optional_args=None):
		self.device = None
		self.hostname = hostname
		self.username = username
		self.password = password
		self.timeout = timeout

		if isinstance(optional_args, dict):
			self.snmp_community = optional_args.get('snmp_community', None)
			self.snmp_port = optional_args.get('snmp_port', 161)
		
	def open(self):
		self.device = yandc.mikrotik.ROS_Client(
			host=self.hostname,
			snmp_community=self.snmp_community,
			snmp_port=self.snmp_port,
			ssh_username=self.username,
			ssh_password=self.password
		)

	def cli(self, commands=None):
		cli_output = dict()

		for command in commands:
			cli_output[unicode(command)] = self.device.ssh_command(command)

		return cli_output

	def close(self):
		self.device.disconnect()
		del self.device

	def get_arp_table(self):
		arp_table = list()
		for arp_entry in self.device.print_to_values_structured(self.device.ssh_command('/ip arp print terse without-paging')):
			arp_table.append(
				{
					unicode('interface'): arp_entry['interface'],
					unicode('mac'): arp_entry['mac-address'],
					unicode('ip'): arp_entry['address'],
					unicode('age'): -1,
				}
			)
		return arp_table

	def get_bgp_neighbors(self):
		bgp_neighbors = {}
		if not self.device.system_package_enabled('routing'):
			return bgp_neighbors


		peer_print_status = self.device.ssh_command('/routing bgp peer print status without-paging')
		peer_print_status.pop(0)
		peer_status_values = self.device.print_to_values_structured(self.device.print_concat(peer_print_status))
		peer_status_values_indexed = self.device.index_values(peer_status_values, 'instance')

		for bgp_instance in self.device.print_to_values_structured(self.device.ssh_command('/routing bgp instance print terse without-paging')):
			instance_name = bgp_instance['name']
			if instance_name in bgp_neighbors:
				raise Exception('Key already seen')
			bgp_neighbors[instance_name] = {
				'router_id': bgp_instance['router-id']
			}
			for bgp_peer in peer_status_values_indexed[instance_name]:
				bgp_neighbors[instance_name][bgp_peer['remote-address']] = {
					'local_as': bgp_instance['as'],
					'remote_as': bgp_peer['remote-as'],
					'remote_id': bgp_peer['remote-id'],
					'is_up': bgp_peer['state'] == 'established',
					'is_enabled': bgp_peer['flags'].find('X') == -1,
					'description': bgp_peer['name'].replace('"', ''),
					'uptime': self.device.to_seconds(bgp_peer['uptime']),
					'address_family': {
						'ipv4': {
							'received_prefixes': bgp_peer['prefix-count'],
							'accepted_prefixes': 0,
							'sent_prefixes': 0
						},
						'ipv6': {
							'received_prefixes': 0,
							'accepted_prefixes': 0,
							'sent_prefixes': 0
						}
					}
				}
		return bgp_neighbors

	def get_bgp_neighbors_detail(self, neighbor_address=''):
		pass

	def get_environment(self):
		system_resource_values = self.device.print_to_values(self.device.ssh_command('/system resource print without-paging'))
		system_health_values = self.device.print_to_values(self.device.ssh_command('/system health print without-paging'))

		cpu_load = dict((v['cpu'], v['load'].rstrip('%')) for v in self.device.print_to_values_structured(self.device.ssh_command('/system resource cpu print terse without-paging')))
		print cpu_load

		return {
			'fans': {
				'location': {
					'status': False
				}
			},
			'temperature': {
				'board': {
					'temperature': float(system_health_values.get('temperature', '-1.0').rstrip('C')),
					'is_alert': False,
					'is_critical': False,
				}
			},
			'power': {
				'main': {
					'status': True,
					'capacity': 0.0,
					'output': float(system_health_values.get('voltage', '0.0').rstrip('V'))
				}
			},
			'cpu': cpu_load,
			'memory': {
				'available_ram': float(re.sub('[KM]iB$', '', system_resource_values.get('total-memory'))),
#				'used_ram': int(system_resource_values.get('total-memory')) - int(system_resource_values.get('free-memory'))
			}
		}

	def get_facts(self):
		system_resource = self.device.print_to_values(self.device.ssh_command('/system resource print without-paging'))
		system_identity = self.device.print_to_values(self.device.ssh_command('/system identity print without-paging'))
		system_routerboard = self.device.print_to_values(self.device.ssh_command('/system routerboard print without-paging'))

		return {
			'uptime': self.device.to_seconds(system_resource['uptime']),
			'vendor': system_resource['platform'],
			'model': system_resource['board-name'],
			'hostname': system_identity['name'],
			'fqdn': '',
			'os_version': system_resource['version'],
			'serial_number': system_routerboard['serial-number'] if system_routerboard['routerboard'] == 'yes' else '',
			'interface_list': napalm_base.utils.string_parsers.sorted_nicely(self.device.interfaces())
		}

	def get_interfaces(self):
		interfaces = {}
		for if_entry in self.device.print_to_values_structured(self.device.ssh_command('/interface print terse without-paging')):
			interfaces[unicode(if_entry['name'])] = {
				'is_up': if_entry['flags'].find('R') != -1,
				'is_enabled': if_entry['flags'].find('X') == -1,
				'description': if_entry.get('comment', ''),
				'last_flapped': self.device.to_seconds_date_time(if_entry.get('last-link-up-time', '')),
				'speed': -1,
				'mac_address': if_entry.get('mac-address', '')
			}
		return interfaces

	def get_interfaces_counters(self):
		stats_detail = self.device.ssh_command('interface print stats-detail without-paging')
		stats_detail.pop(0)

		interface_counters = {}
		for if_counters in self.device.print_to_values_structured(self.device.print_concat(stats_detail)):
			if_name = unicode(if_counters['name'].replace('"', ''))
			if if_name in if_counters:
				raise Exception('Interface already seen')
			interface_counters[if_name] = {
				'tx_errors': int(if_counters['tx-error'].replace(' ', '')),
				'rx_errors': int(if_counters['rx-error'].replace(' ', '')),
				'tx_discards': int(if_counters['tx-drop'].replace(' ', '')),
				'rx_discards': int(if_counters['rx-drop'].replace(' ', '')),
				'tx_octets': int(if_counters['tx-byte'].replace(' ', '')),
				'rx_octets': int(if_counters['rx-byte'].replace(' ', '')),
				'tx_unicast_packets': -1,
				'rx_unicast_packets': -1,
				'tx_multicast_packets': -1,
				'rx_multicast_packets': -1,
				'tx_broadcast_packets': -1,
				'rx_broadcast_packets': -1
			}
		return interface_counters

	def get_interfaces_ip(self):
		ipv4_address_values = self.device.print_to_values_structured(self.device.ssh_command('/ip address print terse without-paging'))
		ipv6_address_values = self.device.print_to_values_structured(self.device.ssh_command('/ipv6  address print terse without-paging'))

		interfaces_ip = {}
		for key, value in self.device.index_values(ipv4_address_values, 'interface').iteritems():
			if_name = unicode(key)
			if not if_name in interfaces_ip:
				interfaces_ip[if_name] = {
					u'ipv4': {}
				}
			for v in value:
				ipv4_address, prefix_length = v['address'].split('/', 1)
				interfaces_ip[if_name][u'ipv4'][unicode(ipv4_address)] = dict(prefix_length=int(prefix_length))

		for key, value in self.device.index_values(ipv6_address_values, 'interface').iteritems():
			if_name = unicode(key)
			if not if_name in interfaces_ip:
				interfaces_ip[if_name] = {
					u'ipv6': {}
				}
			for v in value:
				ipv6_address, prefix_length = v['address'].split('/', 1)
				if not u'ipv6' in interfaces_ip[if_name]:
					interfaces_ip[if_name][u'ipv6'] = {}
				interfaces_ip[if_name][u'ipv6'][unicode(ipv6_address)] = dict(prefix_length=int(prefix_length))

		return interfaces_ip

	def get_lldp_neighbors(self):
		terse_values = self.device.print_to_values_structured(self.device.ssh_command('/ip neighbor print terse without-paging'))

		lldp_neighbors = {}
		for key, value in self.device.index_values(terse_values, 'interface').iteritems():
			if_name = unicode(key)
			if if_name in lldp_neighbors:
				raise Exception('Key already seen')
			lldp_neighbors[if_name] = []
			for v in value:
				lldp_neighbors[if_name].append(
					{
						'hostname': unicode(v['identity']),
						'port': unicode(v['interface-name'])
					}
				)
		return lldp_neighbors

	def get_lldp_neighbors_detail(self, interface=''):
		ip_neighbor_command = '/ip neighbor print terse without-paging'
		if interface != '':
			ip_neighbor_command += ' where interface="{}"'.format(interface)
		terse_values = self.device.print_to_values_structured(self.device.ssh_command(ip_neighbor_command))

		lldp_neighbors_detail = {}
		for key, value in self.device.index_values(terse_values, 'interface').iteritems():
			if_name = unicode(key)
			if if_name in lldp_neighbors_detail:
				raise Exception('Key already seen')
			lldp_neighbors_detail[if_name] = []
			for v in value:
				lldp_neighbors_detail[if_name].append(
					{
						'parent_interface': None,
						'remote_chassis_id': v['mac-address'],
						'remote_system_name': v['identity'],
						'remote_port': v['interface-name'],
						'remote_port_description': '',
						'remote_system_description': '{} {}'.format(v['platform'], v['board']),
						'remote_system_capab': None,
						'remote_system_enable_capab': None
					}
				)
		return lldp_neighbors_detail

	def get_mac_address_table(self):
		mac_address_table = []
		for mac_entry in self.device.print_to_values_structured(self.device.ssh_command('/interface ethernet switch host print terse without-paging')):
			mac_address_table.append(
				{
					'mac': mac_entry['mac-address'],
					'interface': mac_entry['ports'],
					'vlan': mac_entry.get('vlan-id', 0),
					'static': mac_entry['flags'].find('D') == -1,
					'active': True,
					'moves': -1,
					'last_move': 0.0
				}
			)
		return mac_address_table

	def get_snmp_information(self):
		snmp_values = self.device.print_to_values(self.device.ssh_command('/snmp print without-paging'))
		snmp_community_values = self.device.print_to_values_structured(self.device.ssh_command('/snmp community print terse without-paging'))

		snmp_communities = {}
		for v in snmp_community_values:
			snmp_communities[unicode(v.get('name'))] = {
				'acl': unicode(v.get('addresses', '')),
				'mode': 'ro' if v.get('read-access', '') == 'yes' else 'rw'
			}

		return {
			'chassis_id': unicode(snmp_values.get('engine-id', '')),
			'community': snmp_communities,
			'contact': unicode(snmp_values.get('contact', '')),
			'location': unicode(snmp_values.get('location', ''))
		}

	def get_users(self):
		user_sshkeys_values = self.device.print_to_values_structured(self.device.ssh_command('/user ssh-keys print terse without-paging'))
		user_sshkeys_values_indexed = self.device.index_values(user_sshkeys_values, 'user')

		users = {}
		for u in self.device.print_to_values_structured(self.device.ssh_command('/user print terse without-paging')):
			users[u['name']] = {
				'level': 15 if u['group'] == 'full' else 0,
				'password': '',
				'sshkeys': [s for s in user_sshkeys_values_indexed.get(u['name'], [])]

			}
		return users

	def load_merge_candidate(self, filename=None, config=None):
		pass

	def load_replace_candidate(self, filename=None, config=None):
		pass

	def load_template(self, template_name, template_source=None, template_path=None, **template_vars):
		pass

	def ping(destination, source='', ttl=0, timeout=0, size=0, count=0):
		pass

	def rollback(self):
		pass

	def traceroute(self, destination, source='', ttl=0, timeout=0):
		pass
