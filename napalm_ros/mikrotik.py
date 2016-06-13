from napalm_base.base import NetworkDriver
import yandca.mikrotik
import json
import re

class ROSDriver(NetworkDriver):
	def __init__(self, hostname, username, password, timeout=60, optional_args=None):
		self.device = None
		self.hostname = hostname
		self.username = username
		self.password = password
		self.timeout = timeout

		if 'snmp_community' in optional_args:
			self.snmp_community = optional_args['snmp_community']
		if 'snmp_port' in optional_args:
			self.snmp_port = optional_args['snmp_port']
		
	def open(self):
		self.device = yandca.mikrotik.ROS_Client(
			host=self.hostname,
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
		arp_show_command = ':put [/ip arp print as-value]'
		cli_output = self.cli([arp_show_command])

		arp_table = list()
		for arp_entry in self.device.values_decode(cli_output.get(arp_show_command)[0]):
			arp_table.append(
				{
					unicode('interface'): arp_entry.get('interface'),
					unicode('mac'): arp_entry.get('mac-address'),
					unicode('ip'): arp_entry.get('address'),
					unicode('age'): -1,
				}
			)

		return arp_table

	def get_bgp_neighbors(self):
		pass

	def get_environment(self):
		system_resource = self.device.system_resource()
		system_health = self.device.system_health()

		cpu_load = {}
		for i in self.device.system_resource_cpu():
			cpu_load[i.get('cpu')] = {
				'%usage': i.get('load', -1)
			}

		return {
			'fans': {
				'location': {
					'status': False
				}
			},
			'temperature': {
				'board': {
					'temperature': system_health.get('temperature', -1.0),
					'is_alert': False,
					'is_critical': False,
				}
			},
			'power': {
				'main': {
					'status': True,
					'capacity': 0.0,
					'output': system_health.get('voltage', 0.0)
				}
			},
			'cpu': cpu_load,
			'memory': {
				'available_ram': int(system_resource.get('total-memory')),
				'used_ram': int(system_resource.get('total-memory')) - int(system_resource.get('free-memory'))
			}
		}

	def get_facts(self):
		system_routerboard_command = ':put [/system routerboard print as-value]'
		system_identity_command = ':put [/system identity print as-value]'
		cli_output = self.cli([system_routerboard_command, system_identity_command])
		system_resource = self.device.system_resource()

		return {
			'uptime': system_resource.get('uptime'),
			'vendor': system_resource.get('platform'),
			'model': system_resource.get('board-name'),
			'hostname': '',
			'fqdn': '',
			'os_version': system_resource.get('version'),
			'serial_number': None,
			'interface_list': []
		}

	def get_interfaces(self):
		pass

	def get_interfaces_counters(self):
		pass

	def get_lldp_neighbors(self):
		pass

	def get_lldp_neighbors_detail(self):
		pass

	def get_snmp_information(self):
		snmp_command = ':put [/snmp print as-value]'
		snmp_community_command = ':put [/snmp community print as-value]'
		cli_output = self.cli([snmp_command, snmp_community_command])
		snmp_values = self.device.values_decode(cli_output.get(snmp_command)[0])[0]
		snmp_community_values = self.device.values_decode(cli_output.get(snmp_community_command)[0])
		print snmp_community_values

		snmp_communities = {}
		for comm in snmp_community_values:
			snmp_communities[unicode(comm.get('name'))] = {
				'acl': unicode(comm.get('addresses', '')),
				'mode': 'ro' if comm.get('read-access', '') == 'true' else 'rw'
			}

		return {
			'chassis_id': unicode(snmp_values.get('engine-id', '')),
			'community': snmp_communities,
			'contact': unicode(snmp_values.get('contact', '')),
			'location': unicode(snmp_values.get('location', ''))
		}

	def get_users(self):
		user_command = ':put [/user print as-value]'
		user_sshkeys_command = ':put [/user ssh-keys print as-value]'
		cli_output = self.cli([user_command, user_sshkeys_command])
		user_values = self.device.values_decode(cli_output.get(user_command)[0])
		user_sshkeys_values = self.device.values_decode(cli_output.get(user_sshkeys_command)[0])
		print user_sshkeys_values

		users = {}
		for user in user_values:
			users[user.get('name')] = {
				'level': 15 if user.get('group') == 'full' else 0,
				'password': None,
				'sshkeys': []

			}
		return users
