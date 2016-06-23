#from napalm_base.base import NetworkDriver
from napalm_base.exceptions import ConnectionException, SessionLockedException, MergeConfigException, ReplaceConfigException, CommandErrorException
import napalm_base.utils.string_parsers
from napalm_snmp.snmp import SNMPDriver as NetworkDriver
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
		
	def cli(self, *commands):
		cli_output = {}
		for command in commands:
			try:
				ssh_output = self.device.ssh_command(command)
			except Exception as e:
				raise CommandErrorException(e.messsage)
			if len(ssh_output) == 1:
				re_match = re.match(r'[^\(]+\(line \d+ column \d+\)', ssh_output[0])
				if re_match is not None:
					raise CommandErrorException(ssh_output[0])
			cli_output[unicode(command)] = ssh_output
		return cli_output

	def close(self):
		self.device.disconnect()
		del self.device

	def commit_config(self):
		return NotImplementedError('commit_config()')

	def compare_config(self):
		return NotImplementedError('compare_config()')

	def discard_config(self):
		return NotImplementedError('discard_config()')

	@staticmethod
	def format_mac(mac_address):
		if len(mac_address) != 17:
			return mac_address
		if not mac_address.find(':'):
			return mac_address
		mac_parts = mac_address.replace(':', '')
		return ':'.join(list([mac_parts[:4], mac_parts[4:8], mac_parts[8:]]))

	def get_arp_table(self):
		cli_command = '/ip arp print terse without-paging'

		arp_table = []
		for arp_entry in self.device.print_to_values_structured(self.cli(cli_command)[cli_command]):
			arp_table.append(
				{
					unicode('interface'): arp_entry['interface'],
					unicode('mac'): self.format_mac(arp_entry['mac-address']),
					unicode('ip'): arp_entry['address'],
					unicode('age'): -1,
				}
			)
		return arp_table

	def get_bgp_config(self, group='', neighbor=''):
		raise NotImplementedError('get_bgp_config()')

	def get_bgp_neighbors(self):
		bgp_neighbors = {}
		if not self.device.system_package_enabled('routing'):
			return bgp_neighbors

		bgp_peer_print = '/routing bgp peer print status without-paging'
		bgp_instance_print = '/routing bgp instance print terse without-paging'
		cli_output = self.cli(bgp_peer_print, bgp_instance_print)

		peer_print_status = cli_output[bgp_peer_print]
		peer_print_status.pop(0)
		peer_status_values = self.device.print_to_values_structured(self.device.print_concat(peer_print_status))
		peer_status_values_indexed = self.device.index_values(peer_status_values, 'instance')

		for bgp_instance in self.device.print_to_values_structured(cli_output[bgp_instance_print]):
			routing_table = bgp_instance['routing-table'].replace('"', '')
			if routing_table == '':
				routing_table = 'global'
			if not routing_table in bgp_neighbors:
				bgp_neighbors[routing_table] = {
					'router_id': bgp_instance['router-id']
				}
			for bgp_peer in peer_status_values_indexed[bgp_instance['name']]:
				if bgp_peer['remote-address'] in bgp_neighbors[routing_table]:
					raise Exception('Peer already seen')
				bgp_neighbors[routing_table][bgp_peer['remote-address']] = {
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
		bgp_neighbors_detail = {}
		if not self.device.system_package_enabled('routing'):
			return bgp_neighbors_detail

		bgp_peer_print = '/routing bgp peer print status without-paging'
		if neighbor_address != '':
			bgp_peer_print += ' where name ="{}"'.format(neighbor_address)
		bgp_instance_print = '/routing bgp instance print terse without-paging'
		cli_output = self.cli(bgp_peer_print, bgp_instance_print)

		peer_print_status = cli_output[bgp_peer_print]
		peer_print_status.pop(0)

		bgp_instances = self.device.index_values(self.device.print_to_values_structured(cli_output[bgp_instance_print]), 'name')

		for bgp_peer in self.device.print_to_values_structured(self.device.print_concat(peer_print_status)):
			bgp_instance = bgp_instances[bgp_peer['instance']][0]
			remote_as = bgp_peer['remote-as']
			if not remote_as in bgp_neighbors_detail:
				bgp_neighbors_detail[remote_as] = []
			bgp_neighbors_detail[remote_as].append(
				{
					'up': bgp_peer['state'] == 'established',
					'local_as': bgp_instance['as'],
					'remote_as': bgp_peer['remote-as'],
					'local_address': bgp_peer['local-address'],
					'routing_table': bgp_instance['routing-table'].replace('"', ''),
					'local_address_configured': '',
					'local_port': -1,
					'remote_address': bgp_peer['remote-address'],
					'remote_port': -1,
					'multihop': bgp_peer['multihop'] == 'yes',
					'multipath': False,
					'remove_private_as': bgp_peer['remove-private-as'] == 'yes',
					'import_policy': '',
					'export_policy': '',
					'input_messages': -1,
					'output_messages': -1,
					'input_updates': -1,
					'output_updates': -1,
					'messages_queued_out': -1,
					'connection_state': bgp_peer['state'],
					'previous_connection_state': '',
					'last_event': '',
					'suppress_4byte_as': bgp_peer['as4-capability'] == 'no',
					'local_as_prepend': False,
					'holdtime': self.device.to_seconds(bgp_peer['used-hold-time']),
					'configured_holdtime': self.device.to_seconds(bgp_peer['hold-time']),
					'keepalive': self.device.to_seconds(bgp_peer['used-keepalive-time']),
					'configured_keepalive': -1,
					'active_prefix_count': -1,
					'received_prefix_count': -1,
					'accepted_prefix_count': -1,
					'suppressed_prefix_count': -1,
					'advertised_prefix_count': -1,
					'flap_count': -1,
					'_remote_id': bgp_peer['remote-id'],
				}
			)
		return bgp_neighbors_detail

	def get_environment(self):
		system_resource_print = '/system resource print without-paging'
		system_health_print = '/system health print without-paging'
		resource_cpu_print = '/system resource cpu print terse without-paging'
		cli_output = self.cli(system_resource_print, system_health_print, resource_cpu_print)

		resource_values = self.device.print_to_values(cli_output[system_resource_print])
		health_values = self.device.print_to_values(cli_output[system_health_print])

		cpu_load = dict((v['cpu'], v['load'].rstrip('%')) for v in self.device.print_to_values_structured(cli_output[resource_cpu_print]))

		return {
			'fans': {
				'location': {
					'status': False
				}
			},
			'temperature': {
				'board': {
					'temperature': float(health_values.get('temperature', '-1.0').rstrip('C')),
					'is_alert': False,
					'is_critical': False,
				}
			},
			'power': {
				'main': {
					'status': True,
					'capacity': 0.0,
					'output': float(health_values.get('voltage', '0.0').rstrip('V'))
				}
			},
			'cpu': cpu_load,
			'memory': {
				'available_ram': float(re.sub('[KM]iB$', '', resource_values.get('total-memory'))),
#				'used_ram': int(resource_values.get('total-memory')) - int(resource_values.get('free-memory'))
			}
		}

	def get_facts(self):
		system_resource_print = '/system resource print without-paging'
		system_identity_print = '/system identity print without-paging'
		system_routerboard_print = '/system routerboard print without-paging'
		cli_output = self.cli(system_resource_print, system_identity_print, system_routerboard_print)

		system_resource_values = self.device.print_to_values(cli_output[system_resource_print])
		system_identity_values = self.device.print_to_values(cli_output[system_identity_print])
		system_routerboard_values = self.device.print_to_values(cli_output[system_routerboard_print])

		return {
			'uptime': self.device.to_seconds(system_resource_values['uptime']),
			'vendor': system_resource_values['platform'],
			'model': system_resource_values['board-name'],
			'hostname': system_identity_values['name'],
			'fqdn': '',
			'os_version': system_resource_values['version'],
			'serial_number': system_routerboard_values['serial-number'] if system_routerboard_values['routerboard'] == 'yes' else '',
			'interface_list': napalm_base.utils.string_parsers.sorted_nicely(self.device.interfaces())
		}

	def get_interfaces(self):
		interface_print = '/interface print terse without-paging'

		interfaces = {}
		for if_entry in self.device.print_to_values_structured(self.cli(interface_print)[interface_print]):
			interfaces[unicode(if_entry['name'])] = {
				'is_up': if_entry['flags'].find('R') != -1,
				'is_enabled': if_entry['flags'].find('X') == -1,
				'description': if_entry.get('comment', ''),
				'last_flapped': self.device.to_seconds_date_time(if_entry.get('last-link-up-time', -1)),
				'speed': -1,
				'mac_address': self.format_mac(if_entry.get('mac-address', ''))
			}
		return interfaces

	def get_interfaces_counters(self):
		interface_print_stats = 'interface print stats-detail without-paging'

		stats_detail = self.cli(interface_print_stats)[interface_print_stats]
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
		ip_address_print = '/ip address print terse without-paging'
		ipv6_address_print = '/ipv6 address print terse without-paging'
		cli_output = self.cli(ip_address_print, ipv6_address_print)

		ipv4_address_values = self.device.print_to_values_structured(cli_output[ip_address_print])

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

		ipv6_address_values = self.device.print_to_values_structured(cli_output[ipv6_address_print])

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
		return self.get_mndp_neighbors()

	def get_lldp_neighbors_detail(self, *args, **kwargs):
		return self.get_mndp_neighbors_detail(*args, **kwargs)

	def get_mac_address_table(self):
		switch_host_print = '/interface ethernet switch host print terse without-paging'

		mac_address_table = []
		try:
			cli_output = self.cli(switch_host_print)
		except CommandErrorException as e:
			return mac_address_table

		for mac_entry in self.device.print_to_values_structured(cli_output[switch_host_print]):
			mac_address_table.append(
				{
					'mac': self.format_mac(mac_entry['mac-address']),
					'interface': mac_entry['ports'],
					'vlan': mac_entry.get('vlan-id', 0),
					'static': mac_entry['flags'].find('D') == -1,
					'active': True,
					'moves': -1,
					'last_move': 0.0
				}
			)
		return mac_address_table

	def get_mndp_neighbors(self):
		ip_neighbor_print = '/ip neighbor print terse without-paging'

		terse_values = self.device.print_to_values_structured(self.cli(ip_neighbor_print)[ip_neighbor_print])

		mndp_neighbors = {}
		for key, value in self.device.index_values(terse_values, 'interface').iteritems():
			if_name = unicode(key)
			if if_name in mndp_neighbors:
				raise Exception('Key already seen')
			mndp_neighbors[if_name] = []
			for v in value:
				mndp_neighbors[if_name].append(
					{
						'hostname': unicode(v['identity']),
						'port': unicode(v['interface-name'])
					}
				)
		return mndp_neighbors

	def get_mndp_neighbors_detail(self, interface=''):
		ip_neighbor_print = '/ip neighbor print terse without-paging'
		if interface != '':
			ip_neighbor_print += ' where interface ="{}"'.format(interface)

		terse_values = self.device.print_to_values_structured(self.cli(ip_neighbor_print)[ip_neighbor_print])

		mndp_neighbors_detail = {}
		for key, value in self.device.index_values(terse_values, 'interface').iteritems():
			if_name = unicode(key)
			if if_name in mndp_neighbors_detail:
				raise Exception('Key already seen')
			mndp_neighbors_detail[if_name] = []
			for v in value:
				mndp_neighbors_detail[if_name].append(
					{
						'parent_interface': u'',
						'remote_chassis_id': self.format_mac(v['mac-address']),
						'remote_system_name': v['identity'],
						'remote_port': v['interface-name'],
						'remote_port_description': '',
						'remote_system_description': '{} {}'.format(v['platform'], v.get('board', '')),
						'remote_system_capab': u'',
						'remote_system_enable_capab': u''
					}
				)
		return mndp_neighbors_detail

	def get_ntp_peers(self):
		ntp_client_print = '/system ntp client print without-paging'

		ntp_client_values = self.device.print_to_values(self.cli(ntp_client_print)[ntp_client_print])
		if 'active-server' in ntp_client_values:
			return {
				ntp_client_values['active-server']: {}
			}
		return {}

	def get_ntp_stats(self):
		raise NotImplementedError('get_ntp_stats()')

	def get_probes_config(self):
		raise NotImplementedError('get_probes_config')

	def get_probes_results(self):
		raise NotImplementedError('get_probes_results()')

	def get_route_to(self, destination='', protocol=''):
		ip_route_print = '/ip route print terse without-paging'
		if destination != '':
			ip_route_print += ' where dst-address ="{}"'.format(destination)

		route_to = {}
		for ipv4_route in self.device.print_to_values_structured(self.cli(ip_route_print)[ip_route_print]):
			route_type = None
			if ipv4_route['flags'].find('b') != -1:
				route_type = 'BGP'
			elif ipv4_route['flags'].find('C') != -1:
				route_type = 'connected'
			elif ipv4_route['flags'].find('o') != -1:
				route_type = 'OSPF'
			elif ipv4_route['flags'].find('S') != -1:
				route_type = 'static'

			if protocol != '' and route_type != protocol:
				continue

			protocol_attributes = {}
			if route_type == 'BGP':
				bgp_neighbor_details = self.get_bgp_neighbors_detail(ipv4_route['received-from'])[ipv4_route['bgp-as-path']][0]
				protocol_attributes = {
					'local_as': bgp_neighbor_details['local_as'],
					'remote_as': bgp_neighbor_details['remote_as'],
					'peer_id': bgp_neighbor_details.get('_remote_id', ''),
					'as_path': ipv4_route['bgp-as-path'],
					'communities': [unicode(c) for c in ipv4_route.get('bgp-communities', '').split(',') if len(c)],
					'local_preference': ipv4_route.get('bgp-local-pref', 100),
					'preference2': -1,
					'metric': ipv4_route.get('bgp-med', 0),
					'metric2': -1
				}
			elif route_type == 'connected':
				protocol_attributes['gateway_status'] = ipv4_route['gateway-status']
				protocol_attributes['preferred_source'] = ipv4_route.get('pref-src', '')
			elif route_type == 'OSPF':
				pass
			elif route_type == 'static':
				if ipv4_route['flags'].find('B') != -1:
					protocol_attributes['blackhole'] = True
				protocol_attributes['gateway_status'] = ipv4_route.get('gateway-status', '')
				protocol_attributes['metric'] = ipv4_route['distance']

			route_to[ipv4_route['dst-address']] = {
				'next_hop': ipv4_route.get('gateway', ''),
				'protocol': route_type,
				'protocol_attributes': protocol_attributes
			}
		return route_to

	def get_snmp_information(self):
		snmp_print = '/snmp print without-paging'
		snmp_community_print = '/snmp community print terse without-paging'
		cli_output = self.cli(snmp_print, snmp_community_print)

		snmp_values = self.device.print_to_values(cli_output[snmp_print])
		snmp_community_values = self.device.print_to_values_structured(cli_output[snmp_community_print])

		snmp_communities = {}
		for v in snmp_community_values:
			snmp_communities[unicode(v.get('name'))] = {
				'acl': unicode(v.get('addresses', '')),
				'mode': 'ro' if v.get('read-access', '') == 'yes' else 'rw'
			}

		return {
			'chassis_id': unicode(snmp_values['engine-id']),
			'community': snmp_communities,
			'contact': unicode(snmp_values['contact']),
			'location': unicode(snmp_values['location'])
		}

	def get_users(self):
		user_print = '/user print terse without-paging'
		user_sshkeys_print = '/user ssh-keys print terse without-paging'
		cli_output = self.cli(user_print, user_sshkeys_print)

		user_sshkeys_values = self.device.print_to_values_structured(cli_output[user_sshkeys_print])
		user_sshkeys_values_indexed = self.device.index_values(user_sshkeys_values, 'user')

		users = {}
		for u in self.device.print_to_values_structured(cli_output[user_print]):
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

	def open(self):
		self.device = yandc.mikrotik.ROS_Client(
			host=self.hostname,
			snmp_community=self.snmp_community,
			snmp_port=self.snmp_port,
			ssh_username=self.username,
			ssh_password=self.password
		)

	def ping(self, destination, source='', ttl=0, timeout=0, size=0, count=5):
		ping_command = '/ping {} count={}'.format(destination, 10 if count > 10 else count)
		if source != '':
			ping_command + ' src-address={}'.format(source)
		if ttl != 0:
			ping_command + ' ttl={}'.format(ttl)
		if size != 0:
			ping_command + ' size={}'.format(size)

		ping_output = self.cli(ping_command)[ping_command]
		ping_output.pop(0)

		statistics = ping_output.pop().lstrip().rstrip()
		if not len(statistics):
			statistics = ping_output.pop().lstrip().rstrip()
		statistics = self.device.print_to_values_structured(['0 {}'.format(statistics)])[0]

		ret_ = {
			'probes_sent': statistics['sent'],
			'packet_loss': statistics['packet-loss'].rstrip('%'),
			'rtt_min': statistics.get('min-rtt', '-1ms').replace('ms', ''),
			'rtt_max': statistics.get('max-rtt', '-1ms').replace('ms', ''),
			'rtt_avg': statistics.get('avg-rtt', '-1ms').replace('ms', ''),
			'rtt_stddev': -1,
			'results': []
		}
		for ping_entry in ping_output:
			entry_parts = ping_entry.lstrip().rstrip().split()
			if len(entry_parts) != 5:
				continue
			ret_['results'].append(
				{
					'ip_address': entry_parts[1],
					'rtt': entry_parts[4].replace('ms', '')
				}
			)
		return ret_

	def rollback(self):
		pass

	def traceroute(self, destination, source='', ttl=0, timeout=0):
		num_probes = 3
		traceroute_command = '/tool traceroute address={dest} use-dns=no protocol=icmp count={probes}'.format(dest=destination, probes=num_probes)
		if source != '':
			pass
		if ttl != 0:
			pass
		if timeout !=0:
			pass
		traceroute_output = self.device.ssh_client.exec_command(traceroute_command)

		last_line = traceroute_output.pop()
		if last_line != '':
			traceroute_output.append(last_line)
			return {
				'error': ' '.join([l.lstrip() for l in traceroute_output])
				}

		probe_results = {}
		while num_probes:
			while True:
				try:
					line = traceroute_output.pop()
				except IndexError:
					break
				if line == '':
					break
				line_parts = line.split()
				if len(line_parts) < 8:
					print line_parts
					continue
				result_index = line_parts[0]
				if not result_index in probe_results:
					probe_results[result_index] = {
						'probes': {}
					}
				probe_results[result_index]['probes'][num_probes] = {
					'rtt': line_parts[4],
					'ip_address': line_parts[1],
					'host_name': ''
				}
			num_probes -= 1
		return {
			'success': probe_results
		}
