import re
#
from napalm_base.base import NetworkDriver
from napalm_base.exceptions import MergeConfigException, ReplaceConfigException, CommandErrorException
import napalm_base.utils.string_parsers
from yandc import mikrotik


class ROSDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.candidate_config = []
        self.merge_config = False

        if isinstance(optional_args, dict):
            self.snmp_community = optional_args.get('snmp_community', None)
            self.snmp_port = optional_args.get('snmp_port', 161)

    def cli(self, *commands):
        cli_output = {}
        for command in commands:
            kwargs = {}
            if command[0] == '/':
                run_command = command
            else:
                find_index = command.find('=/')
                if find_index == -1:
                    raise CommandErrorException('Invalid command - [{}]'.format(command))
                option, run_command = command.split('=/', 1)
                if option == 'cache':
                    kwargs['use_cache'] = True
                run_command = '/{}'.format(run_command)
            try:
                device_output = self.device.cli_command(run_command, **kwargs)
            except Exception as e:
                raise CommandErrorException(e)
            if len(device_output) == 1:
                if self.device.is_cli_error(device_output[0]):
                    raise CommandErrorException(device_output[0])
            cli_output[unicode(command)] = device_output
        return cli_output

    def close(self):
        if hasattr(self, 'device'):
            self.device.disconnect()
            del self.device

    def commit_config(self):
        if self.merge_config:
            self.device.configure_via_cli(self.candidate_config)
            self.discard_config()
        else:
            raise NotImplementedError

    def compare_config(self):
        config_diff = []
        if self.merge_config:
            command_list = {}
            set_commands = []
            for config_line in self.candidate_config:
                if config_line == '':
                    continue
                re_match = re.match(r'(.+)\s+(add|set)\s+(.*)$', config_line)
                if re_match is not None:
                    first_part, action, last_part = re_match.groups()
                    if action == 'add':
                        config_diff.append('+{}'.format(config_line))
                    elif action == 'set':
                        last_part = last_part.strip()
                        if last_part[0] == '[':
                            continue
                        set_kv = last_part.split()
                        thing = set_kv.pop(0)
                        get_command = ':put [{} get {}]'.format(first_part, thing)
                        command_list[get_command] = config_line
                        set_commands.append(
                            {
                                'set_command': config_line,
                                'get_command': get_command,
                                'to_set': set_kv,
                            }
                        )
            cli_output = self.cli(*[d['get_command'] for d in set_commands])

            for command in set_commands:
                set_command = command['set_command']
                get_command = command['get_command']
                kv_parts = cli_output[get_command][0].split(';')
                kv_parts.pop(0)
                as_values = self.device.parse_as_key_value(kv_parts)

                foo = []
                for key, value in self.device.parse_as_key_value(command['to_set']).iteritems():
                    if value.lstrip()[0] == '"':
                        foo.append('{}="{}"'.format(key, as_values.get(key, 'UNKNOWN')))
                    else:
                        foo.append('{}={}'.format(key, as_values.get(key, 'UNKNOWN')))
                old_set = '{} set {} {}'.format(first_part, thing, ' '.join(foo))
                if set_command != old_set:
                    config_diff.append('-{}'.format(old_set))
                    config_diff.append('+{}'.format(set_command))
        else:
            raise NotImplementedError
        return config_diff

    def discard_config(self):
        self.candidate_config = []

    def get_arp_table(self):
        cli_command = '/ip arp print without-paging terse'

        arp_table = []
        for arp_entry in self.device.print_to_values_structured(self.cli(cli_command)[cli_command]):
            if arp_entry['flags'].find('C') == -1:
                continue
            arp_table.append(
                {
                    'interface': unicode(arp_entry.get('interface')),
                    'mac': unicode(self._format_mac(arp_entry.get('mac-address'))),
                    'ip': unicode(arp_entry.get('address')),
                    'age': float(-1),
                }
            )
        return arp_table

#    def get_bgp_config(self, group='', neighbor=''):

    def get_bgp_neighbors(self):
        bgp_neighbors = {}
        if not self.device.system_package_enabled('routing'):
            return bgp_neighbors

        for routing_table, bgp_peers in self.device.index_values(self._get_bgp_peers(), 'routing-table').iteritems():
            routing_table = unicode(routing_table)
            bgp_neighbors[routing_table] = {
                'router_id': u'',
                'peers': {},
            }

            router_ids = {}
            for bgp_peer in bgp_peers:
                bgp_neighbors[routing_table]['peers'][bgp_peer['remote-address']] = {
                    'local_as': int(bgp_peer['local-as']),
                    'remote_as': int(bgp_peer['remote-as']),
                    'remote_id': unicode(bgp_peer.get('remote-id', '')),
                    'is_up': bgp_peer['state'] == 'established',
                    'is_enabled': bgp_peer['flags'].find('X') == -1,
                    'description': unicode(bgp_peer['name'].replace('"', '')),
                    'uptime': self.device.to_seconds(bgp_peer.get('uptime', '')),
                    'address_family': {
                        'ipv4': {
                            'received_prefixes': int(bgp_peer.get('prefix-count', 0)),
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
                router_ids[bgp_peer['router-id']] = True
            if len(router_ids) != 1:
                raise ValueError('Multiple router-id values seen')
            bgp_neighbors[routing_table]['router_id'] = unicode(router_ids.keys()[0])
        return bgp_neighbors

    def get_bgp_neighbors_detail(self, neighbor_address=''):
        bgp_neighbors_detail = {}
        if not self.device.system_package_enabled('routing'):
            return bgp_neighbors_detail

        for routing_table, peers in self.device.index_values(self._get_bgp_peers(), 'routing-table').iteritems():
            routing_table = unicode(routing_table)
            bgp_neighbors_detail[routing_table] = {}
            for remote_as, bgp_peers in self.device.index_values(peers, 'remote-as').iteritems():
                remote_as = int(remote_as)
                if remote_as not in bgp_neighbors_detail[routing_table]:
                    bgp_neighbors_detail[routing_table][remote_as] = []
                for bgp_peer in bgp_peers:
                    bgp_neighbors_detail[routing_table][remote_as].append(
                        {
                            'up': bgp_peer['state'] == 'established',
                            'local_as': int(bgp_peer['local-as']),
                            'remote_as': int(bgp_peer['remote-as']),
                            'router_id': unicode(bgp_peer.get('router_id', '')),
                            'local_address': unicode(bgp_peer.get('local-address')),
                            'routing_table': unicode(bgp_peer['routing-table']),
                            'local_address_configured': False,
                            'local_port': -1,
                            'remote_address': unicode(bgp_peer['remote-address']),
                            'remote_port': -1,
                            'multihop': bgp_peer['multihop'] == 'yes',
                            'multipath': False,
                            'remove_private_as': bgp_peer['remove-private-as'] == 'yes',
                            'import_policy': u'',
                            'export_policy': u'',
                            'input_messages': -1,
                            'output_messages': -1,
                            'input_updates': -1,
                            'output_updates': -1,
                            'messages_queued_out': -1,
                            'connection_state': unicode(bgp_peer['state']),
                            'previous_connection_state': u'',
                            'last_event': u'',
                            'suppress_4byte_as': bgp_peer.get('as4-capability', '') == 'no',
                            'local_as_prepend': False,
                            'holdtime': self.device.to_seconds(bgp_peer.get('used-hold-time', '')),
                            'configured_holdtime': self.device.to_seconds(bgp_peer['hold-time']),
                            'keepalive': self.device.to_seconds(bgp_peer.get('used-keepalive-time', '')),
                            'configured_keepalive': -1,
                            'active_prefix_count': -1,
                            'received_prefix_count': -1,
                            'accepted_prefix_count': -1,
                            'suppressed_prefix_count': -1,
                            'advertised_prefix_count': -1,
                            'flap_count': -1,
                        }
                    )
        return bgp_neighbors_detail

    def _get_bridge_fdb(self):
        bridge_host_print = '/interface bridge host print without-paging terse'
        bridge_host_values = self.device.index_values(
            self.device.print_to_values_structured(self.cli(bridge_host_print)[bridge_host_print]),
            'bridge'
        )

        switch_host_print = '/interface ethernet switch host print without-paging terse'
        try:
            cli_output = self.cli(switch_host_print)[switch_host_print]
        except CommandErrorException:
            switch_host_values = {}
        else:
            switch_host_values = self.device.index_values(
                self.device.print_to_values_structured(cli_output),
                'mac-address'
            )

        interface_wireless_print = '/interface wireless print without-paging terse'
        wireless_registration_print = '/interface wireless registration-table print without-paging terse'
        try:
            cli_output = self.cli(interface_wireless_print, wireless_registration_print)
        except CommandErrorException:
            wireless_registration_values = {}
        else:
            interface_wireless_values = self.device.index_values(
                self.device.print_to_values_structured(cli_output[interface_wireless_print])
            )
            wireless_registration_values = self.device.index_values(
                self.device.print_to_values_structured(cli_output[wireless_registration_print]),
                'mac-address'
            )

        bridge_fdb = {}
        for key, value in bridge_host_values.iteritems():
            bridge = unicode(key)
            if bridge not in bridge_fdb:
                bridge_fdb[bridge] = []
            for bridge_mac in value:
                if bridge_mac['flags'].find('L') != -1:
                    pass

                mac_address = bridge_mac['mac-address']

                fdb_entry = {
                    'mac_address': mac_address,
                    'interface': key,
                    'vlan': 0,
                    'static': False,
                    'active': True,
                    'moves': -1,
                    'last_move': float(self.device.to_seconds(bridge_mac['age'])),
                }

                on_interface = bridge_mac['on-interface']

                if_type = self.device.interface_type(on_interface)
                if if_type == 'ether':
                    if mac_address in switch_host_values:
                        if len(switch_host_values[mac_address]) > 2:
                            raise ValueError('Too many MAC addresses found')
                        for switch_mac in switch_host_values[mac_address]:
                            if on_interface in [switch_mac['ports'], self.device.master_port(switch_mac['ports'])]:
                                fdb_entry['interface'] = switch_mac['ports']
                                fdb_entry['static'] = switch_mac['flags'].find('D') == -1
                                fdb_entry['vlan'] = switch_mac['vlan-id']
                                break
                elif if_type == 'wlan':
                    if bridge_mac['flags'].find('L') == -1 and bridge_mac['flags'].find('E') == -1:
                        raise ValueError('External FDB flag not set')
                    if mac_address in wireless_registration_values:
                        interface = wireless_registration_values[mac_address][0]['interface']
                        fdb_entry['interface'] = interface
                        if interface_wireless_values[interface][0]['vlan-mode'] != 'no-tag':
                            fdb_entry['vlan'] = interface_wireless_values[interface][0]['vlan-id']
                else:
                    raise TypeError('Unsupported type - [{}][{}]'.format(if_type, on_interface))

                bridge_fdb[bridge].append(fdb_entry)
        return bridge_fdb

    def get_environment(self):
        system_resource_print = 'cache=/system resource print without-paging'
        system_health_print = '/system health print without-paging'
        resource_cpu_print = '/system resource cpu print without-paging terse'
        cli_output = self.cli(system_resource_print, system_health_print, resource_cpu_print)

        system_resource_values = self.device.print_to_values(cli_output[system_resource_print])
        system_health_values = self.device.print_to_values(cli_output[system_health_print])

        cpu_load = dict((cpu_values['cpu'], cpu_values['load'].rstrip('%')) for cpu_values in self.device.print_to_values_structured(cli_output[resource_cpu_print]))

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
#                'used_ram': int(resource_values.get('total-memory')) - int(system_resource_values.get('free-memory'))
            }
        }

    def get_facts(self):
        system_resource_print = '/system resource print without-paging'
        system_identity_print = '/system identity print without-paging'
        system_routerboard_print = 'cache=/system routerboard print without-paging'
        cli_output = self.cli(system_resource_print, system_identity_print, system_routerboard_print)

        system_resource_values = self.device.print_to_values(cli_output[system_resource_print])
        system_identity_values = self.device.print_to_values(cli_output[system_identity_print])
        system_routerboard_values = self.device.print_to_values(cli_output[system_routerboard_print])

        return {
            'uptime': self.device.to_seconds(system_resource_values['uptime']),
            'vendor': unicode(system_resource_values['platform']),
            'model': unicode(system_resource_values['board-name']),
            'hostname': unicode(system_identity_values['name']),
            'fqdn': u'',
            'os_version': unicode(system_resource_values['version']),
            'serial_number': unicode(system_routerboard_values['serial-number'] if system_routerboard_values['routerboard'] == 'yes' else ''),
            'interface_list': napalm_base.utils.string_parsers.sorted_nicely(self.device.interfaces())
        }

    def get_interfaces(self):
        interface_print = '/interface print without-paging terse'

        interfaces = {}
        for if_entry in self.device.print_to_values_structured(self.cli(interface_print)[interface_print]):
            if_name = unicode(if_entry['name'])
            interfaces[if_name] = {
                'is_up': if_entry['flags'].find('R') != -1,
                'is_enabled': if_entry['flags'].find('X') == -1,
                'description': unicode(if_entry.get('comment', '')),
                'last_flapped': float(self.device.to_seconds_date_time(if_entry.get('last-link-up-time', ''))),
                'speed': -1,
                'mac_address': unicode(self._format_mac(if_entry.get('mac-address', ''))),
            }
        return interfaces

    def get_interfaces_counters(self):
        interface_print_stats = '/interface print without-paging stats-detail'
        cli_output = self.cli(interface_print_stats)

        stats_detail = cli_output[interface_print_stats]
        stats_detail.pop(0)

        interface_counters = {}
        for if_counters in self.device.print_to_values_structured(self.device.print_concat(stats_detail)):
            if_name = unicode(if_counters['name'].replace('"', ''))
            if self.device.interface_type(if_name) != 'ether':
                continue
            if if_name in if_counters:
                raise ValueError('Interface already seen')
            stats_command = '/interface ethernet print without-paging stats where name ="{}"'.format(if_name)
            stats_output = self.cli(stats_command)[stats_command]
            if stats_output[0] == '':
                ether_stats = {}
            else:
                ether_stats = self.device.print_to_values(stats_output)
            interface_counters[if_name] = {
                'tx_errors': int(if_counters['tx-error'].replace(' ', '')),
                'rx_errors': int(if_counters['rx-error'].replace(' ', '')),
                'tx_discards': int(if_counters['tx-drop'].replace(' ', '')),
                'rx_discards': int(if_counters['rx-drop'].replace(' ', '')),
                'tx_octets': int(if_counters['tx-byte'].replace(' ', '')),
                'rx_octets': int(if_counters['rx-byte'].replace(' ', '')),
                'tx_unicast_packets': -1,
                'rx_unicast_packets': -1,
                'tx_multicast_packets': int(ether_stats.get('tx-multicast', '-1').replace(' ', '')),
                'rx_multicast_packets': int(ether_stats.get('rx-multicast', '-1').replace(' ', '')),
                'tx_broadcast_packets': int(ether_stats.get('tx-broadcast', '-1').replace(' ', '')),
                'rx_broadcast_packets': int(ether_stats.get('rx-broadcast', '-1').replace(' ', '')),
            }
        return interface_counters

    def get_interfaces_ip(self):
        ip_address_print = '/ip address print without-paging terse'
        ipv4_address_values = self.device.print_to_values_structured(self.cli(ip_address_print)[ip_address_print])

        interfaces_ip = {}
        for if_name, if_addresses in self.device.index_values(ipv4_address_values, 'interface').iteritems():
            if_name = unicode(if_name)
            if if_name not in interfaces_ip:
                interfaces_ip[if_name] = {
                    'ipv4': {}
                }
            for if_address in if_addresses:
                ipv4_address, prefix_length = if_address['address'].split('/', 1)
                interfaces_ip[if_name][u'ipv4'][unicode(ipv4_address)] = dict(prefix_length=int(prefix_length))

        if not self.device.system_package_enabled('ipv6'):
            return interfaces_ip

        ipv6_address_print = '/ipv6 address print without-paging terse'
        ipv6_address_values = self.device.print_to_values_structured(
            self.cli(ipv6_address_print)[ipv6_address_print]
        )

        for if_name, if_addresses in self.device.index_values(ipv6_address_values, 'interface').iteritems():
            if_name = unicode(if_name)
            if if_name not in interfaces_ip:
                interfaces_ip[if_name] = {
                    'ipv6': {}
                }
            for if_address in if_addresses:
                ipv6_address, prefix_length = if_address['address'].split('/', 1)
                if 'ipv6' not in interfaces_ip[if_name]:
                    interfaces_ip[if_name][u'ipv6'] = {}
                interfaces_ip[if_name][u'ipv6'][unicode(ipv6_address)] = dict(prefix_length=int(prefix_length))

        return interfaces_ip

    def get_lldp_neighbors(self):
        return self._get_mndp_neighbors()

    def get_lldp_neighbors_detail(self, *args, **kwargs):
        return self._get_mndp_neighbors_detail(*args, **kwargs)

#    def get_mac_address_table(self):

#    def get_ntp_peers(self):

    def get_ntp_servers(self):
        ntp_client_print = '/system ntp client print without-paging'

        ntp_client_values = self.device.print_to_values(self.cli(ntp_client_print)[ntp_client_print])
        if 'active-server' in ntp_client_values:
            return {
                ntp_client_values['active-server']: {}
            }
        return {}

#    def get_ntp_stats(self):

#    def get_probes_config(self):

#    def get_probes_results(self):

    def get_route_to(self, destination='', protocol=''):
        ip_route_print = '/ip route print without-paging terse'

        where_used = False
        if destination != '':
            ip_route_print += ' where {} in dst-address'.format(destination)
            where_used = True
        if protocol != '':
            if where_used:
                ip_route_print += ' {}'.format(protocol.lower())
            else:
                ip_route_print += 'where {}'.format(protocol.lower())

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

            if protocol != '' and route_type.lower() != protocol.lower():
                continue

            if ipv4_route['dst-address'] not in route_to:
                route_to[ipv4_route['dst-address']] = []

            protocol_attributes = {}
            if route_type == 'BGP':
                bgp_neighbor_details = self._get_bgp_peers(name=ipv4_route['received-from'])[0]
                protocol_attributes = {
                    'local_as': bgp_neighbor_details['local-as'],
                    'remote_as': int(bgp_neighbor_details['remote-as']),
                    'peer_id': bgp_neighbor_details.get('remote-id', ''),
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

            route_to[ipv4_route['dst-address']].append(
                {
                    'protocol': unicode(route_type),
                    'current_active': True,
                    'last_active': False,
                    'age': int(0),
                    'next_hop': unicode(ipv4_route.get('gateway', '')),
                    'outgoing_interface': unicode(ipv4_route.get('gateway-status', '').split()[-1]),
                    'selected_next_hop': False,
                    'preference': int(0),
                    'inactive_reason': u'',
                    'routing_table': u'',
                    'protocol_attributes': protocol_attributes
                }
            )
        return route_to

    def get_snmp_information(self):
        snmp_print = '/snmp print without-paging'
        snmp_community_print = '/snmp community print without-paging terse'
        cli_output = self.cli(snmp_print, snmp_community_print)

        snmp_values = self.device.print_to_values(cli_output[snmp_print])
        snmp_community_values = self.device.print_to_values_structured(cli_output[snmp_community_print])

        snmp_communities = {}
        for snmp_community in snmp_community_values:
            snmp_communities[unicode(snmp_community.get('name'))] = {
                'acl': unicode(snmp_community.get('addresses', '')),
                'mode': unicode('ro' if snmp_community.get('read-access', '') == 'yes' else 'rw'),
            }

        return {
            'chassis_id': unicode(snmp_values['engine-id']),
            'community': snmp_communities,
            'contact': unicode(snmp_values['contact']),
            'location': unicode(snmp_values['location']),
        }

    def get_users(self):
        user_print = '/user print without-paging terse'
        user_sshkeys_print = '/user ssh-keys print without-paging terse'
        cli_output = self.cli(user_print, user_sshkeys_print)

        user_sshkeys_values = self.device.print_to_values_structured(cli_output[user_sshkeys_print])
        user_sshkeys_values_indexed = self.device.index_values(user_sshkeys_values, 'user')

        users = {}
        for user in self.device.print_to_values_structured(cli_output[user_print]):
            users[user['name']] = {
                'level': 15 if user['group'] == 'full' else 0,
                'password': '',
                'sshkeys': [s for s in user_sshkeys_values_indexed.get(user['name'], [])]

            }
        return users

    def load_merge_candidate(self, filename=None, config=None):
        if filename is not None:
            try:
                with open(filename, 'rb') as f:
                    self.candidate_config = f.read().splitlines()
            except IOError as e:
                raise MergeConfigException(e.message)
        elif config is not None:
            self.candidate_config = config.splitlines()
        self.merge_config = True

#    def load_replace_candidate(self, filename=None, config=None):

#    def load_template(self, template_name, template_source=None, template_path=None, **template_vars):

    def open(self):
        self.device = mikrotik.ROS_Client(
            host=self.hostname,
            snmp_community=self.snmp_community,
            snmp_port=self.snmp_port,
            ssh_username=self.username,
            ssh_password=self.password
        )

    def ping(self, destination, source='', ttl=0, timeout=0, size=0, count=5):
        ping_command = '/ping {} count={}'.format(destination, 10 if count > 10 else count)
        if source != '':
            ping_command += ' src-address={}'.format(source)
        if ttl != 0:
            ping_command += ' ttl={}'.format(ttl)
        if size != 0:
            ping_command += ' size={}'.format(size)

        ping_output = self.cli(ping_command)[ping_command]
        if not ping_output.pop(0).startswith('  SEQ HOST'):
            return {
                'error': ' '.join(ping_output)
            }

        statistics = ping_output.pop().strip()
        if not len(statistics):
            statistics = ping_output.pop().strip()
        statistics = self.device.print_to_values_structured(['0 {}'.format(statistics)])[0]

        ping_results = {
            'probes_sent': int(statistics['sent']),
            'packet_loss': int(statistics['packet-loss'].rstrip('%')),
            'rtt_min': float(statistics.get('min-rtt', '-1ms').replace('ms', '')),
            'rtt_max': float(statistics.get('max-rtt', '-1ms').replace('ms', '')),
            'rtt_avg': float(statistics.get('avg-rtt', '-1ms').replace('ms', '')),
            'rtt_stddev': float(-1),
            'results': []
        }

        for ping_entry in ping_output:
            try:
                _, ip_address, _, _, rtt_ms = ping_entry.strip().split()
            except ValueError:
                continue
            ping_results['results'].append(
                {
                    'ip_address': unicode(ip_address),
                    'rtt': float(rtt_ms.replace('ms', '')),
                }
            )
        return dict(success=ping_results)

#    def rollback(self):

    def traceroute(self, destination, source='', ttl=0, timeout=0):
        num_probes = 3
        traceroute_command = '/tool traceroute address={dest} use-dns=no protocol=icmp count={probes}'.format(
            dest=destination,
            probes=num_probes
        )
        if source != '':
            traceroute_command += ' src-address={}'.format(source)
        if ttl != 0:
            traceroute_command += ' max-hops={}'.format(ttl)
        if timeout != 0:
            traceroute_command += ' timeout={}'.format(timeout)
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
                    continue
                result_index = line_parts[0]
                if result_index not in probe_results:
                    probe_results[result_index] = {
                        'probes': {}
                    }
                probe_results[result_index]['probes'][num_probes] = {
                    'rtt': float(line_parts[4].replace('ms', '')),
                    'ip_address': unicode(line_parts[1]),
                    'host_name': u''
                }
            num_probes -= 1
        return {
            'success': probe_results
        }

    def _config_sanity_check(self):
        if self.merge_config:
            config_regexp = re.compile(r'(.+)\s+(add|set)\s+(.*)$')
            for config_line in self.candidate_config:
                if config_line[0] == '#':
                    continue
                re_match = re.match(config_regexp, config_line)
                if re_match is None:
                    return False
        return True

    @staticmethod
    def _format_mac(mac_address):
        if len(mac_address) != 17:
            return mac_address
        if mac_address.find(':') == -1:
            return mac_address
        mac_parts = mac_address.replace(':', '')
        return ':'.join(list([mac_parts[:4], mac_parts[4:8], mac_parts[8:]]))

    def _get_bgp_peers(self, name=''):
        bgp_peers = []
        if not self.device.system_package_enabled('routing'):
            return bgp_peers

        peer_print_status = '/routing bgp peer print without-paging status'
        instance_print = '/routing bgp instance print without-paging terse'
        instance_vrf_print = '/routing bgp instance vrf print without-paging terse'
        cli_output = self.cli(peer_print_status, instance_print, instance_vrf_print)

        peer_status = cli_output[peer_print_status]
        peer_status.pop(0)

        instance_indexed = self.device.index_values(
            self.device.print_to_values_structured(cli_output[instance_print])
        )
        instance_vrf_indexed = self.device.index_values(
            self.device.print_to_values_structured(cli_output[instance_vrf_print])
        )

        for peer in self.device.print_to_values_structured(self.device.print_concat(peer_status)):
            if name != '' and peer['name'].replace('"', '') != name:
                continue
            peer.pop('index')
            peer_instance = peer['instance']
            if peer_instance not in instance_indexed:
                raise ValueError('No such instance - [{}]'.format(peer_instance))
            peer['router-id'] = instance_indexed[peer_instance][0]['router-id']
            peer['local-as'] = instance_indexed[peer_instance][0]['as']
            routing_table = instance_indexed[peer_instance][0]['routing-table'].replace('"', '')
            peer['routing-table'] = 'global' if routing_table == '' else routing_table
            bgp_peers.append(peer)
        return bgp_peers

    def _get_mndp_neighbors(self):
        ip_neighbor_print = '/ip neighbor print without-paging terse'

        terse_values = self.device.print_to_values_structured(self.cli(ip_neighbor_print)[ip_neighbor_print])

        mndp_neighbors = {}
        for if_name, if_neighbors in self.device.index_values(terse_values, 'interface').iteritems():
            if_name = unicode(if_name)
            if if_name not in mndp_neighbors:
                mndp_neighbors[if_name] = []
            for if_neighbor in if_neighbors:
                mndp_neighbors[if_name].append(
                    {
                        'hostname': unicode(if_neighbor['identity']),
                        'port': unicode(if_neighbor['interface-name'])
                    }
                )
        return mndp_neighbors

    def _get_mndp_neighbors_detail(self, interface=''):
        ip_neighbor_print = '/ip neighbor print without-paging terse'
        if interface != '':
            ip_neighbor_print += ' where interface ="{}"'.format(interface)

        terse_values = self.device.print_to_values_structured(self.cli(ip_neighbor_print)[ip_neighbor_print])

        mndp_neighbors_detail = {}
        for if_name, if_neighbors in self.device.index_values(terse_values, 'interface').iteritems():
            if_name = unicode(if_name)
            if if_name not in mndp_neighbors_detail:
                mndp_neighbors_detail[if_name] = []
            for if_neighbor in if_neighbors:
                mndp_neighbors_detail[if_name].append(
                    {
                        'parent_interface': u'',
                        'remote_chassis_id': unicode(self._format_mac(if_neighbor['mac-address'])),
                        'remote_system_name': unicode(if_neighbor['identity']),
                        'remote_port': unicode(if_neighbor['interface-name']),
                        'remote_port_description': u'',
                        'remote_system_description': unicode(
                            '{} {}'.format(if_neighbor['platform'], if_neighbor.get('board', ''))
                        ),
                        'remote_system_capab': u'',
                        'remote_system_enable_capab': u''
                    }
                )
        return mndp_neighbors_detail
