import datetime
import re
#
from napalm_base.base import NetworkDriver
from napalm_base.exceptions import MergeConfigException, ReplaceConfigException, CommandErrorException
import napalm_base.utils.string_parsers
from yandc import ROS_Client


class ROSDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.candidate_config = []
        self.config_session = None
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
            if len(device_output) == 1 and device_output[0] != '':
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
            merge_command = '/import file-name="{}.rsc" verbose=no'.format(self.config_session)
            self.device.safe_mode_toggle()
            cli_output = self.cli(merge_command)[merge_command]
            self.device.safe_mode_toggle()
            if cli_output[-1] != 'Script file loaded and executed successfully':
                pass
            self.discard_config()

#    def compare_config(self):

    def discard_config(self):
        self.candidate_config = []
        self.cli('/file print without-paging terse', '/file remove "{}.rsc"'.format(self.config_session))

    def get_arp_table(self):
        cli_command = '/ip arp print without-paging terse'

        arp_table = []
        for arp_entry in self.device.print_to_values_structured(self.cli(cli_command)[cli_command]):
            if arp_entry['flags'].find('C') == -1:
                continue
            arp_table.append(
                {
                    'interface': unicode(arp_entry.get('interface')),
                    'mac': napalm_base.helpers.mac(arp_entry.get('mac-address').replace(':', '')),
                    'ip': napalm_base.helpers.ip(arp_entry.get('address')),
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
                bgp_neighbors[routing_table]['peers'][napalm_base.helpers.ip(bgp_peer['remote-address'])] = {
                    'local_as': int(bgp_peer['local-as']),
                    'remote_as': int(bgp_peer['remote-as']),
                    'remote_id': napalm_base.helpers.ip(bgp_peer.get('remote-id', '')),
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
            bgp_neighbors[routing_table]['router_id'] = napalm_base.helpers.ip(router_ids.keys()[0])
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
                            'router_id': napalm_base.helpers.ip(bgp_peer.get('router_id', '')),
                            'local_address': napalm_base.helpers.ip(bgp_peer.get('local-address')),
                            'routing_table': unicode(bgp_peer['routing-table']),
                            'local_address_configured': False,
                            'local_port': -1,
                            'remote_address': napalm_base.helpers.ip(bgp_peer['remote-address']),
                            'remote_port': -1,
                            'multihop': bgp_peer['multihop'] == 'yes',
                            'multipath': False,
                            'remove_private_as': bgp_peer['remove-private-as'] == 'yes',
                            'import_policy': u'',
                            'export_policy': u'',
                            'input_messages': -1,
                            'output_messages': -1,
                            'input_updates': int(bgp_peer.get('updates-received', -1)),
                            'output_updates': int(bgp_peer.get('updates-sent', -1)),
                            'messages_queued_out': -1,
                            'connection_state': unicode(bgp_peer['state']),
                            'previous_connection_state': u'',
                            'last_event': u'',
                            'suppress_4byte_as': bgp_peer.get('as4-capability', '') == 'no',
                            'local_as_prepend': False,
                            'holdtime': self.device.to_seconds(bgp_peer.get('used-hold-time', '')),
                            'configured_holdtime': self.device.to_seconds(bgp_peer.get('hold-time', '3m')),
                            'keepalive': self.device.to_seconds(bgp_peer.get('used-keepalive-time', '')),
                            'configured_keepalive': self.device.to_seconds(bgp_peer.get('keepalive-time', '1m')),
                            'active_prefix_count': -1,
                            'received_prefix_count': int(bgp_peer.get('prefix-count', 0)),
                            'accepted_prefix_count': -1,
                            'suppressed_prefix_count': -1,
                            'advertised_prefix_count': -1,
                            'flap_count': -1,
                        }
                    )
        return bgp_neighbors_detail

    def get_environment(self):
        system_resource_print = 'cache=/system resource print without-paging'
        system_health_print = '/system health print without-paging'
        resource_cpu_print = '/system resource cpu print without-paging terse'
        cli_output = self.cli(system_resource_print, system_health_print, resource_cpu_print)

        system_resource_values = self.device.print_to_values(cli_output[system_resource_print])
        system_health_values = self.device.print_to_values(cli_output[system_health_print])

        environment = {
            'fans': {},
            'temperature': {},
            'power': {},
            'cpu': {},
            'memory': {},
        }

        if 'active-fan' in system_health_values:
            environment['fans'][system_health_values['active-fan']] = {
                'status': int(system_health_values.get('fan-speed', '0RPM').replace('RPM', '')) != 0,
            }

        if 'temperature' in system_health_values:
            environment['temperature']['board'] = {
                'temperature': float(system_health_values['temperature'].rstrip('C')),
                'is_alert': False,
                'is_critical': False,
            }

        if 'cpu-temperature' in system_health_values:
            environment['temperature']['cpu'] = {
                'temperature': float(system_health_values['cpu-temperature'].rstrip('C')),
                'is_alert': False,
                'is_critical': False,
            }

        for cpu_values in self.device.print_to_values_structured(cli_output[resource_cpu_print]):
            environment['cpu'][cpu_values['cpu']] = {
                '%usage': float(cpu_values['load'].rstrip('%')),
            }

        total_memory = int(float(re.sub('[KM]iB$', '', system_resource_values.get('total-memory'))))
        free_memory = float(re.sub('[KM]iB$', '', system_resource_values.get('free-memory')))
        environment['memory'] = {
                'available_ram': total_memory,
                'used_ram': int(total_memory - free_memory),
        }

        return environment

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
            'serial_number': unicode(system_routerboard_values['serial-number'] \
                if system_routerboard_values['routerboard'] == 'yes' else ''),
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
                'mac_address': napalm_base.helpers.mac(if_entry.get('mac-address', '')),
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
                interfaces_ip[if_name][u'ipv4'][napalm_base.helpers.ip(ipv4_address)] = dict(prefix_length=int(prefix_length))

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
                interfaces_ip[if_name][u'ipv6'][napalm_base.helpers.ip(ipv6_address)] = dict(prefix_length=int(prefix_length))

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
                    'current_active': ipv4_route['flags'].find('X') == -1,
                    'last_active': False,
                    'age': int(0),
                    'next_hop': napalm_base.helpers.ip(ipv4_route.get('gateway', '')),
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
                with open(filename, 'rU') as file_object:
                    self.candidate_config = file_object.read().splitlines()
            except IOError as e:
                raise MergeConfigException(e.message)
        elif config is not None:
            if isinstance(config, list):
                self.candidate_config = config.splitlines()
            else:
                self.candidate_config = config
        self.merge_config = True
        if self.candidate_config != []:
            self.config_session = 'napalm_{}'.format(datetime.datetime.now().microsecond)
            self.device.upload_config(self.candidate_config, self.config_session)

#    def load_replace_candidate(self, filename=None, config=None):

#    def load_template(self, template_name, template_source=None, template_path=None, **template_vars):

    def open(self):
        self.device = ROS_Client(
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
                    'ip_address': napalm_base.helpers.ip(ip_address),
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
                'error': ' '.join([line.lstrip() for line in traceroute_output])
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
                    'ip_address': napalm_base.helpers.ip(line_parts[1]),
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
                        'remote_chassis_id': napalm_base.helpers.mac(if_neighbor['mac-address']),
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
