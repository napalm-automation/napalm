"""NAPALM driver for Mikrotik RouterBoard OS (ROS)"""
import datetime
import re
import socket
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
#
from napalm_base.base import NetworkDriver
from napalm_base.exceptions import ConnectionException, MergeConfigException, CommandErrorException
import napalm_base.utils.string_parsers
import paramiko
import mikoshell

from . import utils as ros_utils


class ROSDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        optional_args = optional_args or {}
        self.port = optional_args.get('port', 22)

        self.paramiko_transport = None
        self.mikoshell = None
        self.ros_version = None
        self._datetime_offset = None

        self.candidate_config = []
        self.config_session = None
        self.merge_config = False

    def cli(self, *commands):
        cli_output = {}
        for command in commands:
            device_output = self.mikoshell.command(command)
            if len(device_output) == 1 and device_output[0] != '':
                if ros_utils.is_cli_error(device_output[0]):
                    raise CommandErrorException(device_output[0])
            cli_output[unicode(command)] = device_output
        return cli_output

    def close(self):
        if hasattr(self, 'mikoshell'):
            self.mikoshell.exit('/quit')
            del self.mikoshell
        if hasattr(self, 'paramiko_transport'):
            if self.paramiko_transport.is_active():
                self.paramiko_transport.close()
            del self.paramiko_transport

    def commit_config(self):
        if self.merge_config:
            cli_command = '/import file-name="{config_session}.rsc" verbose=no'.format(
                config_session=self.config_session
            )
            cli_output = self.cli(cli_command)[cli_command]
            if cli_output[-1] != 'Script file loaded and executed successfully':
                pass
            self.discard_config()

#   def compare_config(self):

    def discard_config(self):
        self.candidate_config = []
        self.cli(
            '/file print without-paging terse',
            '/file remove "{config_session}.rsc"'.format(config_session=self.config_session)
        )

    def is_alive(self):
        if hasattr(self, 'paramiko_transport'):
            return self.paramiko_transport.is_active()
        return False

    def get_arp_table(self):
        arp_table = []
        for arp_entry in self._api_get('/ip/arp'):
            if arp_entry['flags'].find('C') == -1:
                continue
            arp_table.append(
                {
                    'interface': unicode(arp_entry.get('interface')),
                    'mac': napalm_base.helpers.mac(arp_entry.get('mac-address')),
                    'ip': napalm_base.helpers.ip(arp_entry.get('address')),
                    'age': float(-1),
                }
            )
        return arp_table

#   def get_bgp_config(self, group='', neighbor=''):

    def get_bgp_neighbors(self):
        bgp_neighbors = {
            u'global': {
                'router_id': u'',
                'peers': {},
            }
        }
        if not self._system_package_enabled('routing'):
            return bgp_neighbors

        for routing_table, bgp_peers in ros_utils.index_values(
                self._get_bgp_peers(),
                'routing-table'
        ).iteritems():
            routing_table = unicode(routing_table)
            bgp_neighbors[routing_table] = {
                'router_id': u'',
                'peers': {},
            }

            router_ids = {}
            for bgp_peer in bgp_peers:
                bgp_neighbors[routing_table]['peers'][napalm_base.helpers.ip(
                    bgp_peer['remote-address']
                )] = {
                    'local_as': int(bgp_peer['local-as']),
                    'remote_as': int(bgp_peer['remote-as']),
                    'remote_id': napalm_base.helpers.convert(
                        napalm_base.helpers.ip, bgp_peer.get('remote-id', '')
                    ),
                    'is_up': bgp_peer['state'] == 'established',
                    'is_enabled': bgp_peer['flags'].find('X') == -1,
                    'description': unicode(bgp_peer['name'].replace('"', '')),
                    'uptime': ros_utils.to_seconds(bgp_peer.get('uptime', '')),
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
            bgp_neighbors[routing_table]['router_id'] = \
                napalm_base.helpers.ip(router_ids.keys()[0])
        return bgp_neighbors

    def get_bgp_neighbors_detail(self, neighbor_address=''):
        bgp_neighbors_detail = {
            u'global': {}
        }
        if not self._system_package_enabled('routing'):
            return bgp_neighbors_detail

        for routing_table, peers in ros_utils.index_values(
                self._get_bgp_peers(neighbor_ip=neighbor_address),
                'routing-table'
        ).iteritems():
            routing_table = unicode(routing_table)
            bgp_neighbors_detail[routing_table] = {}
            for remote_as, bgp_peers in ros_utils.index_values(peers, 'remote-as').iteritems():
                remote_as = int(remote_as)
                if remote_as not in bgp_neighbors_detail[routing_table]:
                    bgp_neighbors_detail[routing_table][remote_as] = []
                for bgp_peer in bgp_peers:
                    bgp_neighbors_detail[routing_table][remote_as].append(
                        {
                            'up': bgp_peer['state'] == 'established',
                            'local_as': int(bgp_peer['local-as']),
                            'remote_as': int(bgp_peer['remote-as']),
                            'router_id': napalm_base.helpers.convert(
                                napalm_base.helpers.ip, bgp_peer.get('router-id', '')
                            ),
                            'local_address': napalm_base.helpers.convert(
                                napalm_base.helpers.ip, bgp_peer.get('local-address', '')
                            ),
                            'routing_table': unicode(bgp_peer['routing-table']),
                            'local_address_configured': False,
                            'local_port': -1,
                            'remote_address': napalm_base.helpers.ip(bgp_peer['remote-address']),
                            'remote_port': -1,
                            'multihop': bgp_peer['multihop'] == 'yes',
                            'multipath': False,
                            'remove_private_as': bgp_peer['remove-private-as'] == 'yes',
                            'import_policy': unicode(bgp_peer['in-filter'].replace('"', '')),
                            'export_policy': unicode(bgp_peer['out-filter'].replace('"', '')),
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
                            'holdtime': ros_utils.to_seconds(
                                bgp_peer.get('used-hold-time', '')
                            ),
                            'configured_holdtime': ros_utils.to_seconds(
                                bgp_peer.get('hold-time', '3m')
                            ),
                            'keepalive': ros_utils.to_seconds(
                                bgp_peer.get('used-keepalive-time', '')
                            ),
                            'configured_keepalive': ros_utils.to_seconds(
                                bgp_peer.get('keepalive-time', '1m')
                            ),
                            'active_prefix_count': -1,
                            'received_prefix_count': int(bgp_peer.get('prefix-count', 0)),
                            'accepted_prefix_count': -1,
                            'suppressed_prefix_count': -1,
                            'advertised_prefix_count': -1,
                            'flap_count': -1,
                        }
                    )
        return bgp_neighbors_detail

    def get_config(self, retrieve='all'):
        config = {
            'candidate': '',
            'running': '',
            'startup': ''
        }
        if retrieve == 'all' or retrieve == 'running':
            cli_command = '/export'
            cli_output = self.cli(cli_command)[cli_command]
            config['running'] = '\n'.join(ros_utils.export_concat(cli_output))
        return config

    def get_environment(self):
        environment = {
            'fans': {},
            'temperature': {},
            'power': {},
            'cpu': {},
            'memory': {},
        }

        system_health = self._api_get('/system/health', structured=False)[0]

        if 'active-fan' in system_health and system_health['active-fan'] != 'none':
            environment['fans'][system_health['active-fan']] = {
                'status': int(system_health.get('fan-speed', '0RPM').replace('RPM', '')) != 0,
            }

        if 'temperature' in system_health:
            environment['temperature']['board'] = {
                'temperature': float(system_health['temperature'].rstrip('C')),
                'is_alert': False,
                'is_critical': False,
            }

        if 'cpu-temperature' in system_health:
            environment['temperature']['cpu'] = {
                'temperature': float(system_health['cpu-temperature'].rstrip('C')),
                'is_alert': False,
                'is_critical': False,
            }

        for cpu_values in self._api_get('/system/resource/cpu'):
            environment['cpu'][cpu_values['cpu']] = {
                '%usage': float(cpu_values['load'].rstrip('%')),
            }

        system_resource = self._api_get('/system/resource', structured=False)[0]

        total_memory = int(float(re.sub('[KM]iB$', '', system_resource.get('total-memory'))))
        free_memory = float(re.sub('[KM]iB$', '', system_resource.get('free-memory')))
        environment['memory'] = {
            'available_ram': total_memory,
            'used_ram': int(total_memory - free_memory),
        }

        return environment

    def get_facts(self):
        system_resource = self._api_get('/system/resource', structured=False)[0]
        system_identity = self._api_get('/system/identity', structured=False)[0]
        system_routerboard = self._api_get('/system/routerboard', structured=False)[0]

        return {
            'uptime': ros_utils.to_seconds(system_resource['uptime']),
            'vendor': unicode(system_resource['platform']),
            'model': unicode(system_resource['board-name']),
            'hostname': unicode(system_identity['name']),
            'fqdn': u'',
            'os_version': unicode(system_resource['version']),
            'serial_number': unicode(system_routerboard.get('serial-number', '')),
            'interface_list': napalm_base.utils.string_parsers.sorted_nicely(
                [intf.get('name') for intf in self._api_get('/interface')]
            ),
        }

    def get_interfaces(self):
        interfaces = {}
        for if_entry in self._api_get('/interface'):
            interfaces[unicode(if_entry['name'])] = {
                'is_up': if_entry['flags'].find('R') != -1,
                'is_enabled': if_entry['flags'].find('X') == -1,
                'description': unicode(if_entry.get('comment', '')),
                'last_flapped': float(self._to_seconds_date_time(
                    if_entry.get('last-link-up-time', '')
                )),
                'speed': -1,
                'mac_address': napalm_base.helpers.mac(if_entry.get('mac-address', '')),
            }
        return interfaces

    def get_interfaces_counters(self):
        cli_command = '/interface print without-paging stats-detail'

        stats_detail = self.cli(cli_command)[cli_command]
        stats_detail.pop(0)

        interface_counters = {}
        for if_counters in ros_utils.print_to_values_structured(
                ros_utils.print_concat(stats_detail)
        ):
            if_name = unicode(if_counters['name'].replace('"', ''))
            if self._interface_type(if_name) != 'ether':
                continue
            if if_name in if_counters:
                raise ValueError('Interface already seen')
            stats_command = \
                '/interface ethernet print without-paging stats where name ="{}"'.format(if_name)
            stats_output = self.cli(stats_command)[stats_command]
            if stats_output[0] == '':
                ether_stats = {}
            else:
                ether_stats = ros_utils.print_to_values(stats_output)
            interface_counters[if_name] = {
                'tx_errors': int(if_counters['tx-error'].replace(' ', '')),
                'rx_errors': int(if_counters['rx-error'].replace(' ', '')),
                'tx_discards': int(if_counters['tx-drop'].replace(' ', '')),
                'rx_discards': int(if_counters['rx-drop'].replace(' ', '')),
                'tx_octets': int(if_counters['tx-byte'].replace(' ', '')),
                'rx_octets': int(if_counters['rx-byte'].replace(' ', '')),
                'tx_unicast_packets': -1,
                'rx_unicast_packets': -1,
                'tx_multicast_packets': int(
                    ether_stats.get('tx-multicast', '-1').replace(' ', '')
                ),
                'rx_multicast_packets': int(
                    ether_stats.get('rx-multicast', '-1').replace(' ', '')
                ),
                'tx_broadcast_packets': int(
                    ether_stats.get('tx-broadcast', '-1').replace(' ', '')
                ),
                'rx_broadcast_packets': int(
                    ether_stats.get('rx-broadcast', '-1').replace(' ', '')
                ),
            }
        return interface_counters

    def get_interfaces_ip(self):
        interfaces_ip = {}
        for if_name, if_addresses in ros_utils.index_values(
                self._api_get('/ip/address'),
                'interface'
        ).iteritems():
            if_name = unicode(if_name)
            if if_name not in interfaces_ip:
                interfaces_ip[if_name] = {
                    'ipv4': {}
                }
            for if_address in if_addresses:
                ipv4_address, prefix_length = if_address['address'].split('/', 1)
                interfaces_ip[if_name][u'ipv4'][napalm_base.helpers.ip(ipv4_address)] = \
                    dict(prefix_length=int(prefix_length))

        if not self._system_package_enabled('ipv6'):
            return interfaces_ip

        for if_name, if_addresses in ros_utils.index_values(
                self._api_get('/ipv6/address'),
                'interface'
        ).iteritems():
            if_name = unicode(if_name)
            if if_name not in interfaces_ip:
                interfaces_ip[if_name] = {
                    'ipv6': {}
                }
            for if_address in if_addresses:
                ipv6_address, prefix_length = if_address['address'].split('/', 1)
                if 'ipv6' not in interfaces_ip[if_name]:
                    interfaces_ip[if_name][u'ipv6'] = {}
                interfaces_ip[if_name][u'ipv6'][napalm_base.helpers.ip(ipv6_address)] = \
                    dict(prefix_length=int(prefix_length))

        return interfaces_ip

    def get_lldp_neighbors(self):
        if not self._minimum_version(6, 38):
            raise NotImplementedError
        return self._get_mndp_neighbors()

    def get_lldp_neighbors_detail(self, *args, **kwargs):
        if not self._minimum_version(6, 38):
            raise NotImplementedError
        return self._get_mndp_neighbors_detail(*args, **kwargs)

#   def get_mac_address_table(self):

#   def get_ntp_peers(self):

    def get_ntp_servers(self):
        ntp_servers = {}
        ntp_client_values = self._api_get('/system/ntp/client', structured=False)[0]
        for ntp_peer in ntp_client_values.get('server-dns-names', '').split(','):
            ntp_servers[unicode(ntp_peer)] = {}
        return ntp_servers

#   def get_ntp_stats(self):

#   def get_optics(self):

#   def get_probes_config(self):

#   def get_probes_results(self):

# Need to add IPv6!
    def get_route_to(self, destination='', protocol=''):
        cli_command = '/ip route print without-paging terse'

        where_used = False
        if destination != '':
            cli_command += ' where {} in dst-address'.format(destination)
            where_used = True
        if protocol != '':
            if where_used:
                cli_command += ' {}'.format(protocol.lower())
            else:
                cli_command += 'where {}'.format(protocol.lower())

        route_to = {}
        for ipv4_route in ros_utils.print_to_values_structured(self.cli(cli_command)[cli_command]):
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
            communities = []
            for community in ipv4_route.get('bgp-communities', '').split(','):
                communities.append(unicode(community))

            if route_type == 'BGP':
                bgp_neighbor_details = self._get_bgp_peers(name=ipv4_route['received-from'])[0]
                protocol_attributes = {
                    'local_as': bgp_neighbor_details['local-as'],
                    'remote_as': int(bgp_neighbor_details['remote-as']),
                    'peer_id': napalm_base.helpers.convert(
                        napalm_base.helpers.ip, bgp_neighbor_details.get('remote-id', '')
                    ),
                    'as_path': ipv4_route['bgp-as-path'],
                    'communities': communities,
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
                    'age': int(-1),
                    'next_hop': napalm_base.helpers.convert(
                        napalm_base.helpers.ip,
                        ipv4_route.get('gateway', ''),
                        ipv4_route.get('gateway', '')
                    ),
                    'outgoing_interface': unicode(
                        ipv4_route.get('gateway-status', '').split()[-1]
                    ),
                    'selected_next_hop': False,
                    'preference': int(0),
                    'inactive_reason': u'',
                    'routing_table': unicode(ipv4_route.get('routing-mark', '')),
                    'protocol_attributes': protocol_attributes
                }
            )
        return route_to

    def get_snmp_information(self):
        snmp_communities = {}
        for snmp_community in self._api_get('/snmp/community'):
            snmp_communities[unicode(snmp_community.get('name'))] = {
                'acl': unicode(snmp_community.get('addresses', '')),
                'mode': unicode('ro' if snmp_community.get('read-access', '') == 'yes' else 'rw'),
            }

        snmp_values = self._api_get('/snmp', structured=False)[0]

        return {
            'chassis_id': unicode(snmp_values['engine-id']),
            'community': snmp_communities,
            'contact': unicode(snmp_values['contact']),
            'location': unicode(snmp_values['location']),
        }

    def get_users(self):
        user_sshkeys = ros_utils.index_values(self._api_get('/user/ssh-keys'), 'user')

        users = {}
        for user in self._api_get('/user'):
            users[user['name']] = {
                'level': 15 if user['group'] == 'full' else 0,
                'password': '',
                'sshkeys': [key for key in user_sshkeys.get(user['name'], [])]

            }
        return users

    def load_merge_candidate(self, filename=None, config=None):
        if filename is not None:
            try:
                with open(filename, 'rU') as file_object:
                    self.candidate_config = file_object.read().splitlines()
            except IOError as exc:
                raise MergeConfigException(exc.message)
        elif config is not None:
            if isinstance(config, list):
                self.candidate_config = config.splitlines()
            else:
                self.candidate_config = []
                self.candidate_config.append(config)
        self.merge_config = True
        if self.candidate_config != []:
            self.config_session = 'napalm_{}'.format(datetime.datetime.now().microsecond)
            self._upload_config(self.candidate_config, self.config_session)

    def open(self):
        paramiko.common.logging.basicConfig(level=paramiko.common.CRITICAL)

        try:
            sock = socket.create_connection((self.hostname, self.port), self.timeout)
            paramiko_transport = paramiko.Transport(sock)
            paramiko_transport.connect()
        except socket.error as exc:
            raise ConnectionException(
                'Could not connect to {}:{} - [{}]'.format(self.hostname, self.port, exc.message)
            )

        paramiko_transport.set_keepalive(5)

        try:
            paramiko_transport.auth_password('{}+ct0h160w'.format(self.username), self.password)
        except paramiko.BadAuthenticationType as bad_auth_type:
            raise ConnectionException(
                'Auth method not supported - [{}]'.format(bad_auth_type.allowed_types)
            )
        except paramiko.AuthenticationException as auth_error:
            raise ConnectionException(auth_error.message)
        else:
            self.paramiko_transport = paramiko_transport

        shell_prompts = mikoshell.ShellPrompt(
            mikoshell.ShellPrompt.regexp_prompt(r'\[[^\@]+\@[^\]]+\] > $')
        )
        shell_prompts.add_prompt(
            mikoshell.ShellPrompt.regexp_prompt(r'\[[^\@]+\@[^\]]+\] <SAFE> $')
        )

        self.mikoshell = mikoshell.Shell(self.paramiko_transport.open_session(), shell_prompts)
#       self.mikoshell = mikoshell.Shell.from_transport(self.paramiko_transport, shell_prompts)
#       self.apiros = rosapi.RouterboardAPI(self.hostname, self.username, self.password)
        self.ros_version = self._ros_version()
        self._datetime_offset = datetime.datetime.now() - self._ros_datetime()

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
        statistics = ros_utils.print_to_values_structured(['0 {}'.format(statistics)])[0]

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

#   def rollback(self):

    def traceroute(self, destination, source='', ttl=0, timeout=0):
        num_probes = 3
        traceroute_command = '/tool traceroute address={} count={}'.format(
            destination,
            num_probes
        )
        traceroute_command += ' use-dns=no protocol=icmp'

        if source != '':
            traceroute_command += ' src-address={}'.format(source)
        if ttl != 0:
            traceroute_command += ' max-hops={}'.format(ttl)
        if timeout != 0:
            traceroute_command += ' timeout={}'.format(timeout)

        chan = self.paramiko_transport.open_session()
        chan.set_combine_stderr(True)
        chan.exec_command(traceroute_command)
        output_file = chan.makefile('rb')
        traceroute_output = []
        for output_line in output_file.readlines():
            traceroute_output.append(output_line.rstrip('\r\n'))
        chan.shutdown(2)
        chan.close()

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

    def _api_get(self, command, **kwargs):
        is_structured = kwargs.pop('structured', True)
        if is_structured:
            cli_command = '/{} print without-paging terse'.format(
                command.lstrip('/').replace('/', ' ')
            )
        else:
            cli_command = '/{} print without-paging'.format(
                command.lstrip('/').replace('/', ' ')
            )
        cli_output = self.cli(cli_command)[cli_command]
        if is_structured:
            api_output = ros_utils.print_to_values_structured(cli_output)
        else:
            api_output = [ros_utils.print_to_values(cli_output)]
        return api_output

    def X_api_get(self, command, **kwargs):
        if not hasattr(self, 'command_cache'):
            self.command_cache = {}
        use_cache = kwargs.pop('use_cache', False)
        if use_cache:
            if command in self.command_cache:
                return self.command_cache[command]
        is_structured = kwargs.pop('structured', True)
        if is_structured:
            self.command_cache[command] = ''
        api_output = self.apiros.get_resource(command).get()
        for api_entry in api_output:
            if 'flags' not in api_entry:
                api_entry['flags'] = ''
            if api_entry.get('disabled', 'false') == 'true':
                api_entry['flags'] += 'X'
            if api_entry.get('invalid', 'false') == 'true':
                api_entry['flags'] += 'I'
            if api_entry.get('running', 'false') == 'true':
                api_entry['flags'] += 'R'
            if command.startswith('/interface'):
                if api_entry.get('slave', 'false') == 'true':
                    api_entry['flags'] += 'S'
            elif command == '/ip/arp':
                if api_entry.get('complete', 'false') == 'true':
                    api_entry['flags'] += 'C'
            elif command == '/ip/route':
                if api_entry.get('bgp', 'false') == 'true':
                    api_entry['flags'] += 'b'
                if api_entry.get('connected', 'false') == 'true':
                    api_entry['flags'] += 'C'
                if api_entry.get('ospf', 'false') == 'true':
                    api_entry['flags'] += 'o'
                if api_entry.get('static', 'false') == 'true':
                    api_entry['flags'] += 'S'
        if use_cache:
            self.command_cache[command] = api_output
        return api_output

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

    def _get_bgp_peers(self, name='', neighbor_ip=''):
        bgp_peers = []
        if not self._system_package_enabled('routing'):
            return bgp_peers

        peer_print_status = '/routing bgp peer print without-paging status'
        cli_output = self.cli(peer_print_status)

        peer_status = cli_output[peer_print_status]
        peer_status.pop(0)

        instance_indexed = ros_utils.index_values(self._api_get('/routing/bgp/instance'), 'name')
#       instance_indexed_vrf = ros_utils.index_values(
#           self._api_get('/routing/bgp/instance/vrf'),
#           'name'
#       )

        for peer in ros_utils.print_to_values_structured(ros_utils.print_concat(peer_status)):
            if name != '' and peer['name'].replace('"', '') != name:
                continue
            if neighbor_ip != '' and peer.get('remote-address', '') != neighbor_ip:
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
        mndp_neighbors = {}
        for if_name, if_neighbors in ros_utils.index_values(
                self._api_get('/ip/neighbor'),
                'interface'
        ).iteritems():
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
        cli_command = '/ip neighbor print without-paging terse'
        if interface != '':
            cli_command += ' where interface ="{}"'.format(interface)

        mndp_neighbors_detail = {}
        for if_name, if_neighbors in ros_utils.index_values(
                ros_utils.print_to_values_structured(self.cli(cli_command)[cli_command]),
                'interface'
        ).iteritems():
            if_name = unicode(if_name)
            if if_name not in mndp_neighbors_detail:
                mndp_neighbors_detail[if_name] = []
            for if_neighbor in if_neighbors:
                mndp_neighbors_detail[if_name].append(
                    {
                        'parent_interface': u'',
                        'remote_chassis_id': napalm_base.helpers.convert(
                            napalm_base.helpers.mac,
                            if_neighbor['mac-address'],
                            if_neighbor['mac-address']
                        ),
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

    def _interface_type(self, if_name):
        indexed_values = ros_utils.index_values(self._api_get('/interface', name=if_name), 'name')
        if if_name in indexed_values:
            return indexed_values[if_name][0].get('type')
        return None

    def _minimum_version(self, major_version, minor_version=None, patch_level=None):
        ros_version = self.ros_version or self._ros_version()
        if ros_version['major'] < major_version:
            return False
        if minor_version is not None:
            if ros_version['minor'] < minor_version:
                return False
            if patch_level is not None:
                pass
        return True

    def _ros_datetime(self):
        system_clock = self._api_get('/system/clock', structured=False)[0]
        date_string = '{} {} {}'.format(system_clock['date'], system_clock['time'], 'gmt')
        return datetime.datetime.strptime(date_string, '%b/%d/%Y %H:%M:%S %Z')

    def _ros_version(self):
        system_resource = self._api_get('/system/resource', structured=False)[0]
        for version_regexp in [
                r'(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+) \((?P<channel>[^\)]+)\)$',
                r'(?P<major>\d+)\.(?P<minor>\d+) \((?P<channel>[^\)]+)\)$',
                r'(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$',
                r'(?P<major>\d+)\.(?P<minor>\d+)$'
                r'(?P<major>\d+)\.(?P<minor>\d+)rc(?P<patch>\d+)$'
        ]:
            re_match = re.match(version_regexp, system_resource.get('version'))
            if re_match:
                version = {
                    'major': None,
                    'minor': None,
                    'patch': None,
                    'channel': None,
                }
                for key in version.keys():
                    try:
                        value = re_match.group(key)
                    except IndexError:
                        pass
                    else:
                        if value.isdigit():
                            version[key] = int(value)
                        else:
                            version[key] = value
                return version
        raise ValueError

    def _system_package_enabled(self, package):
        indexed_values = ros_utils.index_values(
            self._api_get('/system/package', name=package),
            'name'
        )
        return indexed_values.get(package, [])[0].get('flags', '').find('X') == -1

    def _to_seconds_date_time(self, date_time):
        if date_time == '':
            return -1.0
        time_then = datetime.datetime.strptime(date_time, '%b/%d/%Y %H:%M:%S')
        time_diff = datetime.datetime.now() - time_then + self._datetime_offset
        return int(time_diff.total_seconds())

    def _upload_config(self, config, config_name):
        sftp_client = paramiko.SFTPClient.from_transport(self.paramiko_transport)
        config_file = StringIO('\r\n'.join(config))
        sftp_client.putfo(config_file, '{}.rsc'.format(config_name))
        sftp_client.close()
