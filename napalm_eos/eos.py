# Copyright 2015 Spotify AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for Arista EOS.

Read napalm.readthedocs.org for more information.
"""

# std libs
import re
import time
from datetime import datetime
from netaddr import IPAddress
from netaddr import IPNetwork
from collections import defaultdict
from netaddr.core import AddrFormatError

# third party libs
import pyeapi
from pyeapi.eapilib import ConnectionError

# NAPALM base
import napalm_base.helpers
from napalm_base.base import NetworkDriver
from napalm_base.utils import string_parsers
from napalm_base.exceptions import ConnectionException, MergeConfigException, ReplaceConfigException,\
                                   SessionLockedException, CommandErrorException

# local modules
# here add local imports
# e.g. import napalm_eos.helpers etc.


class EOSDriver(NetworkDriver):
    """Napalm driver for Arista EOS."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.config_session = None

        if optional_args is None:
            optional_args = {}
        self.port = optional_args.get('port', 443)

    def open(self):
        """Implemantation of NAPALM method open."""
        try:
            connection = pyeapi.client.connect(
                transport='https',
                host=self.hostname,
                username=self.username,
                password=self.password,
                port=self.port,
                timeout=self.timeout
            )
            self.device = pyeapi.client.Node(connection)
            # does not raise an Exception if unusable

            # let's try to run a very simple command
            self.device.run_commands(['show clock'], encoding='text')
        except ConnectionError as ce:
            # and this is raised either if device not avaiable
            # either if HTTP(S) agent is not enabled
            # show management api http-commands
            raise ConnectionException(ce.message)

    def close(self):
        """Implemantation of NAPALM method close."""
        self.discard_config()

    def _load_config(self, filename=None, config=None, replace=True):
        if self.config_session is not None:
            raise SessionLockedException('Session is already in use by napalm')
        else:
            self.config_session = 'napalm_{}'.format(datetime.now().microsecond)

        commands = list()
        commands.append('configure session {}'.format(self.config_session))

        if replace:
            commands.append('rollback clean-config')

        if filename is not None:
            with open(filename, 'r') as f:
                lines = f.readlines()
        else:
            if isinstance(config, list):
                lines = config
            else:
                lines = config.splitlines()

        for line in lines:
            line = line.strip()
            if line == '':
                continue
            if line.startswith('!'):
                continue
            commands.append(line)

        try:
            self.device.run_commands(commands)
        except pyeapi.eapilib.CommandError as e:
            self.discard_config()

            if replace:
                raise ReplaceConfigException(e.message)
            else:
                raise MergeConfigException(e.message)

    def load_replace_candidate(self, filename=None, config=None):
        """Implemantation of NAPALM method load_replace_candidate."""
        self._load_config(filename, config, True)

    def load_merge_candidate(self, filename=None, config=None):
        """Implemantation of NAPALM method load_merge_candidate."""
        self._load_config(filename, config, False)

    def compare_config(self):
        """Implemantation of NAPALM method compare_config."""
        if self.config_session is None:
            return ''
        else:
            commands = ['show session-config named %s diffs' % self.config_session]
            result = self.device.run_commands(commands, encoding='text')[0]['output']

            result = '\n'.join(result.splitlines()[2:])

            return result.strip()

    def commit_config(self):
        """Implemantation of NAPALM method commit_config."""
        commands = list()
        commands.append('copy startup-config flash:rollback-0')
        commands.append('configure session {}'.format(self.config_session))
        commands.append('commit')
        commands.append('write memory')

        self.device.run_commands(commands)
        self.config_session = None

    def discard_config(self):
        """Implemantation of NAPALM method discard_config."""
        if self.config_session is not None:
            commands = list()
            commands.append('configure session {}'.format(self.config_session))
            commands.append('abort')
            self.device.run_commands(commands)
            self.config_session = None

    def rollback(self):
        """Implemantation of NAPALM method rollback."""
        commands = list()
        commands.append('configure replace flash:rollback-0')
        commands.append('write memory')
        self.device.run_commands(commands)

    def get_facts(self):
        """Implemantation of NAPALM method get_facts."""
        commands = list()
        commands.append('show version')
        commands.append('show hostname')
        commands.append('show interfaces status')

        result = self.device.run_commands(commands)

        version = result[0]
        hostname = result[1]
        interfaces_dict = result[2]['interfaceStatuses']

        uptime = time.time() - version['bootupTimestamp']

        interfaces = [i for i in interfaces_dict.keys() if '.' not in i]
        interfaces = string_parsers.sorted_nicely(interfaces)

        return {
            'hostname': hostname['hostname'],
            'fqdn': hostname['fqdn'],
            'vendor': u'Arista',
            'model': version['modelName'],
            'serial_number': version['serialNumber'],
            'os_version': version['internalVersion'],
            'uptime': int(uptime),
            'interface_list': interfaces,
        }

    def get_interfaces(self):
        commands = list()
        commands.append('show interfaces')
        output = self.device.run_commands(commands)[0]

        interfaces = dict()

        for interface, values in output['interfaces'].iteritems():
            interfaces[interface] = dict()

            if values['lineProtocolStatus'] == 'up':
                interfaces[interface]['is_up'] = True
                interfaces[interface]['is_enabled'] = True
            else:
                interfaces[interface]['is_up'] = False
                if values['interfaceStatus'] == 'disabled':
                    interfaces[interface]['is_enabled'] = False
                else:
                    interfaces[interface]['is_enabled'] = True

            interfaces[interface]['description'] = values['description']

            interfaces[interface]['last_flapped'] = values.pop('lastStatusChangeTimestamp', None)

            interfaces[interface]['speed'] = int(values['bandwidth'] * 1e-6)
            interfaces[interface]['mac_address'] = values.pop('physicalAddress', u'')

        return interfaces

    def get_lldp_neighbors(self):
        commands = list()
        commands.append('show lldp neighbors')
        output = self.device.run_commands(commands)[0]['lldpNeighbors']

        lldp = dict()

        for n in output:
            if n['port'] not in lldp.keys():
                lldp[n['port']] = list()

            lldp[n['port']].append(
                {
                    'hostname': n['neighborDevice'],
                    'port': n['neighborPort'],
                }
            )

        return lldp

    def get_interfaces_counters(self):
        commands = list()

        commands.append('show interfaces counters')
        commands.append('show interfaces counters errors')

        output = self.device.run_commands(commands)

        interface_counters = dict()

        for interface, counters in output[0]['interfaces'].iteritems():
            interface_counters[interface] = dict()

            interface_counters[interface]['tx_octets'] = counters['outOctets']
            interface_counters[interface]['rx_octets'] = counters['inOctets']
            interface_counters[interface]['tx_unicast_packets'] = counters['outUcastPkts']
            interface_counters[interface]['rx_unicast_packets'] = counters['inUcastPkts']
            interface_counters[interface]['tx_multicast_packets'] = counters['outMulticastPkts']
            interface_counters[interface]['rx_multicast_packets'] = counters['inMulticastPkts']
            interface_counters[interface]['tx_broadcast_packets'] = counters['outBroadcastPkts']
            interface_counters[interface]['rx_broadcast_packets'] = counters['inBroadcastPkts']
            interface_counters[interface]['tx_discards'] = counters['outDiscards']
            interface_counters[interface]['rx_discards'] = counters['inDiscards']

            # Errors come from a different command
            errors = output[1]['interfaceErrorCounters'][interface]
            interface_counters[interface]['tx_errors'] = errors['outErrors']
            interface_counters[interface]['rx_errors'] = errors['inErrors']

        return interface_counters

    @staticmethod
    def _parse_neigbor_info(line):
        m = re.match('BGP neighbor is (?P<neighbor>.*?), remote AS (?P<as>.*?), .*', line)
        return m.group('neighbor'), m.group('as')

    @staticmethod
    def _parse_rid_info(line):
        m = re.match('.*BGP version 4, remote router ID (?P<rid>.*?), VRF (?P<vrf>.*?)$', line)
        return m.group('rid'), m.group('vrf')

    @staticmethod
    def _parse_desc(line):
        m = re.match('\s+Description: (?P<description>.*?)', line)
        if m:
            return m.group('description')
        else:
            return None

    @staticmethod
    def _parse_local_info(line):
        m = re.match('Local AS is (?P<as>.*?),.*', line)
        return m.group('as')

    @staticmethod
    def _parse_prefix_info(line):
        m = re.match('(\s*?)(?P<af>IPv[46]) Unicast:\s*(?P<sent>\d+)\s*(?P<received>\d+)', line)
        return m.group('sent'), m.group('received')

    def get_bgp_neighbors(self):
        NEIGHBOR_FILTER = 'bgp neighbors vrf all | include remote AS | remote router ID |^\s*IPv[46] Unicast:.*[0-9]+|^Local AS|Desc'
        output_summary_cmds = self.device.run_commands(
            ['show ipv6 bgp summary vrf all', 'show ip bgp summary vrf all'],
            encoding='json')
        output_neighbor_cmds = self.device.run_commands(
            ['show ip ' + NEIGHBOR_FILTER, 'show ipv6 ' + NEIGHBOR_FILTER],
            encoding='text')

        bgp_counters = defaultdict(lambda: dict(peers=dict()))
        for summary in output_summary_cmds:
            """
            Json output looks as follows
            "vrfs": {
                "default": {
                    "routerId": 1,
                    "asn": 1,
                    "peers": {
                        "1.1.1.1": {
                            "msgSent": 1,
                            "inMsgQueue": 0,
                            "prefixReceived": 3926,
                            "upDownTime": 1449501378.418644,
                            "version": 4,
                            "msgReceived": 59616,
                            "prefixAccepted": 3926,
                            "peerState": "Established",
                            "outMsgQueue": 0,
                            "underMaintenance": false,
                            "asn": 1
                        }
                    }
                }
            }
            """
            for vrf, vrf_data in summary['vrfs'].iteritems():
                bgp_counters[vrf]['router_id'] = vrf_data['routerId']
                for peer, peer_data in vrf_data['peers'].iteritems():
                    peer_info = {
                        'is_up': peer_data['peerState'] == 'Established',
                        'is_enabled': peer_data['peerState'] == 'Established' or peer_data['peerState'] == 'Active',
                        'uptime': int(peer_data['upDownTime'])
                    }
                    bgp_counters[vrf]['peers'][peer] = peer_info
        lines = []
        [lines.extend(x['output'].splitlines()) for x in output_neighbor_cmds]
        for line in lines:
            """
            Raw output from the command looks like the following:

              BGP neighbor is 1.1.1.1, remote AS 1, external link
                Description: Very info such descriptive
                BGP version 4, remote router ID 1.1.1.1, VRF my_vrf
                 IPv4 Unicast:         683        78
                 IPv6 Unicast:           0         0
              Local AS is 2, local router ID 2.2.2.2
            """
            if line is '':
                continue
            neighbor, r_as = self._parse_neigbor_info(lines.pop(0))
            # this line can be either description or rid info
            next_line = lines.pop(0)
            desc = self._parse_desc(next_line)
            if desc is None:
                rid, vrf = self._parse_rid_info(next_line)
                desc = ''
            else:
                rid, vrf = self._parse_rid_info(lines.pop(0))

            v4_sent, v4_recv = self._parse_prefix_info(lines.pop(0))
            v6_sent, v6_recv = self._parse_prefix_info(lines.pop(0))
            local_as = self._parse_local_info(lines.pop(0))
            data = {
                'remote_as': int(r_as),
                'remote_id': unicode(rid),
                'local_as': int(local_as),
                'description': unicode(desc),
                'address_family': {
                    'ipv4': {
                        'sent_prefixes': int(v4_sent),
                        'received_prefixes': int(v4_recv),
                        'accepted_prefixes': -1
                    },
                    'ipv6': {
                        'sent_prefixes': int(v6_sent),
                        'received_prefixes': int(v6_recv),
                        'accepted_prefixes': -1
                    }
                }
            }
            bgp_counters[vrf]['peers'][neighbor].update(data)

        if 'default' in bgp_counters.keys():
            bgp_counters['global'] = bgp_counters.pop('default')
        return bgp_counters

    def get_environment(self):
        """
        Returns a dictionary where:
            * fans is a dictionary of dictionaries where the key is the location and the values:
                * status (boolean) - True if it's ok, false if it's broken
            * temperature is a dictionary of dictionaries where the key is the location and the values:
                * temperature (int) - Temperature in celsius the sensor is reporting.
                * is_alert (boolean) - True if the temperature is above the alert threshold
                * is_critical (boolean) - True if the temperature is above the critical threshold
            * power is a dictionary of dictionaries where the key is the PSU id and the values:
                * status (boolean) - True if it's ok, false if it's broken
                * capacity (int) - Capacity in W that the power supply can support
                * output (int) - Watts drawn by the system
            * cpu is a dictionary of dictionaries where the key is the ID and the values
                * %usage
            * available_ram (int) - Total amount of RAM installed in the device
            * used_ram (int) - RAM that is still free in the device
        """
        command = list()
        command.append('show environment cooling')
        command.append('show environment temperature')
        command.append('show environment power')
        output = self.device.run_commands(command)

        environment_counters = dict()
        environment_counters['fans'] = dict()
        environment_counters['temperature'] = dict()
        environment_counters['power'] = dict()
        environment_counters['cpu'] = dict()
        environment_counters['available_ram'] = ''
        environment_counters['used_ram'] = ''

        fans_output = output[0]
        temp_output = output[1]
        power_output = output[2]
        cpu_output = self.device.run_commands(['show processes top once'], encoding='text')[0]['output']

        ''' Get fans counters '''
        for slot in fans_output['fanTraySlots']:
            environment_counters['fans'][slot['label']] = dict()
            environment_counters['fans'][slot['label']]['status'] = slot['status'] == 'ok'

        ''' Get temp counters '''
        for slot in temp_output:
            try:
                for sensorsgroup in temp_output[slot]:
                    for sensor in sensorsgroup['tempSensors']:
                        environment_counters['temperature'][sensor['name']] = {
                            'temperature': sensor['currentTemperature'],
                            'is_alert': sensor['currentTemperature'] > sensor['overheatThreshold'],
                            'is_critical': sensor['currentTemperature'] > sensor['criticalThreshold']
                        }
            except:
                pass

        ''' Get power counters '''
        for _, item in power_output.iteritems():
            for id, ps in item.iteritems():
                environment_counters['power'][id] = {
                    'status': ps['state'] == 'ok',
                    'capacity': ps['capacity'],
                    'output': ps['outputPower']
                }

        ''' Get CPU counters '''
        m = re.search('(\d+.\d+)\%', cpu_output.splitlines()[2])
        environment_counters['cpu'][0] = {
            '%usage': float(m.group(1))
        }
        m = re.search('(\d+)k\W+total\W+(\d+)k\W+used\W+(\d+)k\W+free', cpu_output.splitlines()[3])

        environment_counters['memory'] = {
            'available_ram': int(m.group(1)),
            'used_ram': int(m.group(2))
        }

        return environment_counters

    def get_lldp_neighbors_detail(self, interface = ''):

        lldp_neighbors_out = dict()

        filters = list()
        if interface:
            filters.append(interface)

        commands = list()
        commands.append(
            'show lldp neighbors {filters} detail'.format(
                filters = ' '.join(filters)
            )
        )

        lldp_neighbors_in = {}
        try:
            lldp_neighbors_in = self.device.run_commands(commands)[0].get('lldpNeighbors', {})
        except Exception:
            return {}

        for interface in lldp_neighbors_in:
            interface_neighbors = lldp_neighbors_in.get(interface).get('lldpNeighborInfo', {})
            if not interface_neighbors:
                # in case of empty infos
                continue
            for neighbor in interface_neighbors: # it is provided a list of neighbors per interface
                if interface not in lldp_neighbors_out.keys():
                    lldp_neighbors_out[interface] = list()
                capabilities = neighbor.get('systemCapabilities')
                lldp_neighbors_out[interface].append(
                    {
                        'parent_interface'              : interface, # no parent interfaces
                        'remote_port'                   : neighbor.get('neighborInterfaceInfo', {}).get('interfaceId', u''),
                        'remote_port_description'       : u'',
                        'remote_system_name'            : neighbor.get('systemName', u''),
                        'remote_system_description'     : neighbor.get('systemDescription', u''),
                        'remote_chassis_id'             : neighbor.get('chassisId', u''),
                        'remote_system_capab'           : unicode(', '.join(capabilities)),
                        'remote_system_enable_capab'   : unicode(', '.join([capability for capability in capabilities.keys() if capabilities[capability]]))
                    }
                )

        return lldp_neighbors_out

    def cli(self, commands = None):

        cli_output = dict()

        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            try:
                cli_output[unicode(command)] = self.device.run_commands([command], encoding='text')[0].get('output')
                # not quite fair to not exploit rum_commands
                # but at least can have better control to point to wrong command in case of failure
            except pyeapi.eapilib.CommandError:
                # for sure this command failed
                cli_output[unicode(command)] = 'Invalid command: "{cmd}"'.format(
                    cmd=command
                )
                raise CommandErrorException(str(cli_output))
            except Exception as e:
                # something bad happened
                cli_output[unicode(command)] = 'Unable to execute command "{cmd}": {err}'.format(
                    cmd=command,
                    err=e
                )
                raise CommandErrorException(str(cli_output))

        return cli_output

    def get_bgp_config(self, group='', neighbor=''):
        """Implemantation of NAPALM method get_bgp_config."""
        _GROUP_FIELD_MAP_ = {
            'type': 'type',
            'multipath': 'multipath',
            'apply-groups': 'apply_groups',
            'remove-private-as': 'remove_private_as',
            'ebgp-multihop': 'multihop_ttl',
            'remote-as': 'remote_as',
            'local-v4-addr': 'local_address',
            'local-v6-addr': 'local_address',
            'local-as': 'local_as',
            'description': 'description',
            'import-policy': 'import_policy',
            'export-policy': 'export_policy'
        }

        _PEER_FIELD_MAP_ = {
            'description': 'description',
            'remote-as': 'remote_as',
            'local-v4-addr': 'local_address',
            'local-v6-addr': 'local_address',
            'local-as': 'local_as',
            'next-hop-self': 'nhs',
            'route-reflector-client': 'route_reflector_client',
            'description': 'description',
            'import-policy': 'import_policy',
            'export-policy': 'export_policy',
            'passwd': 'authentication_key'
        }

        _PROPERTY_FIELD_MAP_ = _GROUP_FIELD_MAP_.copy()
        _PROPERTY_FIELD_MAP_.update(_PEER_FIELD_MAP_)

        _PROPERTY_TYPE_MAP_ = {
            # used to determine the default value
            # and cast the values
            'remote-as'             : int,
            'ebgp-multihop'         : int,
            'local-v4-addr'         : unicode,
            'local-v6-addr'         : unicode,
            'local-as'              : int,
            'remove-private-as'     : bool,
            'next-hop-self'         : bool,
            'description'           : unicode,
            'route-reflector-client': bool,
            'password'              : unicode,
            'route-map'             : unicode,
            'apply-groups'          : list,
            'type'                  : unicode,
            'import-policy'         : unicode,
            'export-policy'         : unicode,
            'multipath'             : bool
        }

        _DATATYPE_DEFAULT_ = {
            unicode     : u'',
            int         : 0,
            bool        : False,
            list        : []
        }

        def parse_options(options, default_value = False):

            if not options:
                return dict()

            config_property = options[0]
            field_name  = _PROPERTY_FIELD_MAP_.get(config_property)
            field_type  = _PROPERTY_TYPE_MAP_.get(config_property)
            field_value = _DATATYPE_DEFAULT_.get(field_type) # to get the default value

            if not field_type:
                # no type specified at all => return empty dictionary
                return dict()

            if not default_value:
                if len(options) > 1:
                    field_value = field_type(options[1])
                else:
                    if field_type is bool:
                        field_value = True
            if field_name is not None:
                return {field_name: field_value}
            elif config_property in ['route-map', 'password']:
                # do not respect the pattern neighbor [IP_ADDRESS] [PROPERTY] [VALUE]
                # or need special output (e.g.: maximum-routes)
                if config_property == 'password':
                    return {'authentication_key': unicode(options[2])}
                    # returns the MD5 password
                if config_property == 'route-map':
                    direction = None
                    if len(options) == 3:
                        direction = options[2]
                        field_value = field_type(options[1]) # the name of the policy
                    elif len(options) == 2:
                        direction = options[1]
                    if direction == 'in':
                        field_name = 'import_policy'
                    else:
                        field_name = 'export_policy'
                    return {field_name: field_value}

            return dict()

        bgp_config = dict()

        commands = list()
        commands.append('show running-config | section router bgp')
        bgp_conf = self.device.run_commands(commands, encoding='text')[0].get('output', '\n\n')
        bgp_conf_lines = bgp_conf.splitlines()[2:]

        bgp_neighbors = dict()

        if not group:
            neighbor = ''

        last_peer_group = ''
        local_as = 0
        for bgp_conf_line in bgp_conf_lines:
            raw_line = bgp_conf_line
            default_value = False
            bgp_conf_line = bgp_conf_line.strip()
            if bgp_conf_line.startswith('router bgp'):
                local_as = int(bgp_conf_line.replace('router bgp', '').strip())
                continue
            if not (bgp_conf_line.startswith('neighbor') or bgp_conf_line.startswith('no neighbor')):
                continue
            if bgp_conf_line.startswith('no'):
                default_value = True
            bgp_conf_line = bgp_conf_line.replace('no neighbor ', '').replace('neighbor ', '')
            bgp_conf_line_details = bgp_conf_line.split()
            group_or_neighbor = unicode(bgp_conf_line_details[0])
            options = bgp_conf_line_details[1:]
            try:
                # will try to parse the neighbor name
                # which sometimes is the IP Address of the neigbor
                # or the name of the BGP group
                IPAddress(group_or_neighbor)
                # if passes the test => it is an IP Address, thus a Neighbor!
                peer_address = group_or_neighbor

                if options[0] == 'peer-group':
                    last_peer_group = options[1]

                # if looking for a specific group
                if group and last_peer_group != group:
                    continue

                # or even more. a specific neighbor within a group
                if neighbor and peer_address != neighbor:
                    continue
                # skip all other except the target

                # in the config, neighbor details are lister after
                # the group is specified for the neighbor:
                #
                # neighbor 192.168.172.36 peer-group 4-public-anycast-peers
                # neighbor 192.168.172.36 remote-as 12392
                # neighbor 192.168.172.36 maximum-routes 200
                #
                # because the lines are parsed sequentially
                # can use the last group detected
                # that way we avoid one more loop to match the neighbors with the group they belong to
                # directly will apend the neighbor in the neighbor list of the group at the end
                if last_peer_group not in bgp_neighbors.keys():
                    bgp_neighbors[last_peer_group] = dict()
                if peer_address not in bgp_neighbors[last_peer_group]:
                    bgp_neighbors[last_peer_group][peer_address] = dict()
                    bgp_neighbors[last_peer_group][peer_address].update({
                        key:_DATATYPE_DEFAULT_.get(_PROPERTY_TYPE_MAP_.get(prop)) for prop, key in _PEER_FIELD_MAP_.iteritems()
                    }) # populating with default values
                    bgp_neighbors[last_peer_group][peer_address].update({
                        'prefix_limit': {},
                        'local_as'    : local_as,
                        'authentication_key': u''
                    }) # few more default values
                bgp_neighbors[last_peer_group][peer_address].update(
                    parse_options(options, default_value)
                )
            except AddrFormatError:
                # exception trying to parse group name
                # group_or_neighbor represents the name of the group
                group_name = group_or_neighbor
                if group and group_name != group:
                    continue
                if group_name not in bgp_config.keys():
                    bgp_config[group_name] = dict()
                    bgp_config[group_name].update({
                        key:_DATATYPE_DEFAULT_.get(_PROPERTY_TYPE_MAP_.get(prop)) for prop, key in _GROUP_FIELD_MAP_.iteritems()
                    })
                    bgp_config[group_name].update({
                        'prefix_limit'   : {},
                        'neighbors'      : {},
                        'local_as'       : local_as
                    }) # few more default values
                bgp_config[group_name].update(
                    parse_options(options, default_value)
                )
            except Exception:
                # for other kind of exception pass to next line
                continue

        for group, peers in bgp_neighbors.iteritems():
            if group not in bgp_config.keys():
                continue
            bgp_config[group]['neighbors'] = peers

        return bgp_config

    def get_arp_table(self):

        arp_table = list()

        commands = ['show arp']

        ipv4_neighbors = []
        try:
            ipv4_neighbors = self.device.run_commands(commands)[0].get('ipV4Neighbors', [])
        except pyeapi.eapilib.CommandError:
            return []

        for neighbor in ipv4_neighbors:
            interface   = unicode(neighbor.get('interface'))
            mac_raw     = neighbor.get('hwAddress')
            mac_all     = mac_raw.replace('.', '').replace(':', '')
            mac_format  = unicode(':'.join([mac_all[i:i+2] for i in range(12)[::2]]))
            ip          = unicode(neighbor.get('address'))
            age         = float(neighbor.get('age'))
            arp_table.append(
                {
                    'interface' : interface,
                    'mac'       : mac_format,
                    'ip'        : ip,
                    'age'       : age
                }
            )

        return arp_table


    def get_ntp_peers(self):

        commands = ['show running-config | section ntp']

        raw_ntp_config = self.device.run_commands(commands, encoding='text')[0].get('output', '')

        ntp_config = napalm_base.helpers.textfsm_extractor(self, 'ntp_peers', raw_ntp_config)

        return {unicode(ntp_peer.get('ntppeer')):{} for ntp_peer in ntp_config if ntp_peer.get('ntppeer', '')}


    def get_ntp_stats(self):

        ntp_stats = list()

        REGEX = (
            '^\s?(\+|\*|x|-)?([a-zA-Z0-9\.+-:]+)'
            '\s+([a-zA-Z0-9\.]+)\s+([0-9]{1,2})'
            '\s+(-|u)\s+([0-9h-]+)\s+([0-9]+)'
            '\s+([0-9]+)\s+([0-9\.]+)\s+([0-9\.-]+)'
            '\s+([0-9\.]+)\s?$'
        )

        commands = list()
        commands.append('show ntp associations')

        # output = self.device.run_commands(commands)
        # pyeapi.eapilib.CommandError: CLI command 2 of 2 'show ntp associations' failed: unconverted command
        # JSON output not yet implemented...

        ntp_assoc = self.device.run_commands(commands, encoding = 'text')[0].get('output', '\n\n')
        ntp_assoc_lines = ntp_assoc.splitlines()[2:]

        for ntp_assoc in ntp_assoc_lines:
            line_search = re.search(REGEX, ntp_assoc, re.I)
            if not line_search:
                continue # pattern not found
            line_groups = line_search.groups()
            try:
                ntp_stats.append({
                    'remote'        : unicode(line_groups[1]),
                    'synchronized'  : (line_groups[0] == '*'),
                    'referenceid'   : unicode(line_groups[2]),
                    'stratum'       : int(line_groups[3]),
                    'type'          : unicode(line_groups[4]),
                    'when'          : unicode(line_groups[5]),
                    'hostpoll'      : int(line_groups[6]),
                    'reachability'  : int(line_groups[7]),
                    'delay'         : float(line_groups[8]),
                    'offset'        : float(line_groups[9]),
                    'jitter'        : float(line_groups[10])
                })
            except Exception:
                continue # jump to next line

        return ntp_stats

    def get_interfaces_ip(self):

        interfaces_ip = dict()

        commands = list()
        commands.append('show ip interface')
        commands.append('show ipv6 interface')

        interfaces_ip_out   = self.device.run_commands(commands)
        interfaces_ipv4_out = interfaces_ip_out[0].get('interfaces', {})
        interfaces_ipv6_out = interfaces_ip_out[1].get('interfaces', {})

        for interface_name, interface_details in interfaces_ipv4_out.iteritems():
            ipv4_list = list()
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = dict()
            if u'ipv4' not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name][u'ipv4'] = dict()
            ipv4_list.append(
                {
                    'address'   : interface_details.get('interfaceAddress', {}).get('primaryIp', {}).get('address'),
                    'masklen'   : interface_details.get('interfaceAddress', {}).get('primaryIp', {}).get('maskLen')
                }
            )
            for secondary_ip in interface_details.get('interfaceAddress', {}).get('secondaryIpsOrderedList', []):
                ipv4_list.append(
                    {
                        'address'   : secondary_ip.get('address'),
                        'masklen'   : secondary_ip.get('maskLen')
                    }
                )

            for ip in ipv4_list:
                if not ip.get('address'):
                    continue
                if ip.get('address') not in interfaces_ip.get(interface_name).get(u'ipv4'):
                    interfaces_ip[interface_name][u'ipv4'][ip.get('address')] = {
                        u'prefix_length': ip.get('masklen')
                    }

        for interface_name, interface_details in interfaces_ipv6_out.iteritems():
            ipv6_list = list()
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = dict()
            if u'ipv6' not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name][u'ipv6'] = dict()
            ipv6_list.append(
                {
                    'address'   : interface_details.get('linkLocal', {}).get('address'),
                    'masklen'   : int(interface_details.get('linkLocal', {}).get('subnet', '::/0').split('/')[-1])
                    # when no link-local set, address will be None and maslken 0
                }
            )
            for address in interface_details.get('addresses'):
                ipv6_list.append(
                    {
                        'address'   : address.get('address'),
                        'masklen'   : int(address.get('subnet').split('/')[-1])
                    }
                )
            for ip in ipv6_list:
                if not ip.get('address'):
                    continue
                if ip.get('address') not in interfaces_ip.get(interface_name).get(u'ipv6'):
                    interfaces_ip[interface_name][u'ipv6'][ip.get('address')] = {
                        u'prefix_length': ip.get('masklen')
                    }

        return interfaces_ip

    def get_mac_address_table(self):

        mac_table = list()

        commands = ['show mac address-table']

        mac_entries = []
        try:
            mac_entries = self.device.run_commands(commands)[0].get('unicastTable', {}).get('tableEntries', [])
        except Exception:
            return {}

        for mac_entry in mac_entries:
            vlan        = mac_entry.get('vlanId')
            interface   = mac_entry.get('interface')
            mac_raw     = mac_entry.get('macAddress')
            mac_str     = mac_raw.replace('.', '').replace(':', '')
            mac_format  = ':'.join([ mac_str[i:i+2] for i in range(12)[::2] ])
            static      = (mac_entry.get('entryType') == 'static')
            last_move   = mac_entry.get('lastMove', 0.0)
            moves       = mac_entry.get('moves', 0)
            mac_table.append(
                {
                    'mac'       : mac_format,
                    'interface' : interface,
                    'vlan'      : vlan,
                    'active'    : True,
                    'static'    : static,
                    'moves'     : moves,
                    'last_move' : last_move
                }
            )

        return mac_table

    def get_route_to(self, destination = '', protocol = ''):

        routes = dict()

        try:
            ipv = ''
            if IPNetwork(destination).version == 6:
                ipv = 'v6'
        except AddrFormatError:
            return 'Please specify a valid destination!'

        command = 'show ip{ipv} route {destination} detail'.format(
            ipv         = ipv,
            destination = destination
        )

        command_output = self.device.run_commands([command])[0]
        if ipv == 'v6':
            routes_out = command_output.get('routes', {})
        else:
            # on a multi-VRF configured device need to go through a loop and get for each instance
            routes_out = command_output.get('vrfs', {}).get('default', {}).get('routes', {})

        for prefix, route_details in routes_out.iteritems():
            if prefix not in routes.keys():
                routes[prefix] = list()
            route_protocol    = route_details.get('routeType').upper()
            preference  = route_details.get('preference')

            route = {
                'current_active'    : False,
                'last_active'       : False,
                'age'               : 0,
                'next_hop'          : u'',
                'protocol'          : route_protocol,
                'outgoing_interface': u'',
                'preference'        : preference,
                'inactive_reason'   : u'',
                'routing_table'     : u'default',
                'selected_next_hop' : False,
                'protocol_attributes': {}
            }
            if protocol == 'bgp':
                metric      = route_details.get('metric')
                command = 'show ip{ipv} bgp {destination} detail'.format(
                    ipv         = ipv,
                    destination = prefix
                )
                default_vrf_details = self.device.run_commands([command])[0].get('vrfs', {}).get('default', {})
                local_as   = default_vrf_details.get('asn')
                bgp_routes = default_vrf_details.get('bgpRouteEntries', {}).get(prefix, {}).get('bgpRoutePaths', [])
                for bgp_route_details in bgp_routes:
                    bgp_route = route.copy()
                    as_path = bgp_route_details.get('asPathEntry', {}).get('asPath', u'')
                    remote_as = int(as_path.split()[-1])
                    remote_address = bgp_route_details.get('routeDetail', {}).get('peerEntry', {}).get('peerAddr', '')
                    local_preference = bgp_route_details.get('localPreference')
                    next_hop = bgp_route_details.get('nextHop')
                    active_route = bgp_route_details.get('routeType', {}).get('active', False)
                    last_active = active_route # should find smth better
                    communities = bgp_route_details.get('routeDetail', {}).get('communityList', [])
                    preference2 = bgp_route_details.get('weight')
                    selected_next_hop = active_route
                    bgp_route.update({
                        'current_active'    : active_route,
                        'last_active'       : last_active,
                        'next_hop'          : next_hop,
                        'selected_next_hop' : active_route,
                        'protocol_attributes': {
                            'metric'            : metric,
                            'as_path'           : as_path,
                            'local_preference'  : local_preference,
                            'local_as'          : local_as,
                            'remote_as'         : remote_as,
                            'remote_address'    : remote_address,
                            'preference2'       : preference2,
                            'communities'       : communities
                        }
                    })
                    routes[prefix].append(bgp_route)
            else:
                for next_hop in route_details.get('vias'):
                    route_next_hop = route.copy()
                    route_next_hop.update(
                        {
                            'next_hop'          : next_hop.get('nexthopAddr'),
                            'outgoing_interface': next_hop.get('interface')
                        }
                    )
                    routes[prefix].append(route_next_hop)

        return routes

    def get_snmp_information(self):

        snmp_information = dict()

        commands = list()
        commands.append('show running-config | section snmp-server')
        raw_snmp_config = self.device.run_commands(commands, encoding='text')[0].get('output', '')

        snmp_config = napalm_base.helpers.textfsm_extractor(self, 'snmp_config', raw_snmp_config)

        if not snmp_config:
            return snmp_information

        snmp_information = {
            'contact'   : unicode(snmp_config[0].get('contact', '')),
            'location'  : unicode(snmp_config[0].get('location', '')),
            'chassis_id': unicode(snmp_config[0].get('chassis_id', '')),
            'community' : {}
        }

        for snmp_entry in snmp_config:
            community_name = unicode(snmp_entry.get('community', ''))
            if not community_name:
                continue
            snmp_information['community'][community_name] = {
                'acl': unicode(snmp_entry.get('acl', '')),
                'mode': unicode(snmp_entry.get('mode', 'ro').lower())
            }

        return snmp_information

    def get_users(self):

        def _sshkey_type(sshkey):
            if sshkey.startswith('ssh-rsa'):
                return 'ssh_rsa', sshkey
            elif sshkey.startswith('ssh-dss'):
                return 'ssh_dsa', sshkey
            return 'ssh_rsa', ''

        users = dict()

        commands = ['show user-account']
        user_items = self.device.run_commands(commands)[0].get('users', {})

        for user, user_details in user_items.iteritems():
            user_details.pop('username', '')
            sshkey_value = user_details.pop('sshAuthorizedKey', '')
            sshkey_type, sshkey_value = _sshkey_type(sshkey_value)
            user_details.update({
                'level': user_details.pop('privLevel', 0),
                'password': user_details.pop('secret', ''),
                'sshkeys': [sshkey_value]
            })
            users[user] = user_details

        return users

    def traceroute(self, destination, source='', ttl=0, timeout=0):

        _HOP_ENTRY_PROBE = [
            '\s+',
            '(',  # beginning of host_name (ip_address) RTT group
            '(',  # beginning of host_name (ip_address) group only
            '([a-zA-Z0-9\.:-]*)',  # hostname
            '\s+',
            '\(?([a-fA-F0-9\.:][^\)]*)\)?'  # IP Address between brackets
            ')?',  # end of host_name (ip_address) group only
            # also hostname/ip are optional -- they can or cannot be specified
            # if not specified, means the current probe followed the same path as the previous
            '\s+',
            '(\d+\.\d+)\s+ms',  # RTT
            '|\*',  # OR *, when non responsive hop
            ')'  # end of host_name (ip_address) RTT group
        ]

        _HOP_ENTRY = [
            '\s?',  # space before hop index?
            '(\d+)',  # hop index
        ]

        traceroute_result = {}

        source_opt = ''
        ttl_opt = ''
        timeout_opt = ''

        # if not ttl:
        #     ttl = 20

        probes = 3
        # in case will be added one further param to adjust the number of probes/hop

        if source:
            source_opt = '-s {source}'.format(source=source)
        if ttl:
            ttl_opt = '-m {ttl}'.format(ttl=ttl)
        if timeout:
            timeout_opt = '-w {timeout}'.format(timeout=timeout)
        else:
            timeout = 5

        command = 'traceroute {destination} {source_opt} {ttl_opt} {timeout_opt}'.format(
            destination=destination,
            source_opt=source_opt,
            ttl_opt=ttl_opt,
            timeout_opt=timeout_opt
        )

        try:
            traceroute_raw_output = self.device.run_commands([command], encoding='text')[0].get('output')
        except CommandErrorException:
            return {'error': 'Cannot execute traceroute on the device: {}'.format(command)}

        hop_regex = ''.join(_HOP_ENTRY + _HOP_ENTRY_PROBE * probes)

        traceroute_result['success'] = {}
        for line in traceroute_raw_output.splitlines():
            hop_search = re.search(hop_regex, line)
            if not hop_search:
                continue
            hop_details = hop_search.groups()
            hop_index = int(hop_details[0])
            previous_probe_host_name = '*'
            previous_probe_ip_address = '*'
            traceroute_result['success'][hop_index] = {'probes':{}}
            for probe_index in range(probes):
                host_name = hop_details[3+probe_index*5]
                ip_address = hop_details[4+probe_index*5]
                rtt = hop_details[5+probe_index*5]
                if rtt:
                    rtt = float(rtt)
                else:
                    rtt = timeout * 1000.0
                if not host_name:
                    host_name = previous_probe_host_name
                if not ip_address:
                    ip_address = previous_probe_ip_address
                if hop_details[1+probe_index*5] == '*':
                    host_name = '*'
                    ip_address = '*'
                traceroute_result['success'][hop_index]['probes'][probe_index+1] = {
                    'host_name': unicode(host_name),
                    'ip_address': unicode(ip_address),
                    'rtt': rtt
                }
                previous_probe_host_name = host_name
                previous_probe_ip_address = ip_address

        return traceroute_result
