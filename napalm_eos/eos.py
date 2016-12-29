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
from __future__ import print_function
from __future__ import unicode_literals

# std libs
import re
import time

from datetime import datetime
from collections import defaultdict
from netaddr import IPAddress
from netaddr import IPNetwork

from netaddr.core import AddrFormatError

# third party libs
import pyeapi
from pyeapi.eapilib import ConnectionError

# NAPALM base
import napalm_base.helpers
from napalm_base.base import NetworkDriver
from napalm_base.utils import string_parsers
from napalm_base.utils import py23_compat
from napalm_base.exceptions import ConnectionException, MergeConfigException, \
                        ReplaceConfigException, SessionLockedException, CommandErrorException

import napalm_base.constants as c
# local modules
# here add local imports
# e.g. import napalm_eos.helpers etc.


class EOSDriver(NetworkDriver):
    """Napalm driver for Arista EOS."""

    SUPPORTED_OC_MODELS = []

    _RE_BGP_INFO = re.compile('BGP neighbor is (?P<neighbor>.*?), remote AS (?P<as>.*?), .*') # noqa
    _RE_BGP_RID_INFO = re.compile('.*BGP version 4, remote router ID (?P<rid>.*?), VRF (?P<vrf>.*?)$') # noqa
    _RE_BGP_DESC = re.compile('\s+Description: (?P<description>.*?)')
    _RE_BGP_LOCAL = re.compile('Local AS is (?P<as>.*?),.*')
    _RE_BGP_PREFIX = re.compile('(\s*?)(?P<af>IPv[46]) Unicast:\s*(?P<sent>\d+)\s*(?P<received>\d+)') # noqa

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

        self.transport = optional_args.get('eos_transport', 'https')

        if self.transport == 'https':
            self.port = optional_args.get('port', 443)
        elif self.transport == 'http':
            self.port = optional_args.get('port', 80)

        self.enablepwd = optional_args.get('enable_password', '')

    def open(self):
        """Implementation of NAPALM method open."""
        try:
            if self.transport in ('http', 'https'):
                connection = pyeapi.client.connect(
                    transport=self.transport,
                    host=self.hostname,
                    username=self.username,
                    password=self.password,
                    port=self.port,
                    timeout=self.timeout
                )
            elif self.transport == 'socket':
                connection = pyeapi.client.connect(transport=self.transport)
            else:
                raise ConnectionException("Unknown transport: {}".format(self.transport))

            if self.device is None:
                self.device = pyeapi.client.Node(connection, enablepwd=self.enablepwd)
            # does not raise an Exception if unusable

            # let's try to run a very simple command
            self.device.run_commands(['show clock'], encoding='text')
        except ConnectionError as ce:
            # and this is raised either if device not avaiable
            # either if HTTP(S) agent is not enabled
            # show management api http-commands
            raise ConnectionException(ce.message)

    def close(self):
        """Implementation of NAPALM method close."""
        self.discard_config()

    def is_alive(self):
        return {
            'is_alive': True  # always true as eAPI is HTTP-based
        }

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
        """Implementation of NAPALM method load_replace_candidate."""
        self._load_config(filename, config, True)

    def load_merge_candidate(self, filename=None, config=None):
        """Implementation of NAPALM method load_merge_candidate."""
        self._load_config(filename, config, False)

    def compare_config(self):
        """Implementation of NAPALM method compare_config."""
        if self.config_session is None:
            return ''
        else:
            commands = ['show session-config named %s diffs' % self.config_session]
            result = self.device.run_commands(commands, encoding='text')[0]['output']

            result = '\n'.join(result.splitlines()[2:])

            return result.strip()

    def commit_config(self):
        """Implementation of NAPALM method commit_config."""
        commands = list()
        commands.append('copy startup-config flash:rollback-0')
        commands.append('configure session {}'.format(self.config_session))
        commands.append('commit')
        commands.append('write memory')

        self.device.run_commands(commands)
        self.config_session = None

    def discard_config(self):
        """Implementation of NAPALM method discard_config."""
        if self.config_session is not None:
            commands = list()
            commands.append('configure session {}'.format(self.config_session))
            commands.append('abort')
            self.device.run_commands(commands)
            self.config_session = None

    def rollback(self):
        """Implementation of NAPALM method rollback."""
        commands = list()
        commands.append('configure replace flash:rollback-0')
        commands.append('write memory')
        self.device.run_commands(commands)

    def get_facts(self):
        """Implementation of NAPALM method get_facts."""
        commands = []
        commands.append('show version')
        commands.append('show hostname')
        commands.append('show interfaces')

        result = self.device.run_commands(commands)

        version = result[0]
        hostname = result[1]
        interfaces_dict = result[2]['interfaces']

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

        for interface, values in output['interfaces'].items():
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
            interfaces[interface]['mac_address'] = napalm_base.helpers.convert(
                napalm_base.helpers.mac, values.pop('physicalAddress', u''))

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
        commands = ['show interfaces']
        output = self.device.run_commands(commands)
        interface_counters = defaultdict(dict)
        for interface, data in output[0]['interfaces'].items():
            if data['hardware'] == 'subinterface':
                # Subinterfaces will never have counters so no point in parsing them at all
                continue
            counters = data.get('interfaceCounters', {})
            interface_counters[interface].update(
                tx_octets=counters.get('outOctets', -1),
                rx_octets=counters.get('inOctets', -1),
                tx_unicast_packets=counters.get('outUcastPkts', -1),
                rx_unicast_packets=counters.get('inUcastPkts', -1),
                tx_multicast_packets=counters.get('outMulticastPkts', -1),
                rx_multicast_packets=counters.get('inMulticastPkts', -1),
                tx_broadcast_packets=counters.get('outBroadcastPkts', -1),
                rx_broadcast_packets=counters.get('inBroadcastPkts', -1),
                tx_discards=counters.get('outDiscards', -1),
                rx_discards=counters.get('inDiscards', -1),
                tx_errors=counters.get('totalOutErrors', -1),
                rx_errors=counters.get('totalInErrors', -1)
            )
        return interface_counters

    def get_bgp_neighbors(self):

        def get_re_group(res, key, default=None):
            """ Small helper to retrive data from re match groups"""
            try:
                return res.group(key)
            except KeyError:
                return default

        NEIGHBOR_FILTER = 'bgp neighbors vrf all | include remote AS | remote router ID |IPv[46] Unicast:.*[0-9]+|^Local AS|Desc|BGP state'  # noqa
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
            for vrf, vrf_data in summary['vrfs'].items():
                bgp_counters[vrf]['router_id'] = vrf_data['routerId']
                for peer, peer_data in vrf_data['peers'].items():
                    if peer_data['peerState'] == 'Idle':
                        is_enabled = True if peer_data['peerStateIdleReason'] != 'Admin' else False
                    else:
                        is_enabled = True
                    peer_info = {
                        'is_up': peer_data['peerState'] == 'Established',
                        'is_enabled': is_enabled,
                        'uptime': int(time.time() - peer_data['upDownTime'])
                    }
                    bgp_counters[vrf]['peers'][napalm_base.helpers.ip(peer)] = peer_info
        lines = []
        [lines.extend(x['output'].splitlines()) for x in output_neighbor_cmds]
        while lines:
            """
            Raw output from the command looks like the following:

              BGP neighbor is 1.1.1.1, remote AS 1, external link
                Description: Very info such descriptive
                BGP version 4, remote router ID 1.1.1.1, VRF my_vrf
                BGP state is Idle, Administratively shut down
                 IPv4 Unicast:         683        78
                 IPv6 Unicast:           0         0
              Local AS is 2, local router ID 2.2.2.2
            """
            neighbor_info = re.match(self._RE_BGP_INFO, lines.pop(0))
            # this line can be either description or rid info
            next_line = lines.pop(0)
            desc = re.match(self._RE_BGP_DESC, next_line)
            if desc is None:
                rid_info = re.match(self._RE_BGP_RID_INFO, next_line)
                desc = ''
            else:
                rid_info = re.match(self._RE_BGP_RID_INFO, lines.pop(0))
                desc = desc.group('description')
            lines.pop(0)
            v4_stats = re.match(self._RE_BGP_PREFIX, lines.pop(0))
            v6_stats = re.match(self._RE_BGP_PREFIX, lines.pop(0))
            local_as = re.match(self._RE_BGP_LOCAL, lines.pop(0))
            data = {
                'remote_as': int(neighbor_info.group('as')),
                'remote_id': napalm_base.helpers.ip(get_re_group(rid_info, 'rid', '0.0.0.0')),
                'local_as': int(local_as.group('as')),
                'description': py23_compat.text_type(desc),
                'address_family': {
                    'ipv4': {
                        'sent_prefixes': int(get_re_group(v4_stats, 'sent', -1)),
                        'received_prefixes': int(get_re_group(v4_stats, 'received', -1)),
                        'accepted_prefixes': -1
                    },
                    'ipv6': {
                        'sent_prefixes': int(get_re_group(v6_stats, 'sent', -1)),
                        'received_prefixes': int(get_re_group(v6_stats, 'received', -1)),
                        'accepted_prefixes': -1
                    }
                }
            }
            peer_addr = napalm_base.helpers.ip(neighbor_info.group('neighbor'))
            vrf = rid_info.group('vrf')
            if peer_addr not in bgp_counters[vrf]['peers']:
                bgp_counters[vrf]['peers'][peer_addr] = {
                    'is_up': False,  # if not found, means it was not found in the oper stats
                                     # i.e. neighbor down,
                    'uptime': 0,
                    'is_enabled': True
                }
            bgp_counters[vrf]['peers'][peer_addr].update(data)
        if 'default' in bgp_counters:
            bgp_counters['global'] = bgp_counters.pop('default')
        return dict(bgp_counters)

    def get_environment(self):
        def extract_temperature_data(data):
            for s in data:
                temp = s['currentTemperature'] if 'currentTemperature' in s else 0.0
                name = s['name']
                values = {
                   'temperature': temp,
                   'is_alert': temp > s['overheatThreshold'],
                   'is_critical': temp > s['criticalThreshold']
                }
                yield name, values

        sh_version_out = self.device.run_commands(['show version'])
        is_veos = sh_version_out[0]['modelName'].lower() == 'veos'
        commands = [
            'show environment cooling',
            'show environment temperature'
        ]
        if not is_veos:
            commands.append('show environment power')
            fans_output, temp_output, power_output = self.device.run_commands(commands)
        else:
            fans_output, temp_output = self.device.run_commands(commands)
        environment_counters = {
            'fans': {},
            'temperature': {},
            'power': {},
            'cpu': {}
        }
        cpu_output = self.device.run_commands(['show processes top once'],
                                              encoding='text')[0]['output']
        for slot in fans_output['fanTraySlots']:
            environment_counters['fans'][slot['label']] = {'status': slot['status'] == 'ok'}
        # First check FRU's
        for fru_type in ['cardSlots', 'powerSupplySlots']:
            for fru in temp_output[fru_type]:
                t = {name: value for name, value in extract_temperature_data(fru['tempSensors'])}
                environment_counters['temperature'].update(t)
        # On board sensors
        parsed = {n: v for n, v in extract_temperature_data(temp_output['tempSensors'])}
        environment_counters['temperature'].update(parsed)
        if not is_veos:
            for psu, data in power_output['powerSupplies'].items():
                environment_counters['power'][psu] = {
                    'status': data['state'] == 'ok',
                    'capacity': data['capacity'],
                    'output': data['outputPower']
                }
        cpu_lines = cpu_output.splitlines()
        # Matches either of
        # Cpu(s):  5.2%us,  1.4%sy,  0.0%ni, 92.2%id,  0.6%wa,  0.3%hi,  0.4%si,  0.0%st ( 4.16 > )
        # %Cpu(s):  4.2 us,  0.9 sy,  0.0 ni, 94.6 id,  0.0 wa,  0.1 hi,  0.2 si,  0.0 st ( 4.16 < )
        m = re.match('.*ni, (?P<idle>.*).id.*', cpu_lines[2])
        environment_counters['cpu'][0] = {
            '%usage': round(100 - float(m.group('idle')), 1)
        }
        # Matches either of
        # Mem:   3844356k total,  3763184k used,    81172k free,    16732k buffers ( 4.16 > )
        # KiB Mem:  32472080 total,  5697604 used, 26774476 free,   372052 buffers ( 4.16 < )
        mem_regex = '.*total,\s+(?P<used>\d+)[k\s]+used,\s+(?P<free>\d+)[k\s]+free,.*'
        m = re.match(mem_regex, cpu_lines[3])
        environment_counters['memory'] = {
            'available_ram': int(m.group('free')),
            'used_ram': int(m.group('used'))
        }
        return environment_counters

    def get_lldp_neighbors_detail(self, interface=''):

        lldp_neighbors_out = dict()

        filters = list()
        if interface:
            filters.append(interface)

        commands = list()
        commands.append(
            'show lldp neighbors {filters} detail'.format(
                filters=' '.join(filters)
            )
        )

        lldp_neighbors_in = {}
        lldp_neighbors_in = self.device.run_commands(commands)[0].get('lldpNeighbors', {})

        for interface in lldp_neighbors_in:
            interface_neighbors = lldp_neighbors_in.get(interface).get('lldpNeighborInfo', {})
            if not interface_neighbors:
                # in case of empty infos
                continue

            # it is provided a list of neighbors per interface
            for neighbor in interface_neighbors:
                if interface not in lldp_neighbors_out.keys():
                    lldp_neighbors_out[interface] = list()
                capabilities = neighbor.get('systemCapabilities')
                capabilities_list = list(capabilities.keys())
                capabilities_list.sort()
                lldp_neighbors_out[interface].append(
                    {
                        'parent_interface': interface,  # no parent interfaces
                        'remote_port':
                            neighbor.get('neighborInterfaceInfo', {}).get('interfaceId', u''),
                        'remote_port_description': u'',
                        'remote_system_name': neighbor.get('systemName', u''),
                        'remote_system_description': neighbor.get('systemDescription', u''),
                        'remote_chassis_id': napalm_base.helpers.mac(
                            neighbor.get('chassisId', u'')),
                        'remote_system_capab': py23_compat.text_type(', '.join(capabilities_list)),
                        'remote_system_enable_capab': py23_compat.text_type(', '.join(
                            [capability for capability in capabilities_list
                             if capabilities[capability]]))
                    }
                )
        return lldp_neighbors_out

    def cli(self, commands):
        cli_output = dict()

        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            try:
                cli_output[py23_compat.text_type(command)] = self.device.run_commands(
                    [command], encoding='text')[0].get('output')
                # not quite fair to not exploit rum_commands
                # but at least can have better control to point to wrong command in case of failure
            except pyeapi.eapilib.CommandError:
                # for sure this command failed
                cli_output[py23_compat.text_type(command)] = 'Invalid command: "{cmd}"'.format(
                    cmd=command
                )
                raise CommandErrorException(str(cli_output))
            except Exception as e:
                # something bad happened
                msg = 'Unable to execute command "{cmd}": {err}'.format(cmd=command, err=e)
                cli_output[py23_compat.text_type(command)] = msg
                raise CommandErrorException(str(cli_output))

        return cli_output

    def get_bgp_config(self, group='', neighbor=''):
        """Implementation of NAPALM method get_bgp_config."""
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
            'remote-as': int,
            'ebgp-multihop': int,
            'local-v4-addr': py23_compat.text_type,
            'local-v6-addr': py23_compat.text_type,
            'local-as': int,
            'remove-private-as': bool,
            'next-hop-self': bool,
            'description': py23_compat.text_type,
            'route-reflector-client': bool,
            'password': py23_compat.text_type,
            'route-map': py23_compat.text_type,
            'apply-groups': list,
            'type': py23_compat.text_type,
            'import-policy': py23_compat.text_type,
            'export-policy': py23_compat.text_type,
            'multipath': bool
        }

        _DATATYPE_DEFAULT_ = {
            py23_compat.text_type: '',
            int: 0,
            bool: False,
            list: []
        }

        def parse_options(options, default_value=False):

            if not options:
                return dict()

            config_property = options[0]
            field_name = _PROPERTY_FIELD_MAP_.get(config_property)
            field_type = _PROPERTY_TYPE_MAP_.get(config_property)
            field_value = _DATATYPE_DEFAULT_.get(field_type)  # to get the default value

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
                    return {'authentication_key': py23_compat.text_type(options[2])}
                    # returns the MD5 password
                if config_property == 'route-map':
                    direction = None
                    if len(options) == 3:
                        direction = options[2]
                        field_value = field_type(options[1])  # the name of the policy
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
            default_value = False
            bgp_conf_line = bgp_conf_line.strip()
            if bgp_conf_line.startswith('router bgp'):
                local_as = int(bgp_conf_line.replace('router bgp', '').strip())
                continue
            if not (bgp_conf_line.startswith('neighbor') or
                    bgp_conf_line.startswith('no neighbor')):
                continue
            if bgp_conf_line.startswith('no'):
                default_value = True
            bgp_conf_line = bgp_conf_line.replace('no neighbor ', '').replace('neighbor ', '')
            bgp_conf_line_details = bgp_conf_line.split()
            group_or_neighbor = py23_compat.text_type(bgp_conf_line_details[0])
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
                # that way we avoid one more loop to
                # match the neighbors with the group they belong to
                # directly will apend the neighbor in the neighbor list of the group at the end
                if last_peer_group not in bgp_neighbors.keys():
                    bgp_neighbors[last_peer_group] = dict()
                if peer_address not in bgp_neighbors[last_peer_group]:
                    bgp_neighbors[last_peer_group][peer_address] = dict()
                    bgp_neighbors[last_peer_group][peer_address].update({
                        key: _DATATYPE_DEFAULT_.get(_PROPERTY_TYPE_MAP_.get(prop))
                        for prop, key in _PEER_FIELD_MAP_.items()
                    })  # populating with default values
                    bgp_neighbors[last_peer_group][peer_address].update({
                        'prefix_limit': {},
                        'local_as': local_as,
                        'authentication_key': u''
                    })  # few more default values
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
                        key: _DATATYPE_DEFAULT_.get(_PROPERTY_TYPE_MAP_.get(prop))
                        for prop, key in _GROUP_FIELD_MAP_.items()
                    })
                    bgp_config[group_name].update({
                        'prefix_limit': {},
                        'neighbors': {},
                        'local_as': local_as
                    })  # few more default values
                bgp_config[group_name].update(
                    parse_options(options, default_value)
                )
            except Exception:
                # for other kind of exception pass to next line
                continue

        for group, peers in bgp_neighbors.items():
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
            interface = py23_compat.text_type(neighbor.get('interface'))
            mac_raw = neighbor.get('hwAddress')
            ip = py23_compat.text_type(neighbor.get('address'))
            age = float(neighbor.get('age'))
            arp_table.append(
                {
                    'interface': interface,
                    'mac': napalm_base.helpers.mac(mac_raw),
                    'ip': napalm_base.helpers.ip(ip),
                    'age': age
                }
            )

        return arp_table

    def get_ntp_servers(self):
        commands = ['show running-config | section ntp']

        raw_ntp_config = self.device.run_commands(commands, encoding='text')[0].get('output', '')

        ntp_config = napalm_base.helpers.textfsm_extractor(self, 'ntp_peers', raw_ntp_config)

        return {py23_compat.text_type(ntp_peer.get('ntppeer')): {}
                for ntp_peer in ntp_config if ntp_peer.get('ntppeer', '')}

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
        # pyeapi.eapilib.CommandError: CLI command 2 of 2 'show ntp associations'
        # failed: unconverted command
        # JSON output not yet implemented...

        ntp_assoc = self.device.run_commands(commands, encoding='text')[0].get('output', '\n\n')
        ntp_assoc_lines = ntp_assoc.splitlines()[2:]

        for ntp_assoc in ntp_assoc_lines:
            line_search = re.search(REGEX, ntp_assoc, re.I)
            if not line_search:
                continue  # pattern not found
            line_groups = line_search.groups()
            try:
                ntp_stats.append({
                    'remote': py23_compat.text_type(line_groups[1]),
                    'synchronized': (line_groups[0] == '*'),
                    'referenceid': py23_compat.text_type(line_groups[2]),
                    'stratum': int(line_groups[3]),
                    'type': py23_compat.text_type(line_groups[4]),
                    'when': py23_compat.text_type(line_groups[5]),
                    'hostpoll': int(line_groups[6]),
                    'reachability': int(line_groups[7]),
                    'delay': float(line_groups[8]),
                    'offset': float(line_groups[9]),
                    'jitter': float(line_groups[10])
                })
            except Exception:
                continue  # jump to next line

        return ntp_stats

    def get_interfaces_ip(self):

        interfaces_ip = dict()

        interfaces_ipv4_out = self.device.run_commands(['show ip interface'])[0]['interfaces']
        try:
            interfaces_ipv6_out = self.device.run_commands(['show ipv6 interface'])[0]['interfaces']
        except pyeapi.eapilib.CommandError as e:
            if 'No IPv6 configured interfaces' in e.message:
                interfaces_ipv6_out = {}
            else:
                raise

        for interface_name, interface_details in interfaces_ipv4_out.items():
            ipv4_list = list()
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = dict()

            if u'ipv4' not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name][u'ipv4'] = dict()
            if u'ipv6' not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name][u'ipv6'] = dict()

            iface_details = interface_details.get('interfaceAddress', {})
            if iface_details.get('primaryIp', {}).get('address') != '0.0.0.0':
                ipv4_list.append(
                    {
                        'address': napalm_base.helpers.ip(iface_details.get(
                            'primaryIp', {}).get('address')),
                        'masklen': iface_details.get('primaryIp', {}).get('maskLen')
                    }
                )
            for secondary_ip in iface_details.get('secondaryIpsOrderedList', []):
                ipv4_list.append(
                    {
                        'address': napalm_base.helpers.ip(secondary_ip.get('address')),
                        'masklen': secondary_ip.get('maskLen')
                    }
                )

            for ip in ipv4_list:
                if not ip.get('address'):
                    continue
                if ip.get('address') not in interfaces_ip.get(interface_name).get(u'ipv4'):
                    interfaces_ip[interface_name][u'ipv4'][ip.get('address')] = {
                        u'prefix_length': ip.get('masklen')
                    }

        for interface_name, interface_details in interfaces_ipv6_out.items():
            ipv6_list = list()
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = dict()

            if u'ipv4' not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name][u'ipv4'] = dict()
            if u'ipv6' not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name][u'ipv6'] = dict()

            ipv6_list.append(
                {
                    'address': napalm_base.helpers.convert(
                        napalm_base.helpers.ip, interface_details.get('linkLocal', {})
                                                                 .get('address')),
                    'masklen': int(
                        interface_details.get('linkLocal', {}).get('subnet', '::/0').split('/')[-1])
                    # when no link-local set, address will be None and maslken 0
                }
            )
            for address in interface_details.get('addresses'):
                ipv6_list.append(
                    {
                        'address': napalm_base.helpers.ip(address.get('address')),
                        'masklen': int(address.get('subnet').split('/')[-1])
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
            mac_entries = self.device.run_commands(commands)[0].get(
                'unicastTable', {}).get('tableEntries', [])
        except Exception:
            return {}

        for mac_entry in mac_entries:
            vlan = mac_entry.get('vlanId')
            interface = mac_entry.get('interface')
            mac_raw = mac_entry.get('macAddress')
            static = (mac_entry.get('entryType') == 'static')
            last_move = mac_entry.get('lastMove', 0.0)
            moves = mac_entry.get('moves', 0)
            mac_table.append(
                {
                    'mac': napalm_base.helpers.mac(mac_raw),
                    'interface': interface,
                    'vlan': vlan,
                    'active': True,
                    'static': static,
                    'moves': moves,
                    'last_move': last_move
                }
            )

        return mac_table

    def get_route_to(self, destination='', protocol=''):
        routes = dict()

        if protocol.lower() == 'direct':
            protocol = 'connected'

        try:
            ipv = ''
            if IPNetwork(destination).version == 6:
                ipv = 'v6'
        except AddrFormatError:
            return 'Please specify a valid destination!'

        command = 'show ip{ipv} route {destination} {protocol} detail'.format(
            ipv=ipv,
            destination=destination,
            protocol=protocol,
        )

        command_output = self.device.run_commands([command])[0]
        if ipv == 'v6':
            routes_out = command_output.get('routes', {})
        else:
            # on a multi-VRF configured device need to go through a loop and get for each instance
            routes_out = command_output.get('vrfs', {}).get('default', {}).get('routes', {})

        for prefix, route_details in routes_out.items():
            if prefix not in routes.keys():
                routes[prefix] = list()
            route_protocol = route_details.get('routeType').upper()
            preference = route_details.get('preference', 0)

            route = {
                'current_active': False,
                'last_active': False,
                'age': 0,
                'next_hop': u'',
                'protocol': route_protocol,
                'outgoing_interface': u'',
                'preference': preference,
                'inactive_reason': u'',
                'routing_table': u'default',
                'selected_next_hop': False,
                'protocol_attributes': {}
            }
            if protocol == 'bgp':
                metric = route_details.get('metric')
                command = 'show ip{ipv} bgp {destination} detail'.format(
                    ipv=ipv,
                    destination=prefix
                )
                default_vrf_details = self.device.run_commands([command])[0].get(
                    'vrfs', {}).get('default', {})
                local_as = default_vrf_details.get('asn')
                bgp_routes = default_vrf_details.get(
                    'bgpRouteEntries', {}).get(prefix, {}).get('bgpRoutePaths', [])
                for bgp_route_details in bgp_routes:
                    bgp_route = route.copy()
                    as_path = bgp_route_details.get('asPathEntry', {}).get('asPath', u'')
                    remote_as = int(as_path.split()[-1])
                    remote_address = napalm_base.helpers.ip(bgp_route_details.get(
                        'routeDetail', {}).get('peerEntry', {}).get('peerAddr', ''))
                    local_preference = bgp_route_details.get('localPreference')
                    next_hop = napalm_base.helpers.ip(bgp_route_details.get('nextHop'))
                    active_route = bgp_route_details.get('routeType', {}).get('active', False)
                    last_active = active_route  # should find smth better
                    communities = bgp_route_details.get('routeDetail', {}).get('communityList', [])
                    preference2 = bgp_route_details.get('weight')
                    bgp_route.update({
                        'current_active': active_route,
                        'last_active': last_active,
                        'next_hop': next_hop,
                        'selected_next_hop': active_route,
                        'protocol_attributes': {
                            'metric': metric,
                            'as_path': as_path,
                            'local_preference': local_preference,
                            'local_as': local_as,
                            'remote_as': remote_as,
                            'remote_address': remote_address,
                            'preference2': preference2,
                            'communities': communities
                        }
                    })
                    routes[prefix].append(bgp_route)
            else:
                for next_hop in route_details.get('vias'):
                    route_next_hop = route.copy()
                    if next_hop.get('nexthopAddr') is None:
                        route_next_hop.update(
                            {
                                'next_hop': '',
                                'outgoing_interface': next_hop.get('interface')
                            }
                        )
                    else:
                        route_next_hop.update(
                            {
                                'next_hop': napalm_base.helpers.ip(next_hop.get('nexthopAddr')),
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
            'contact': py23_compat.text_type(snmp_config[0].get('contact', '')),
            'location': py23_compat.text_type(snmp_config[0].get('location', '')),
            'chassis_id': py23_compat.text_type(snmp_config[0].get('chassis_id', '')),
            'community': {}
        }

        for snmp_entry in snmp_config:
            community_name = py23_compat.text_type(snmp_entry.get('community', ''))
            if not community_name:
                continue
            snmp_information['community'][community_name] = {
                'acl': py23_compat.text_type(snmp_entry.get('acl', '')),
                'mode': py23_compat.text_type(snmp_entry.get('mode', 'ro').lower())
            }

        return snmp_information

    def get_users(self):

        def _sshkey_type(sshkey):
            if sshkey.startswith('ssh-rsa'):
                return u'ssh_rsa', py23_compat.text_type(sshkey)
            elif sshkey.startswith('ssh-dss'):
                return u'ssh_dsa', py23_compat.text_type(sshkey)
            return u'ssh_rsa', u''

        users = dict()

        commands = ['show user-account']
        user_items = self.device.run_commands(commands)[0].get('users', {})

        for user, user_details in user_items.items():
            user_details.pop('username', '')
            sshkey_value = user_details.pop('sshAuthorizedKey', '')
            sshkey_type, sshkey_value = _sshkey_type(sshkey_value)
            user_details.update({
                'level': user_details.pop('privLevel', 0),
                'password': py23_compat.text_type(user_details.pop('secret', '')),
                'sshkeys': [sshkey_value]
            })
            users[user] = user_details

        return users

    def traceroute(self,
                   destination,
                   source=c.TRACEROUTE_SOURCE,
                   ttl=c.TRACEROUTE_TTL,
                   timeout=c.TRACEROUTE_TIMEOUT):

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
            traceroute_raw_output = self.device.run_commands(
                [command], encoding='text')[0].get('output')
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
            traceroute_result['success'][hop_index] = {'probes': {}}
            for probe_index in range(probes):
                host_name = hop_details[3+probe_index*5]
                hop_addr = hop_details[4+probe_index*5]
                ip_address = napalm_base.helpers.convert(
                    napalm_base.helpers.ip, hop_addr, hop_addr
                )
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
                    'host_name': py23_compat.text_type(host_name),
                    'ip_address': py23_compat.text_type(ip_address),
                    'rtt': rtt
                }
                previous_probe_host_name = host_name
                previous_probe_ip_address = ip_address

        return traceroute_result

    def get_bgp_neighbors_detail(self, neighbor_address=''):
        """Implementation of get_bgp_neighbors_detail"""
        def _parse_per_peer_bgp_detail(peer_output):
            """This function parses the raw data per peer and returns a
            json structure per peer.
            """

            int_fields = ['local_as', 'remote_as',
                          'local_port', 'remote_port', 'local_port',
                          'input_messages', 'output_messages', 'input_updates',
                          'output_updates', 'messages_queued_out', 'holdtime',
                          'configured_holdtime', 'keepalive',
                          'configured_keepalive', 'advertised_prefix_count',
                          'received_prefix_count']

            peer_details = []

            # Using preset template to extract peer info
            peer_info = (
                napalm_base.helpers.textfsm_extractor(
                    self, 'bgp_detail', peer_output))

            for item in peer_info:

                # Determining a few other fields in the final peer_info
                item['up'] = (
                    True if item['up'] == "up" else False)
                item['local_address_configured'] = (
                    True if item['local_address'] else False)
                item['multihop'] = (
                    False if item['multihop'] == 0 or
                    item['multihop'] == '' else True)

                # TODO: The below fields need to be retrieved
                # Currently defaulting their values to False or 0
                item['multipath'] = False
                item['remove_private_as'] = False
                item['suppress_4byte_as'] = False
                item['local_as_prepend'] = False
                item['flap_count'] = 0
                item['active_prefix_count'] = 0
                item['suppressed_prefix_count'] = 0

                # Converting certain fields into int
                for key in int_fields:
                    item[key] = napalm_base.helpers.convert(int, item[key], 0)

                # Conforming with the datatypes defined by the base class
                item['export_policy'] = (
                    napalm_base.helpers.convert(
                        py23_compat.text_type, item['export_policy']))
                item['last_event'] = (
                    napalm_base.helpers.convert(
                        py23_compat.text_type, item['last_event']))
                item['remote_address'] = napalm_base.helpers.ip(item['remote_address'])
                item['previous_connection_state'] = (
                    napalm_base.helpers.convert(
                        py23_compat.text_type, item['previous_connection_state']))
                item['import_policy'] = (
                    napalm_base.helpers.convert(
                        py23_compat.text_type, item['import_policy']))
                item['connection_state'] = (
                    napalm_base.helpers.convert(
                        py23_compat.text_type, item['connection_state']))
                item['routing_table'] = (
                    napalm_base.helpers.convert(
                        py23_compat.text_type, item['routing_table']))
                item['router_id'] = napalm_base.helpers.ip(item['router_id'])
                item['local_address'] = napalm_base.helpers.convert(
                    napalm_base.helpers.ip, item['local_address'])

                peer_details.append(item)

            return peer_details

        def _append(bgp_dict, peer_info):

            remote_as = peer_info['remote_as']
            vrf_name = peer_info['routing_table']

            if vrf_name not in bgp_dict.keys():
                bgp_dict[vrf_name] = {}
            if remote_as not in bgp_dict[vrf_name].keys():
                bgp_dict[vrf_name][remote_as] = []

            bgp_dict[vrf_name][remote_as].append(peer_info)

        commands = []
        summary_commands = []
        if not neighbor_address:
            commands.append('show ip bgp neighbors vrf all')
            commands.append('show ipv6 bgp neighbors vrf all')
            summary_commands.append('show ip bgp summary vrf all')
            summary_commands.append('show ipv6 bgp summary vrf all')
        else:
            try:
                peer_ver = IPAddress(neighbor_address).version
            except Exception as e:
                raise e

            if peer_ver == 4:
                commands.append('show ip bgp neighbors %s vrf all' %
                                neighbor_address)
                summary_commands.append('show ip bgp summary vrf all')
            elif peer_ver == 6:
                commands.append('show ipv6 bgp neighbors %s vrf all' %
                                neighbor_address)
                summary_commands.append('show ipv6 bgp summary vrf all')

        raw_output = (
            self.device.run_commands(commands, encoding='text'))
        bgp_summary = (
            self.device.run_commands(summary_commands, encoding='json'))

        bgp_detail_info = {}

        v4_peer_info = []
        v6_peer_info = []

        if neighbor_address:
            peer_info = _parse_per_peer_bgp_detail(raw_output[0]['output'])

            if peer_ver == 4:
                v4_peer_info.append(peer_info[0])
            else:
                v6_peer_info.append(peer_info[0])

        else:
            # Using preset template to extract peer info
            v4_peer_info = _parse_per_peer_bgp_detail(raw_output[0]['output'])
            v6_peer_info = _parse_per_peer_bgp_detail(raw_output[1]['output'])

        for peer_info in v4_peer_info:

            vrf_name = peer_info['routing_table']
            peer_remote_addr = peer_info['remote_address']
            peer_info['accepted_prefix_count'] = (
                bgp_summary[0]['vrfs'][vrf_name]['peers'][peer_remote_addr]['prefixAccepted']
                if peer_remote_addr in bgp_summary[0]['vrfs'][vrf_name]['peers'].keys()
                else 0
            )

            _append(bgp_detail_info, peer_info)

        for peer_info in v6_peer_info:

            vrf_name = peer_info['routing_table']
            peer_remote_addr = peer_info['remote_address']
            peer_info['accepted_prefix_count'] = (
                bgp_summary[1]['vrfs'][vrf_name]['peers'][peer_remote_addr]['prefixAccepted']
                if peer_remote_addr in bgp_summary[1]['vrfs'][vrf_name]['peers'].keys()
                else 0
            )

            _append(bgp_detail_info, peer_info)

        return bgp_detail_info

    def get_optics(self):

        command = ['show interfaces transceiver']

        output = (
            self.device.run_commands(
                command, encoding='json')[0]['interfaces'])

        # Formatting data into return data structure
        optics_detail = {}

        for port, port_values in output.items():
            port_detail = {}

            port_detail['physical_channels'] = {}
            port_detail['physical_channels']['channel'] = []

            # Defaulting avg, min, max values to 0.0 since device does not
            # return these values
            optic_states = {
                'index': 0,
                'state': {
                    'input_power': {
                        'instant': (port_values['rxPower']
                                    if 'rxPower' in port_values else 0.0),
                        'avg': 0.0,
                        'min': 0.0,
                        'max': 0.0
                    },
                    'output_power': {
                        'instant': (port_values['txPower']
                                    if 'txPower' in port_values else 0.0),
                        'avg': 0.0,
                        'min': 0.0,
                        'max': 0.0
                    },
                    'laser_bias_current': {
                        'instant': (port_values['txBias']
                                    if 'txBias' in port_values else 0.0),
                        'avg': 0.0,
                        'min': 0.0,
                        'max': 0.0
                    }
                }
            }

            port_detail['physical_channels']['channel'].append(optic_states)
            optics_detail[port] = port_detail

        return optics_detail

    def get_config(self, retrieve="all"):
        """get_config implementation for EOS."""
        get_startup = retrieve == "all" or retrieve == "startup"
        get_running = retrieve == "all" or retrieve == "running"
        get_candidate = (retrieve == "all" or retrieve == "candidate") and self.config_session

        if retrieve == "all":
            commands = ['show startup-config',
                        'show running-config']

            if self.config_session:
                commands.append('show session-config named {}'.format(self.config_session))

            output = self.device.run_commands(commands, encoding="text")
            return {
                'startup': py23_compat.text_type(output[0]['output']) if get_startup else u"",
                'running': py23_compat.text_type(output[1]['output']) if get_running else u"",
                'candidate': py23_compat.text_type(output[2]['output']) if get_candidate else u"",
            }
        elif get_startup or get_running:
            commands = ['show {}-config'.format(retrieve)]
            output = self.device.run_commands(commands, encoding="text")
            return {
                'startup': py23_compat.text_type(output[0]['output']) if get_startup else u"",
                'running': py23_compat.text_type(output[0]['output']) if get_running else u"",
                'candidate': "",
            }
        elif get_candidate:
            commands = ['show session-config named {}'.format(self.config_session)]
            output = self.device.run_commands(commands, encoding="text")
            return {
                'startup': "",
                'running': "",
                'candidate': py23_compat.text_type(output[0]['output']),
            }
        elif retrieve == "candidate":
            # If we get here it means that we want the candidate but there is none.
            return {
                'startup': "",
                'running': "",
                'candidate': "",
            }
        else:
            raise Exception("Wrong retrieve filter: {}".format(retrieve))

    def get_network_instances(self, name=''):
        """get_network_instances implementation for EOS."""

        commands = ['show vrf']

        # This command has no JSON yet
        raw_output = self.device.run_commands(commands, encoding='text')[0].get('output', '')

        output = napalm_base.helpers.textfsm_extractor(self, 'vrf', raw_output)
        vrfs = dict()
        all_vrf_interfaces = dict()
        for vrf in output:
            if (vrf.get('route_distinguisher', '') == "<not set>" or
                    vrf.get('route_distinguisher', '') == 'None'):
                vrf['route_distinguisher'] = u''
            else:
                vrf['route_distinguisher'] = py23_compat.text_type(vrf['route_distinguisher'])
            interfaces = dict()
            for interface_raw in vrf.get('interfaces', []):
                interface = interface_raw.split(',')
                for line in interface:
                    if line.strip() != '':
                        interfaces[py23_compat.text_type(line.strip())] = {}
                        all_vrf_interfaces[py23_compat.text_type(line.strip())] = {}

            vrfs[py23_compat.text_type(vrf['name'])] = {
                          u'name': py23_compat.text_type(vrf['name']),
                          u'type': u'L3VRF',
                          u'state': {
                              u'route_distinguisher': vrf['route_distinguisher'],
                          },
                          u'interfaces': {
                              u'interface': interfaces,
                          },
            }
        all_interfaces = self.get_interfaces_ip().keys()
        vrfs[u'default'] = {
            u'name': u'default',
            u'type': u'DEFAULT_INSTANCE',
            u'state': {
                u'route_distinguisher': u'',
            },
            u'interfaces': {
                u'interface': {
                    k: {} for k in all_interfaces if k not in all_vrf_interfaces.keys()
                },
            },
        }

        if name:
            if name in vrfs:
                return {py23_compat.text_type(name): vrfs[name]}
            return {}
        else:
            return vrfs

    def ping(self, destination, source=c.PING_SOURCE, ttl=c.PING_TTL, timeout=c.PING_TIMEOUT,
             size=c.PING_SIZE, count=c.PING_COUNT):
        """
        Execute ping on the device and returns a dictionary with the result.
        Output dictionary has one of following keys:
            * success
            * error
        In case of success, inner dictionary will have the followin keys:
            * probes_sent (int)
            * packet_loss (int)
            * rtt_min (float)
            * rtt_max (float)
            * rtt_avg (float)
            * rtt_stddev (float)
            * results (list)
        'results' is a list of dictionaries with the following keys:
            * ip_address (str)
            * rtt (float)
        """
        ping_dict = {}
        command = 'ping {}'.format(destination)
        command += ' timeout {}'.format(timeout)
        command += ' size {}'.format(size)
        command += ' repeat {}'.format(count)
        if source != '':
            command += ' source {}'.format(source)
        output = self.device.run_commands([command], encoding='text')[0]['output']
        if 'connect:' in output:
            ping_dict['error'] = output
        elif 'PING' in output:
            ping_dict['success'] = {
                                'probes_sent': 0,
                                'packet_loss': 0,
                                'rtt_min': 0.0,
                                'rtt_max': 0.0,
                                'rtt_avg': 0.0,
                                'rtt_stddev': 0.0,
                                'results': []
            }
            results_array = []
            for line in output.splitlines():
                fields = line.split()
                if 'icmp' in line:
                    if 'Unreachable' in line:
                        results_array.append({'ip_address': py23_compat.text_type(fields[1]),
                                              'rtt': 0.0})
                    elif fields[1] == 'bytes':
                        m = fields[6][5:]
                        results_array.append({'ip_address': py23_compat.text_type(fields[3]),
                                              'rtt': float(m)})
                elif 'packets transmitted' in line:
                    ping_dict['success']['probes_sent'] = int(fields[0])
                    ping_dict['success']['packet_loss'] = int(fields[0]) - int(fields[3])
                elif 'min/avg/max' in line:
                    m = fields[3].split('/')
                    ping_dict['success'].update({
                                    'rtt_min': float(m[0]),
                                    'rtt_avg': float(m[1]),
                                    'rtt_max': float(m[2]),
                                    'rtt_stddev': float(m[3]),
                    })
            ping_dict['success'].update({'results': results_array})
        return ping_dict
