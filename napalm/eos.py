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

import pyeapi
import re
from base import NetworkDriver
from exceptions import MergeConfigException, ReplaceConfigException, SessionLockedException
from datetime import datetime
import time
from napalm.utils import string_parsers
from collections import defaultdict


class EOSDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.config_session = None

    def open(self):
        connection = pyeapi.client.connect(
            transport='https',
            host=self.hostname,
            username=self.username,
            password=self.password,
            port=443,
            timeout=self.timeout
        )
        self.device = pyeapi.client.Node(connection)

    def close(self):
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
        self._load_config(filename, config, True)

    def load_merge_candidate(self, filename=None, config=None):
        self._load_config(filename, config, False)

    def compare_config(self):
        if self.config_session is None:
            return ''
        else:
            commands = ['show session-config named %s diffs' % self.config_session]
            result = self.device.run_commands(commands, encoding='text')[0]['output']

            result = '\n'.join(result.splitlines()[2:])

            return result.strip()

    def commit_config(self):
        commands = list()
        commands.append('copy startup-config flash:rollback-0')
        commands.append('configure session {}'.format(self.config_session))
        commands.append('commit')
        commands.append('write memory')

        self.device.run_commands(commands)
        self.config_session = None

    def discard_config(self):
        if self.config_session is not None:
            commands = list()
            commands.append('configure session {}'.format(self.config_session))
            commands.append('abort')
            self.device.run_commands(commands)
            self.config_session = None

    def rollback(self):
        commands = list()
        commands.append('configure replace flash:rollback-0')
        commands.append('write memory')
        self.device.run_commands(commands)

    def get_facts(self):
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

            interfaces[interface]['speed'] = values['bandwidth']
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


    def get_bgp_neighbors_detail(self, neighbor_address = ''):

        bgp_neighbors = dict()

        return bgp_neighbors

    def cli(self, command = ''):

        if not command:
            return 'Please enter a valid command!'

        commands = list()
        commands.append(command)

        output = ''

        try:
            output = self.device.run_commands(commands, encoding = 'text')[0].get('output')
        except pyeapi.eapilib.CommandError:
            return 'Unrecognized command {0}'.format(command)
        except Exception:
            return ''

        return output

    def get_arp_table(self,  interface = '', host = '', ip = '', mac = ''):

        arp_table = dict()

        filters = list()
        if interface:
            filters.append(
                'interface {name}'.format(
                    name = interface
                )
            )
        if host:
            filters.append(
                'host {name}'.format(
                    name = host
                )
            )
        if ip:
            filters.append(ip)
        if mac:
             filters.append(
                'mac-address {mac}'.format(
                    mac = mac
                )
            )

        commands = list()
        commands.append(
            'show arp {filters}'.format(
                filters = ' '.join(filters)
            )
        )

        ipv4_neighbors = []
        try:
            ipv4_neighbors = self.device.run_commands(commands)[0].get('ipV4Neighbors', [])
        except pyeapi.eapilib.CommandError:
            return {}

        for neighbor in ipv4_neighbors:
            interface   = neighbor.get('interface')
            mac         = neighbor.get('hwAddress')
            ip          = neighbor.get('address')
            age         = neighbor.get('age')
            if interface not in arp_table.keys():
                arp_table[interface] = list()
            arp_table[interface].append(
                {
                    'mac'   : mac,
                    'ip'    : ip,
                    'age'   : age
                }
            )

        return arp_table

    def get_mac_address_table(self, address = '', interface = '', dynamic = False, static = False, vlan = None):

        mac_table = dict()

        filters = list()
        if address:
             filters.append(
                'address {addr}'.format(
                    addr = address
                )
            )
        if interface:
             filters.append(
                'interface {name}'.format(
                    name = interface
                )
            )
        if dynamic is True:
            static = False
            filters.append('dynamic')
        if static is True:
            filters.append('static')
        if type(vlan) is int:
            filters.append(
                'vlan {id}'.format(
                    id = vlan
                )
            )

        commands = list()
        commands.append(
            'show mac address-table {filters}'.format(
                filters = ' '.join(filters)
            )
        )

        mac_entries = []
        try:
            mac_entries = self.device.run_commands(commands)[0].get('unicastTable', {}).get('tableEntries', [])
        except Exception:
            return {}

        for mac_entry in mac_entries:
            vlan        = int(mac_entry.get('vlanId'))
            interface   = mac_entry.get('interface')
            mac         = mac_entry.get('macAddress')
            static      = (mac_entry.get('entryType') == 'static')
            last_move   = mac_entry.get('lastMove')
            moves       = mac_entry.get('moves')
            if vlan not in mac_table.keys():
                mac_table[vlan] = list()
            mac_table[vlan].append(
                {
                    'mac'       : mac,
                    'interface' : interface,
                    'active'    : True,
                    'static'    : static,
                    'moves'     : moves,
                    'last_move' : last_move
                }
            )

        return mac_table

    def get_ntp_peers(self):

        ntp_peers = dict()

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
                ntp_peers[line_groups[1]] = {
                    'referenceid'   : line_groups[2],
                    'stratum'       : int(line_groups[3]),
                    'type'          : line_groups[4],
                    'when'          : line_groups[5],
                    'hostpoll'      : int(line_groups[6]),
                    'reachability'  : int(line_groups[7]),
                    'delay'         : float(line_groups[8]),
                    'offset'        : float(line_groups[9]),
                    'jitter'        : float(line_groups[10])
                }
            except Exception:
                continue # jump to next line

        return ntp_peers

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
            neighbor_info = lldp_neighbors_in.get(interface).get('lldpNeighborInfo', {})
            if not neighbor_info:
                # in case of empty infos
                continue
            neighbor_info = neighbor_info[0]
            if interface not in lldp_neighbors_out.keys():
                lldp_neighbors_out[interface] = list()
            lldp_neighbors_out[interface].append(
                {
                    'interface_descr': neighbor_info.get('neighborInterfaceInfo').get('interfaceDescription'),
                    'remote_port':  neighbor_info.get('neighborInterfaceInfo').get('interfaceId'),
                    'remote_system_name': neighbor_info.get('systemName'),
                    'remote_system_descr': neighbor_info.get('systemDescription'),
                    'remote_chassis_id': neighbor_info.get('chassisId')
                }
            )

        return lldp_neighbors_out

    def show_route(self, destination = ''):

        route = dict()

        return route


    def get_interfaces_ip(self):

        ip_list = []

        commands = list()
        commands.append('show ip interfaces brief')

        interfaces_out = self.device.run_commands(commands, encoding = 'text')[0].get('output', '\n\n')
        interfaces_lines = interfaces_out.splitlines()[2:]

        for interface in interfaces_lines:
            ip = interface.split()[1]
            if ip == 'unassigned':
                continue
            ip_nw = ip.split('/')
            if len(ip_nw) == 2:
                ip_list.append(ip_nw[0])

        return ip_list
