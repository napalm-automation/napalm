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


class EOSDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60):
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
            port=443
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

    def get_bgp_neighbors(self):

        commands_json = list()
        commands_txt = list()
        commands_json.append('show ip bgp summary vrf all')
        commands_json.append('show ipv6 bgp summary vrf all')
        commands_txt.append('show ip bgp neighbors vrf all | include remote AS|remote router ID|Description|^ *IPv[4-6] Unicast:')
        commands_txt.append('show ipv6 bgp neighbors vrf all | include remote AS|remote router ID|Description|^ *IPv[4-6] Unicast:')

        output_summary = self.device.run_commands(commands_json, encoding='json')
        output_neighbors = self.device.run_commands(commands_txt, encoding='text')

        ##########################################
        # no JSON available for show ip bgp neigh
        # Using 'show ipv[4-6] bgp neighbors vrf all | i remote AS|remote router ID|Description|^ *IPv[4-6] Unicast:'
        # NOTE: if there is no description, EOS does not print the line.


        # Regex the output from show ip bgp neigh
        def get_bgp_neighbor(needed_peer, vrf, output_to_parse):
            import re

            bgp_neighbors = dict()
            bgp_peer = dict()
            neighbor_regexp = re.compile('BGP neighbor is (.*?),')
            description_regexp = re.compile('Description: (.*?)$')
            remote_id_regexp = re.compile('remote router ID (.*?),')
            vrf_regexp = re.compile('VRF (.*?)$')
            IPv4_sent_regexp = re.compile('IPv4 Unicast: ( *)(\d*) ')
            IPv6_sent_regexp = re.compile('IPv6 Unicast: ( *)(\d*) ')

            for line in output_to_parse.splitlines():
                if re.search(neighbor_regexp, line):
                    peer = re.search(neighbor_regexp, line).group(1)
                    bgp_neighbors[peer] = dict()
                    bgp_neighbors[peer]['description'] = ''
                    continue
                elif re.search(description_regexp, line):
                    bgp_neighbors[peer]['description'] = re.search(description_regexp, line).group(1)
                    continue
                elif re.search(remote_id_regexp, line):
                    bgp_neighbors[peer]['remote_id'] = re.search(remote_id_regexp, line).group(1)
                    bgp_neighbors[peer]['vrf'] = re.search(vrf_regexp, line).group(1)
                    continue
                elif re.search(IPv4_sent_regexp, line):
                    bgp_neighbors[peer]['ipv4'] = re.search(IPv4_sent_regexp, line).group(2)
                    continue
                elif re.search(IPv6_sent_regexp, line):
                    bgp_neighbors[peer]['ipv6'] = re.search(IPv6_sent_regexp, line).group(2)
                    continue
            try:
                peer = next(peer for peer in bgp_neighbors if peer == needed_peer)
            except StopIteration:
                raise Exception("Peer %s not found in show bgp neighbors" % needed_peer)
            if bgp_neighbors[peer]['vrf'] == vrf:
                bgp_peer['remote_id'] = bgp_neighbors[peer]['remote_id']
                bgp_peer['description'] = bgp_neighbors[peer]['description']
                bgp_peer['ipv4'] = bgp_neighbors[peer]['ipv4']
                bgp_peer['ipv6'] = bgp_neighbors[peer]['ipv6']
            return bgp_peer

        bgp_counters = dict()
        for id in [0,1]:
            for vrf in output_summary[id]['vrfs']:
                bgp_counters[vrf] = dict()
                bgp_counters[vrf]['router_id'] = unicode(output_summary[id]['vrfs'][vrf]['routerId'])
                bgp_counters[vrf]['peers'] = dict()
                for peer in output_summary[id]['vrfs'][vrf]['peers']:
                    bgp_counters[vrf]['peers'][peer] = dict()
                    bgp_counters[vrf]['peers'][peer]['local_as'] = int(output_summary[id]['vrfs'][vrf]['asn'])
                    bgp_counters[vrf]['peers'][peer]['remote_as'] = int(output_summary[id]['vrfs'][vrf]['peers'][peer]['asn'])
                    peerState = output_summary[id]['vrfs'][vrf]['peers'][peer]['peerState']
                    bgp_counters[vrf]['peers'][peer]['is_up'] = peerState == 'Established'
                    if 'peerStateIdleReason' in output_summary[id]['vrfs'][vrf]['peers'][peer]:
                        bgp_counters[vrf]['peers'][peer]['is_enabled'] = False
                    else:
                        bgp_counters[vrf]['peers'][peer]['is_enabled'] = peerState == 'Established' or peerState == 'Active'
                    bgp_counters[vrf]['peers'][peer]['uptime'] = int(output_summary[id]['vrfs'][vrf]['peers'][peer]['upDownTime'])
                    bgp_peer = get_bgp_neighbor(peer, vrf, output_neighbors[id]['output'])
                    bgp_counters[vrf]['peers'][peer]['remote_id'] = unicode(bgp_peer['remote_id'])
                    bgp_counters[vrf]['peers'][peer]['description'] = unicode(bgp_peer['description'])
                    bgp_counters[vrf]['peers'][peer]['address_family'] = dict()
                    for family in ['ipv4', 'ipv6']:
                        bgp_counters[vrf]['peers'][peer]['address_family'][family] = dict()
                        bgp_counters[vrf]['peers'][peer]['address_family'][family]['received_prefixes'] = int(output_summary[id]['vrfs'][vrf]['peers'][peer]['prefixReceived'])
                        bgp_counters[vrf]['peers'][peer]['address_family'][family]['accepted_prefixes'] = int(output_summary[id]['vrfs'][vrf]['peers'][peer]['prefixAccepted'])
                        bgp_counters[vrf]['peers'][peer]['address_family'][family]['sent_prefixes'] = int(bgp_peer[family])
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
