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

from base import NetworkDriver

from exceptions import MergeConfigException, ReplaceConfigException, SessionLockedException

from datetime import datetime
import time

from utils.string_parsers import colon_separated_string_to_dict, hyphen_range, sorted_nicely


class EOSDriver(NetworkDriver):

    def __init__(self, hostname, username, password):
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
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
        version = self.device.show_version()
        hostname = self.device.show_hostname()

        uptime = time.time() - version['bootupTimestamp']

        interfaces = [i for i in self.device.show_interfaces_status()['interfaceStatuses'].keys() if '.' not in i]
        interfaces = sorted_nicely(interfaces)

        return {
            'hostname': hostname['hostname'],
            'fqdn': hostname['fqdn'],
            'vendor': u'Arista',
            'model': version['modelName'],
            'serial_number': version['serialNumber'],
            'os_version': version['internalVersion'],
            'uptime': int(uptime),
            'interface_list': interfaces
        }

    def get_interfaces(self):
        '''
        def _process_counters():
            interfaces[interface]['counters'] = dict()
            if counters is None:
                interfaces[interface]['counters']['tx_packets'] = -1
                interfaces[interface]['counters']['rx_packets'] = -1
                interfaces[interface]['counters']['tx_errors'] = -1
                interfaces[interface]['counters']['rx_errors'] = -1
                interfaces[interface]['counters']['tx_discards'] = -1
                interfaces[interface]['counters']['rx_discards'] = -1
            else:
                interfaces[interface]['counters']['tx_packets'] = counters['outUcastPkts'] + \
                                                      counters['outMulticastPkts'] + \
                                                      counters['outBroadcastPkts']
                interfaces[interface]['counters']['rx_packets'] = counters['inUcastPkts'] + \
                                                      counters['inMulticastPkts'] + \
                                                      counters['inBroadcastPkts']

                interfaces[interface]['counters']['tx_errors'] = counters['totalOutErrors']
                interfaces[interface]['counters']['rx_errors'] = counters['totalInErrors']

                interfaces[interface]['counters']['tx_discards'] = counters['outDiscards']
                interfaces[interface]['counters']['rx_discards'] = counters['inDiscards']

        def _process_routed_interface():
            interface_json = values.pop("interfaceAddress", [])
            interfaces[interface]['ip_address_v4'] = list()

            if len(interface_json) > 0:
                interface_json = interface_json[0]
                interfaces[interface]['ip_address_v4'].append('{}/{}'.format(
                    interface_json['primaryIp']['address'], interface_json['primaryIp']['maskLen'])
                )

                for sec_ip, sec_values in interface_json['secondaryIps'].iteritems():
                    interfaces[interface]['ip_address_v4'].append('{}/{}'.format(sec_ip, sec_values['maskLen']))

        def _process_switched_interface():
            data = colon_separated_string_to_dict(switchport_data['output'])

            if data[u'Operational Mode'] == u'static access':
                interfaces[interface]['switchport_mode'] = 'access'
                interfaces[interface]['access_vlan'] = int(data[u'Access Mode VLAN'].split()[0])
            elif data[u'Operational Mode'] == u'trunk':
                interfaces[interface]['switchport_mode'] = 'trunk'
                interfaces[interface]['native_vlan'] = int(data[u'Trunking Native Mode VLAN'].split()[0])

                if data[u'Trunking VLANs Enabled'] == u'ALL':
                    interfaces[interface]['trunk_vlans'] = range(1,4095)
                else:
                    interfaces[interface]['trunk_vlans'] = hyphen_range(data[u'Trunking VLANs Enabled'])
        '''
        output = self.device.show_interfaces()

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

            #interfaces[interface]['mode'] = values['forwardingModel']

            interfaces[interface]['speed'] = values['bandwidth']
            interfaces[interface]['mac_address'] = values.pop('physicalAddress', None)


            #counters = values.pop('interfaceCounters', None)
            #_process_counters()


            #if interfaces[interface]['mode'] == u'routed':
            #    _process_routed_interface()
            #if interfaces[interface]['mode'] == u'bridged':
            #    switchport_data = eval('self.device.show_interfaces_{}_switchport(format="text")'.format(interface))
            #    _process_switched_interface()

        return interfaces

    # def get_bgp_neighbors(self):
    #     bgp_neighbors = dict()
    #
    #     for vrf, vrf_data in self.device.show_ip_bgp_summary_vrf_all()['vrfs'].iteritems():
    #         bgp_neighbors[vrf] = dict()
    #         bgp_neighbors[vrf]['router_id'] = vrf_data['routerId']
    #         bgp_neighbors[vrf]['local_as'] = vrf_data['asn']
    #         bgp_neighbors[vrf]['peers'] = dict()
    #
    #         for n, n_data in vrf_data['peers'].iteritems():
    #             bgp_neighbors[vrf]['peers'][n] = dict()
    #
    #             if n_data['peerState'] == 'Established':
    #                 bgp_neighbors[vrf]['peers'][n]['is_up'] = True
    #                 bgp_neighbors[vrf]['peers'][n]['is_enabled'] = True
    #             else:
    #                 bgp_neighbors[vrf]['peers'][n]['is_up'] = False
    #
    #                 reason = n_data.pop('peerStateIdleReason', None)
    #                 if reason == 'Admin':
    #                     bgp_neighbors[vrf]['peers'][n]['is_enabled'] = False
    #                 else:
    #                     bgp_neighbors[vrf]['peers'][n]['is_enabled'] = True
    #
    #             bgp_neighbors[vrf]['peers'][n]['remote_as'] = n_data['asn']
    #             bgp_neighbors[vrf]['peers'][n]['uptime'] = n_data['upDownTime']
    #
    #             raw_data = eval(
    #                 'self.device.show_ip_bgp_neighbors_vrf_{}(format="text", pipe="section {}")'.format(vrf, n)
    #             )['output']
    #
    #             n_data_full =  colon_separated_string_to_dict(raw_data)
    #             sent, rcvd = n_data_full['IPv4 Unicast'].split()
    #
    #             bgp_neighbors[vrf]['peers'][n]['received_prefixes'] = int(rcvd)
    #             bgp_neighbors[vrf]['peers'][n]['sent_prefixes'] = int(sent)
    #             bgp_neighbors[vrf]['peers'][n]['accepted_prefixes'] = n_data['prefixAccepted']
    #
    #             bgp_neighbors[vrf]['peers'][n]['description'] = n_data_full.pop('Description', '')
    #
    #     return bgp_neighbors

    def get_lldp_neighbors(self):
        lldp = dict()

        for n in self.device.show_lldp_neighbors()['lldpNeighbors']:
            if n['port'] not in lldp.keys():
                lldp[n['port']] = list()

            lldp[n['port']].append(
                {
                    'hostname': n['neighborDevice'],
                    'port': n['neighborPort'],
                }
            )

        return lldp
