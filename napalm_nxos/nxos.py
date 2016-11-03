# -*- coding: utf-8 -*-
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

from __future__ import unicode_literals

# import stdlib
import re
import ssl
import time
import tempfile
from urllib2 import URLError
from datetime import datetime

# import third party lib
from netaddr import IPAddress
from netaddr.core import AddrFormatError

from pycsco.nxos.utils import nxapi_lib
from pycsco.nxos.utils import install_config
from pycsco.nxos.utils.file_copy import FileCopy
from pycsco.nxos.device import Device as NXOSDevice

from pycsco.nxos.error import CLIError
from pycsco.nxos.error import FileTransferError

# import NAPALM Base
import napalm_base.helpers
from napalm_base import NetworkDriver
from napalm_base.utils import py23_compat
from napalm_base.exceptions import ConnectionException
from napalm_base.exceptions import MergeConfigException
from napalm_base.exceptions import CommandErrorException
from napalm_base.exceptions import ReplaceConfigException


# Allow untrusted SSL Certificates
ssl._create_default_https_context = ssl._create_unverified_context


def strip_trailing(string):
    lines = list(x.rstrip(' ') for x in string.splitlines())
    return '\n'.join(lines)


class NXOSDriver(NetworkDriver):

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.up = False
        self.replace = True
        self.loaded = False
        self.fc = None
        self.changed = False
        self.port = optional_args.get('port', 80)
        self.protocol = optional_args.get('nxos_protocol', 'http')

    def open(self):
        try:
            self.device = NXOSDevice(username=self.username,
                                     password=self.password,
                                     ip=self.hostname,
                                     timeout=self.timeout,
                                     port=self.port,
                                     protocol=self.protocol)
            self.device.show('show version', fmat='json')
            # execute something easy
            # something easier with XML format?
            self.up = True
        except URLError:
            # unable to open connection
            raise ConnectionException('Cannot connect to {}'.format(self.hostname))

    def close(self):
        if self.changed:
            self._delete_file(self.backup_file)

    @staticmethod
    def _compute_timestamp(stupid_cisco_output):
        """
        Some fields such `uptime` are returned as: 23week(s) 3day(s)
        This method will determine the epoch of the event.
        e.g.: 23week(s) 3day(s) -> 1462248287
        """

        if not stupid_cisco_output:
            return -1.0

        things = {
            'second(s)': {
                'weight': 1
            },
            'minute(s)': {
                'weight': 60
            },
            'hour(s)': {
                'weight': 3600
            },
            'day(s)': {
                'weight': 24*3600
            },
            'week(s)': {
                'weight': 7*24*3600
            },
            'year(s)': {
                'weight': 365.25*24*3600
            }
        }

        things_keys = things.keys()
        for part in stupid_cisco_output.split():
            for key in things_keys:
                if key in part:
                    things[key]['count'] = napalm_base.helpers.convert(
                        int, part.replace(key, ''), 0)

        delta = sum([det.get('count', 0)*det.get('weight') for det in things.values()])

        return time.time() - delta

    @staticmethod
    def _get_reply_body(result):
        # useful for debugging
        ret = result.get('ins_api', {}).get('outputs', {}).get('output', {}).get('body', {})
        # Original 'body' entry may have been an empty string, don't return that.
        if not isinstance(ret, dict):
            return {}
        return ret

    @staticmethod
    def _get_table_rows(parent_table, table_name, row_name):
        # because if an inconsistent piece of shit.
        # {'TABLE_intf': [{'ROW_intf': {
        # vs
        # {'TABLE_mac_address': {'ROW_mac_address': [{
        # vs
        # {'TABLE_vrf': {'ROW_vrf': {'TABLE_adj': {'ROW_adj': {
        _table = parent_table.get(table_name)
        _table_rows = []
        if isinstance(_table, list):
            _table_rows = [_table_row.get(row_name) for _table_row in _table]
        elif isinstance(_table, dict):
            _table_rows = _table.get(row_name)
        if not isinstance(_table_rows, list):
            _table_rows = [_table_rows]
        return _table_rows

    def _get_reply_table(self, result, table_name, row_name):
        _table = self._get_reply_body(result)
        return self._get_table_rows(_table, table_name, row_name)

    def _get_command_table(self, command, table_name, row_name):

        result = {}
        result = self.device.show(command, fmat='json')
        json_output = eval(result[1])

        return self._get_reply_table(json_output, table_name, row_name)

    def load_replace_candidate(self, filename=None, config=None):
        self.replace = True
        self.loaded = True

        if filename is None:
            temp_file = tempfile.NamedTemporaryFile()
            temp_file.write(config)
            temp_file.flush()
            cfg_file_path = temp_file.name
        else:
            cfg_file_path = filename

        self.fc = FileCopy(self.device, cfg_file_path)
        if not self.fc.file_already_exists():
            try:
                self.fc.transfer_file()
            except FileTransferError as fte:
                raise ReplaceConfigException(fte.message)

    def load_merge_candidate(self, filename=None, config=None):
        self.replace = False
        self.loaded = True
        if filename is not None:
            with open(filename, "r") as f:
                self.merge_candidate = f.read()
        else:
            self.merge_candidate = config

    def compare_config(self):
        if self.loaded:
            if not self.replace:
                return self.merge_candidate
            messy_diff = install_config.get_diff(self.device, self.fc.dst)
            clean_diff = strip_trailing(messy_diff)
            return clean_diff

        return ''

    def _copy_run_start(self):
        _save_startup_cmd = 'copy run start'
        copy_output = self.cli([_save_startup_cmd])[_save_startup_cmd]  # exec copy run st
        last_line = copy_output.splitlines()[-1]  # Should be `Copy complete.`
        if 'copy complete' not in last_line.lower():  # weak?
            raise CommandErrorException('Unable to commit config!')

    def _commit_merge(self):
        commands = self.merge_candidate.splitlines()
        command_string = ';'.join(list(' %s ' % x.strip() for x in commands))
        self.device.config(command_string)  # this will load all lines in running config only
        self._copy_run_start()

    def commit_config(self):
        if self.loaded:
            self.backup_file = 'config_' + str(datetime.now()).replace(' ', '_')
            install_config.save_config(self.device, self.backup_file)
            if self.replace:
                if install_config.rollback(self.device, self.fc.dst) is False:
                    raise ReplaceConfigException
            else:
                try:
                    self._commit_merge()
                except Exception as e:
                    raise MergeConfigException(str(e))

            self.changed = True
            self.loaded = False
        else:
            raise ReplaceConfigException('No config loaded.')

    def _delete_file(self, filename):
        self.device.show('terminal dont-ask', text=True)
        self.device.show('delete {}'.format(filename), text=True)
        self.device.show('no terminal dont-ask', text=True)

    def discard_config(self):
        if self.loaded and self.replace:
            try:
                self._delete_file(self.fc.dst)
            except CLIError:
                pass

        self.loaded = False

    def rollback(self):
        if self.changed:
            install_config.rollback(self.device, self.backup_file)
            self._copy_run_start()
            self.changed = False

    def get_facts(self):
        facts = {
            'vendor': u'Cisco'
        }

        sh_uptime_cmd = 'show system uptime'
        sh_uptime = eval(self.device.show(sh_uptime_cmd, fmat='json')[1])
        sh_uptime_body = self._get_reply_body(sh_uptime)

        uptime_days = sh_uptime_body.get('sys_up_days', 0)
        uptime_hrs = sh_uptime_body.get('sys_up_hrs', 0)
        uptime_mins = sh_uptime_body.get('sys_up_mins', 0)
        uptime_secs = sh_uptime_body.get('sys_up_secs', 0)
        facts['uptime'] = (uptime_secs + uptime_mins * 60 + uptime_hrs * (60 * 60) +
                           uptime_days * (60 * 60 * 24))

        sh_ver_cmd = 'show version'
        sh_ver_json = eval(self.device.show(sh_ver_cmd, fmat='json')[1])
        sh_ver_body = self._get_reply_body(sh_ver_json)

        sh_ver_json = eval(self.device.show(sh_ver_cmd, fmat='json')[1])
        facts['serial_number'] = unicode(sh_ver_body.get('proc_board_id'))
        facts['os_version'] = unicode(sh_ver_body.get('sys_ver_str'))
        facts['model'] = unicode(sh_ver_body.get('chassis_id'))
        host_name = unicode(sh_ver_body.get('host_name'))
        facts['hostname'] = host_name

        sh_domain_cmd = 'show running-config | include domain-name'
        sh_domain_name_out = self.cli([sh_domain_cmd])[sh_domain_cmd]
        if not sh_domain_name_out:
            sh_domain_name_out = ''

        domain_name = ''
        for line in sh_domain_name_out.splitlines():
            if line.startswith('ip domain-name'):
                domain_name = line.replace('ip domain-name', '').strip()
                break

        facts['fqdn'] = unicode(
            '{0}.{1}'.format(host_name, domain_name) if domain_name else host_name)

        intrf_cmd = 'show interface status'
        interfaces_status = self._get_command_table(intrf_cmd, 'TABLE_interface', 'ROW_interface')
        facts['interface_list'] = [intrf.get('interface') for intrf in interfaces_status]

        return facts

    def get_interfaces(self):
        interfaces = {}

        iface_cmd = 'show interface'
        interfaces_out = self._get_command_table(iface_cmd, 'TABLE_interface', 'ROW_interface')

        for interface_details in interfaces_out:
            interface_name = interface_details.get('interface')
            # Earlier version of Nexus returned a list for 'eth_bw' (observed on 7.1(0)N1(1a))
            interface_speed = interface_details.get('eth_bw', 0)
            if isinstance(interface_speed, list):
                interface_speed = interface_speed[0]
            interface_speed = int(interface_speed * 1000)
            interfaces[interface_name] = {
                'is_up': (interface_details.get('admin_state', '') == 'up'),
                'is_enabled': (interface_details.get('state') == 'up') or
                (interface_details.get('admin_state', '') == 'up'),
                'description': unicode(interface_details.get('desc', '')),
                'last_flapped': self._compute_timestamp(
                    interface_details.get('eth_link_flapped', '')),
                'speed': interface_speed,
                'mac_address': napalm_base.helpers.convert(
                    napalm_base.helpers.mac, interface_details.get('eth_hw_addr')),

            }

        return interfaces

    def get_lldp_neighbors(self):
        results = {}

        try:
            neighbor_list = nxapi_lib.get_neighbors(self.device, 'lldp')
        except CLIError:
            neighbor_list = []

        for neighbor in neighbor_list:
            local_iface = neighbor.get('local_interface')
            if neighbor.get(local_iface) is None:
                if local_iface not in results:
                    results[local_iface] = []

            neighbor_dict = {}
            neighbor_dict['hostname'] = unicode(neighbor.get('neighbor'))
            neighbor_dict['port'] = unicode(neighbor.get('neighbor_interface'))

            results[local_iface].append(neighbor_dict)

        return results

    def get_bgp_neighbors(self):
        results = {}
        try:
            cmd = 'show bgp sessions vrf all'
            vrf_list = self._get_command_table(cmd, 'TABLE_vrf', 'ROW_vrf')
        except CLIError:
            vrf_list = []

        for vrf_dict in vrf_list:
            result_vrf_dict = {}
            result_vrf_dict['router_id'] = unicode(vrf_dict['router-id'])
            result_vrf_dict['peers'] = {}

            neighbors_list = vrf_dict.get('TABLE_neighbor', {}).get('ROW_neighbor', [])
            if isinstance(neighbors_list, dict):
                neighbors_list = [neighbors_list]
            for neighbor_dict in neighbors_list:
                neighborid = napalm_base.helpers.ip(neighbor_dict['neighbor-id'])

                result_peer_dict = {
                    'local_as': int(vrf_dict['local-as']),
                    'remote_as': int(neighbor_dict['remoteas']),
                    'remote_id': neighborid,
                    'is_enabled': True,
                    'uptime': -1,
                    'description': unicode(''),
                    'is_up': True
                }
                result_peer_dict['address_family'] = {
                    'ipv4': {
                        'sent_prefixes': -1,
                        'accepted_prefixes': -1,
                        'received_prefixes': -1
                    }
                }

                result_vrf_dict['peers'][neighborid] = result_peer_dict

            results[vrf_dict['vrf-name-out']] = result_vrf_dict
        return results

    def get_checkpoint_file(self):
        return install_config.get_checkpoint(self.device)

    def get_lldp_neighbors_detail(self, interface=''):

        lldp_neighbors = {}

        filter = ''
        if interface:
            filter = 'interface {name} '.format(name=interface)

        command = 'show lldp neighbors {filter}detail'.format(filter=filter)
        # seems that show LLDP neighbors detail does not return JSON output...

        try:
            lldp_neighbors_table_str = self.cli([command]).get(command)
            # thus we need to take the raw text output
            lldp_neighbors_list = lldp_neighbors_table_str.splitlines()
        except CLIError:
            lldp_neighbors_list = []

        if not lldp_neighbors_list:
            return lldp_neighbors  # empty dict

        CHASSIS_REGEX = '^(Chassis id:)\s+([a-z0-9\.]+)$'
        PORT_REGEX = '^(Port id:)\s+([0-9]+)$'
        LOCAL_PORT_ID_REGEX = '^(Local Port id:)\s+(.*)$'
        PORT_DESCR_REGEX = '^(Port Description:)\s+(.*)$'
        SYSTEM_NAME_REGEX = '^(System Name:)\s+(.*)$'
        SYSTEM_DESCR_REGEX = '^(System Description:)\s+(.*)$'
        SYST_CAPAB_REEGX = '^(System Capabilities:)\s+(.*)$'
        ENABL_CAPAB_REGEX = '^(Enabled Capabilities:)\s+(.*)$'
        VLAN_ID_REGEX = '^(Vlan ID:)\s+(.*)$'

        lldp_neighbor = {}
        interface_name = None

        for line in lldp_neighbors_list:
            chassis_rgx = re.search(CHASSIS_REGEX, line, re.I)
            if chassis_rgx:
                lldp_neighbor = {
                    'remote_chassis_id': napalm_base.helpers.mac(chassis_rgx.groups()[1])
                }
                continue
            lldp_neighbor['parent_interface'] = u''
            port_rgx = re.search(PORT_REGEX, line, re.I)
            if port_rgx:
                lldp_neighbor['parent_interface'] = unicode(port_rgx.groups()[1])
                continue  # jump to next line
            local_port_rgx = re.search(LOCAL_PORT_ID_REGEX, line, re.I)
            if local_port_rgx:
                interface_name = local_port_rgx.groups()[1]
                continue
            port_descr_rgx = re.search(PORT_DESCR_REGEX, line, re.I)
            if port_descr_rgx:
                lldp_neighbor['remote_port'] = unicode(port_descr_rgx.groups()[1])
                lldp_neighbor['remote_port_description'] = unicode(port_descr_rgx.groups()[1])
                continue
            syst_name_rgx = re.search(SYSTEM_NAME_REGEX, line, re.I)
            if syst_name_rgx:
                lldp_neighbor['remote_system_name'] = unicode(syst_name_rgx.groups()[1])
                continue
            syst_descr_rgx = re.search(SYSTEM_DESCR_REGEX, line, re.I)
            if syst_descr_rgx:
                lldp_neighbor['remote_system_description'] = unicode(syst_descr_rgx.groups()[1])
                continue
            syst_capab_rgx = re.search(SYST_CAPAB_REEGX, line, re.I)
            if syst_capab_rgx:
                lldp_neighbor['remote_system_capab'] = unicode(syst_capab_rgx.groups()[1])
                continue
            syst_enabled_rgx = re.search(ENABL_CAPAB_REGEX, line, re.I)
            if syst_enabled_rgx:
                lldp_neighbor['remote_system_enable_capab'] = unicode(syst_enabled_rgx.groups()[1])
                continue
            vlan_rgx = re.search(VLAN_ID_REGEX, line, re.I)
            if vlan_rgx:
                # at the end of the loop
                if interface_name not in lldp_neighbors.keys():
                    lldp_neighbors[interface_name] = []
                lldp_neighbors[interface_name].append(lldp_neighbor)

        return lldp_neighbors

    def cli(self, commands=None):

        cli_output = {}

        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            string_output = self.device.show(command, fmat='json', text=True)[1]
            dict_output = eval(string_output)
            command_output = dict_output.get('ins_api', {})\
                                        .get('outputs', {})\
                                        .get('output', {})\
                                        .get('body', '')
            cli_output[unicode(command)] = command_output

        return cli_output

    def get_arp_table(self):

        arp_table = []

        command = 'show ip arp'
        arp_table_vrf = self._get_command_table(command, 'TABLE_vrf', 'ROW_vrf')
        arp_table_raw = self._get_table_rows(arp_table_vrf[0], 'TABLE_adj', 'ROW_adj')

        for arp_table_entry in arp_table_raw:
            raw_ip = arp_table_entry.get('ip-addr-out')
            raw_mac = arp_table_entry.get('mac')
            age = arp_table_entry.get('time-stamp')
            age_time = ''.join(age.split(':'))
            age_sec = float(3600 * int(age_time[:2]) + 60 * int(age_time[2:4]) + int(age_time[4:]))
            interface = unicode(arp_table_entry.get('intf-out'))
            arp_table.append({
                'interface': interface,
                'mac': napalm_base.helpers.convert(
                    napalm_base.helpers.mac, raw_mac, raw_mac),
                'ip': napalm_base.helpers.ip(raw_ip),
                'age': age_sec
            })

        return arp_table

    def _get_ntp_entity(self, peer_type):

        ntp_entities = {}

        command = 'show ntp peers'
        ntp_peers_table = self._get_command_table(command, 'TABLE_peers', 'ROW_peers')

        for ntp_peer in ntp_peers_table:
            if ntp_peer.get('serv_peer', '').strip() != peer_type:
                continue
            peer_addr = napalm_base.helpers.ip(ntp_peer.get('PeerIPAddress').strip())
            ntp_entities[peer_addr] = {}

        return ntp_entities

    def get_ntp_peers(self):
        return self._get_ntp_entity('Peer')

    def get_ntp_servers(self):
        return self._get_ntp_entity('Server')

    def get_ntp_stats(self):

        ntp_stats = []

        command = 'show ntp peer-status'
        ntp_stats_table = self._get_command_table(command, 'TABLE_peersstatus', 'ROW_peersstatus')

        for ntp_peer in ntp_stats_table:
            peer_address = napalm_base.helpers.ip(ntp_peer.get('remote'))
            syncmode = ntp_peer.get('syncmode')
            stratum = int(ntp_peer.get('st'))
            hostpoll = int(ntp_peer.get('poll'))
            reachability = int(ntp_peer.get('reach'))
            delay = float(ntp_peer.get('delay'))
            ntp_stats.append({
                'remote': peer_address,
                'synchronized': (syncmode == '*'),
                'referenceid': peer_address,
                'stratum': stratum,
                'type': u'',
                'when': u'',
                'hostpoll': hostpoll,
                'reachability': reachability,
                'delay': delay,
                'offset': 0.0,
                'jitter': 0.0
            })

        return ntp_stats

    def get_interfaces_ip(self):

        interfaces_ip = {}

        ipv4_command = 'show ip interface'
        ipv4_interf_table_vrf = self._get_command_table(ipv4_command, 'TABLE_intf', 'ROW_intf')

        for interface in ipv4_interf_table_vrf:
            interface_name = unicode(interface.get('intf-name', ''))
            address = napalm_base.helpers.ip(interface.get('prefix'))
            prefix = int(interface.get('masklen', ''))
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = {}
            if u'ipv4' not in interfaces_ip[interface_name].keys():
                interfaces_ip[interface_name][u'ipv4'] = {}
            if address not in interfaces_ip[interface_name].get(u'ipv4'):
                interfaces_ip[interface_name][u'ipv4'][address] = {}
            interfaces_ip[interface_name][u'ipv4'][address].update({
                'prefix_length': prefix
            })
            secondary_addresses = interface.get('TABLE_secondary_address', {})\
                                           .get('ROW_secondary_address', [])
            if type(secondary_addresses) is dict:
                secondary_addresses = [secondary_addresses]
            for secondary_address in secondary_addresses:
                secondary_address_ip = napalm_base.helpers.ip(secondary_address.get('prefix1'))
                secondary_address_prefix = int(secondary_address.get('masklen1', ''))
                if u'ipv4' not in interfaces_ip[interface_name].keys():
                    interfaces_ip[interface_name][u'ipv4'] = {}
                if secondary_address_ip not in interfaces_ip[interface_name].get(u'ipv4'):
                    interfaces_ip[interface_name][u'ipv4'][secondary_address_ip] = {}
                interfaces_ip[interface_name][u'ipv4'][secondary_address_ip].update({
                    'prefix_length': secondary_address_prefix
                })

        ipv6_command = 'show ipv6 interface'
        ipv6_interf_table_vrf = self._get_command_table(ipv6_command, 'TABLE_intf', 'ROW_intf')

        for interface in ipv6_interf_table_vrf:
            interface_name = unicode(interface.get('intf-name', ''))
            address = napalm_base.helpers.ip(interface.get('addr', '').split('/')[0])
            prefix = int(interface.get('prefix', '').split('/')[-1])
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = {}
            if u'ipv6' not in interfaces_ip[interface_name].keys():
                interfaces_ip[interface_name][u'ipv6'] = {}
            if address not in interfaces_ip[interface_name].get('ipv6'):
                interfaces_ip[interface_name][u'ipv6'][address] = {}
            interfaces_ip[interface_name][u'ipv6'][address].update({
                u'prefix_length': prefix
            })
            secondary_addresses = interface.get('TABLE_sec_addr', {}).get('ROW_sec_addr', [])
            if type(secondary_addresses) is dict:
                secondary_addresses = [secondary_addresses]
            for secondary_address in secondary_addresses:
                sec_prefix = secondary_address.get('sec-prefix', '').split('/')
                secondary_address_ip = napalm_base.helpers.ip(sec_prefix[0])
                secondary_address_prefix = int(sec_prefix[-1])
                if u'ipv6' not in interfaces_ip[interface_name].keys():
                    interfaces_ip[interface_name][u'ipv6'] = {}
                if secondary_address_ip not in interfaces_ip[interface_name].get(u'ipv6'):
                    interfaces_ip[interface_name][u'ipv6'][secondary_address_ip] = {}
                interfaces_ip[interface_name][u'ipv6'][secondary_address_ip].update({
                    u'prefix_length': secondary_address_prefix
                })

        return interfaces_ip

    def get_mac_address_table(self):

        mac_table = []

        command = 'show mac address-table'
        mac_table_raw = self._get_command_table(command, 'TABLE_mac_address', 'ROW_mac_address')

        for mac_entry in mac_table_raw:
            raw_mac = mac_entry.get('disp_mac_addr')
            interface = unicode(mac_entry.get('disp_port'))
            # age = mac_entry.get('disp_age')
            vlan = int(mac_entry.get('disp_vlan'))
            active = True
            static = (mac_entry.get('disp_is_static') != '0')
            moves = 0
            last_move = 0.0
            mac_table.append({
                'mac': napalm_base.helpers.mac(raw_mac),
                'interface': interface,
                'vlan': vlan,
                'active': active,
                'static': static,
                'moves': moves,
                'last_move': last_move
            })

        return mac_table

    def get_snmp_information(self):

        snmp_information = {}

        snmp_command = 'show running-config | section snmp-server'
        snmp_raw_output = self.cli([snmp_command]).get(snmp_command, '')
        snmp_config = napalm_base.helpers.textfsm_extractor(self, 'snmp_config', snmp_raw_output)

        if not snmp_config:
            return snmp_information

        snmp_information = {
            'contact': unicode(snmp_config[0].get('contact', '')),
            'location': unicode(snmp_config[0].get('location', '')),
            'chassis_id': unicode(snmp_config[0].get('chassis_id', '')),
            'community': {}
        }

        for snmp_entry in snmp_config:
            community_name = unicode(snmp_entry.get('community', ''))
            if not community_name:
                continue
            snmp_information['community'][community_name] = {
                'acl': unicode(snmp_entry.get('acl', '')),
                'mode': unicode(snmp_entry.get('mode', '').lower())
            }

        return snmp_information

    def get_users(self):

        _CISCO_TO_CISCO_MAP = {
            'network-admin': 15,
            'network-operator': 5
        }

        _DEFAULT_USER_DICT = {
            'password': '',
            'level': 0,
            'sshkeys': []
        }

        users = {}

        command = 'sh run | sec username'
        section_username_raw_output = self.cli([command]).get(command, '')
        section_username_tabled_output = napalm_base.helpers.textfsm_extractor(
            self, 'users', section_username_raw_output)

        for user in section_username_tabled_output:
            username = user.get('username', '')
            if not username:
                continue
            if username not in users:
                users[username] = _DEFAULT_USER_DICT.copy()

            password = user.get('password', '')
            if password:
                users[username]['password'] = py23_compat.text_type(password.strip())

            level = 0
            role = user.get('role', '')
            if role.startswith('priv'):
                level = int(role.split('-')[-1])
            else:
                level = _CISCO_TO_CISCO_MAP.get(role, 0)
            if level > users.get(username).get('level'):
                # unfortunately on Cisco you can set different priv levels for the same user
                # Good news though: the device will consider the highest level
                users[username]['level'] = level

            sshkeytype = user.get('sshkeytype', '')
            sshkeyvalue = user.get('sshkeyvalue', '')
            if sshkeytype and sshkeyvalue:
                if sshkeytype not in ['ssh-rsa', 'ssh-dsa']:
                    continue
                users[username]['sshkeys'].append(py23_compat.text_type(sshkeyvalue))

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

        timeout = 5  # seconds
        probes = 3  # 3 probes/jop and this cannot be changed on NXOS!

        version = ''
        try:
            version = '6' if IPAddress(destination).version == 6 else ''
        except AddrFormatError:
            return {'error': 'Destination doest not look like a valid IP Address: {}'.format(
                destination)}

        source_opt = ''
        if source:
            source_opt = 'source {source}'.format(source=source)

        command = 'traceroute{version} {destination} {source_opt}'.format(
            version=version,
            destination=destination,
            source_opt=source_opt
        )

        try:
            traceroute_raw_output = self.cli([command]).get(command)
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
                ip_address_raw = hop_details[4+probe_index*5]
                ip_address = napalm_base.helpers.convert(
                    napalm_base.helpers.ip, ip_address_raw, ip_address_raw)
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

    def get_config(self, retrieve='all'):

        config = {
            'startup': '',
            'running': '',
            'candidate': ''
        }  # default values

        if retrieve.lower() in ('running', 'all'):
            _cmd = 'show running-config'
            config['running'] = py23_compat.text_type(self.cli([_cmd]).get(_cmd))
        if retrieve.lower() in ('startup', 'all'):
            _cmd = 'show startup-config'
            config['startup'] = py23_compat.text_type(self.cli([_cmd]).get(_cmd))

        return config
