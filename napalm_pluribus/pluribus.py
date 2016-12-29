# -*- coding: utf-8 -*-
# Copyright 2016 CloudFlare, Inc. All rights reserved.
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

"""Pluribus driver."""

from __future__ import unicode_literals

# python std lib
import re

# third party libs
import pyPluribus.exceptions
from pyPluribus import PluribusDevice

# NAPALM base
import napalm_base.helpers
import napalm_base.exceptions
import napalm_base.constants as C
from napalm_base.utils import py23_compat
from napalm_base.base import NetworkDriver


class PluribusDriver(NetworkDriver):

    """
    PluribusDriver class.
    """

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):

        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {}
        self.port = optional_args.get('port', 22)

        self.device = PluribusDevice(hostname, username, password, self.port, timeout)

    def open(self):
        try:
            self.device.open()
        except pyPluribus.exceptions.ConnectionError as connerr:
            raise napalm_base.exceptions.ConnectionException(connerr.message)

    def is_alive(self):
        return{
            'is_alive': self.device._connection.transport.is_alive()
        }

    def close(self):
        self.device.close()

    def load_merge_candidate(self, filename=None, config=None):
        return self.device.config.load_candidate(filename=filename, config=config)

    def compare_config(self):
        return self.device.config.compare()

    def commit_config(self):
        return self.device.config.commit()

    def discard_config(self):
        return self.device.config.discard()

    def rollback(self):
        return self.device.config.rollback(number=1)

    def get_facts(self):

        switch_info = self.device.show('switch info', delim='@$@')
        lines = switch_info.splitlines()[1:4]

        hostname = lines[0].split('@$@')[1].strip()
        model = lines[1].split('@$@')[1].strip()
        serial = lines[2].split('@$@')[1].strip()

        software_info = self.device.show('software', delim='@$@')
        lines = software_info.splitlines()[1:2]

        os_ver = lines[0].split('@$@')[1].strip()

        system_stats = self.device.show('system stats', delim='@$@')
        # one single line

        uptime_str = system_stats.split('@$@')[9].strip()
        uptime_days_split = uptime_str.split('d')
        uptime_days = int(uptime_days_split[0])
        uptime_hours_split = uptime_days_split[-1].split('h')
        uptime_minutes_split = uptime_hours_split[-1].split('m')
        uptime_minutes = int(uptime_minutes_split[0])
        uptime_seconds = int(uptime_minutes_split[-1].replace('s', ''))
        uptime = 24*3600*uptime_days + 60*uptime_minutes + uptime_seconds

        interfaces = []
        port_stats = self.device.show('port stats', delim='@$@')
        lines = port_stats.splitlines()[1:-1]

        for line in lines:
            interface = line.split('@$@')[9].strip()
            interfaces.append(interface)

        facts = {
            'vendor': u'Pluribus',
            'os_version': py23_compat.text_type(os_ver),
            'hostname': py23_compat.text_type(hostname),
            'uptime': uptime,
            'model': py23_compat.text_type(model),
            'serial_number': py23_compat.text_type(serial),
            'interface_list': interfaces,
            'fqdn': u''
        }

        return facts

    def cli(self, commands):

        cli_output = {}

        if type(commands) is not list:
            raise TypeError('Please provide a valid list of commands!')

        for command in commands:
            cli_output[py23_compat.text_type(command)] = self.device.cli(command)

        return cli_output

    def get_interfaces(self):

        interfaces = {}

        interface_info = self.device.show('port config', delim='@$@')
        interfaces_lines = interface_info.splitlines()[1:-1]

        for line in interfaces_lines:
            interface_details = line.split('@$@')
            interface_name = py23_compat.text_type(interface_details[1])
            up = (interface_details[4] != 'disable')
            enabled = (interface_details[8] == 'on')
            speed = 0
            if up and interface_details[4].replace('g', '').isdigit():
                speed = int(1e3 * int(interface_details[4].replace('g', '')))
                # > 1G interfaces
            last_flap = 0.0
            description = py23_compat.text_type(interface_details[17])
            mac_address = py23_compat.text_type(interface_details[28])
            interfaces[interface_name] = {
                'is_up': up,
                'is_enabled': enabled,
                'description': description,
                'last_flapped': last_flap,
                'speed': speed,
                'mac_address': napalm_base.helpers.convert(
                    napalm_base.helpers.mac, mac_address)
            }

        return interfaces

    def get_mac_address_table(self):

        mac_table = []

        mac_show = self.device.show('l2 table', delim='@$@')
        lines = mac_show.splitlines()[1:-1]

        for line in lines:
            mac_details = line.split('@$@')
            mac_raw = mac_details[2].strip()
            vlan = int(mac_details[3].strip())
            ports = py23_compat.text_type(mac_details[8].strip())
            active = (mac_details[9].strip == 'active')
            mac_table.append({
                'mac': napalm_base.helpers.convert(
                    napalm_base.helpers.mac, mac_raw),
                'interface': ports,
                'vlan': vlan,
                'active': active,
                'static': False,
                'moves': 0,
                'last_move': 0.0
            })

        return mac_table

    def get_lldp_neighbors(self):

        lldp_neighbors = {}

        lldp_show = self.device.show('lldp', delim='@$@')
        lines = lldp_show.splitlines()[1:-1]

        for line in lines:
            neighbor_details = line.split('@$@')
            port = py23_compat.text_type(neighbor_details[1].strip())
            port_id = py23_compat.text_type(neighbor_details[3].strip())
            system_name = py23_compat.text_type(neighbor_details[6].strip())
            if port_id not in lldp_neighbors.keys():
                lldp_neighbors[port_id] = []
            lldp_neighbors[port_id].append({
                'port': port,
                'hostname': system_name
            })

        return lldp_neighbors

    def get_lldp_neighbors_detail(self, interface=''):

        lldp_neighbors = {}

        lldp_show = self.device.show('lldp', delim='@$@')
        lines = lldp_show.splitlines()[1:-1]

        for line in lines:
            neighbor_details = line.split('@$@')
            port = py23_compat.text_type(neighbor_details[1].strip())
            if interface and port != interface:
                continue
            chassis = napalm_base.helpers.convert(
                    napalm_base.helpers.mac, neighbor_details[2].strip())
            port_id = py23_compat.text_type(neighbor_details[3].strip())
            port_descr = py23_compat.text_type(neighbor_details[4].strip())
            system_name = py23_compat.text_type(neighbor_details[6].strip())
            if port not in lldp_neighbors.keys():
                lldp_neighbors[port] = []
            lldp_neighbors[port].append({
                'parent_interface': u'',
                'remote_port': port_id,
                'remote_port_description': port_descr,
                'remote_chassis_id': chassis,
                'remote_system_name': system_name,
                'remote_system_description': u'',
                'remote_system_capab': u'',
                'remote_system_enable_capab': u''
            })

        return lldp_neighbors

    def get_ntp_servers(self):

        ntp_stats = self.get_ntp_stats()
        return {
            napalm_base.helpers.convert(napalm_base.helpers.ip, ntp_peer.get('remote')): {}
            for ntp_peer in ntp_stats if ntp_peer.get('remote', '')
        }

    def get_ntp_stats(self):

        ntp_stats = []

        sw_setup_show = self.device.show('switch setup', delim='@$@')
        ntp_server = py23_compat.text_type(sw_setup_show.splitlines()[9].split('@$@')[-1])

        ntp_stats.append({
            'remote': ntp_server,
            'referenceid': ntp_server,
            'synchronized': True,
            'stratum': 1,
            'type': u'',
            'when': u'',
            'hostpoll': 0,
            'reachability': 0,
            'delay': 0.0,
            'offset': 0.0,
            'jitter': 0.0
        })

        return ntp_stats

    def get_snmp_information(self):

        snmp_information = {}

        _SNMP_MODE_MAP_ = {
            'read-write': u'rw',
            'read-only': u'ro'
        }

        switch_info = self.device.show('switch info', delim='@$@')
        chassis_id = switch_info.splitlines()[2].split('@$@')[-1]

        snmp_information['chassis_id'] = py23_compat.text_type(chassis_id)
        snmp_information['contact'] = u''
        snmp_information['location'] = u''
        snmp_information['community'] = {}

        snmp_communities = self.device.show('snmp community', delim='@$@')
        snmp_lines = snmp_communities.splitlines()

        for snmp_line in snmp_lines:
            snmp_line_details = snmp_line.split('@$@')
            snmp_community = py23_compat.text_type(snmp_line_details[1])
            snmp_mode = _SNMP_MODE_MAP_.get(snmp_line_details[2], u'ro')
            snmp_acl = u''
            snmp_information['community'][snmp_community] = {
                'acl': snmp_acl,
                'mode': snmp_mode
            }

        return snmp_information

    def get_users(self):

        users = {}

        _DEFAULT_USER_DETAILS = {
            'level': 0,
            'password': '',
            'sshkeys': []
        }

        role_level = {}
        roles_config = self.device.show('role', delim='@$@')
        for role in roles_config.splitlines():
            role_details = role.split('@$@')
            role_name = role_details[2]
            level = 0
            access = role_details[5]
            running_config = role_details[6]
            if access == 'read-write' and running_config == 'permit':
                level = 15
            if (access == 'read-write' and running_config == 'deny') or\
               (access == 'read-only' and running_config == 'permit'):
                level = 5
            if access == 'read-only' and running_config == 'deny':
                level = 1
            role_level[role_name] = level
        running_config = self.device.config._download_running_config()
        for line in running_config.splitlines():
            if not line.startswith('import-password user-create'):
                continue
            user_details = _DEFAULT_USER_DETAILS.copy()
            user_config = line.split()
            username = py23_compat.text_type(user_config[3])
            password = py23_compat.text_type(user_config[7])
            role = user_config[9]
            level = role_level.get(role)
            user_details.update({
                'level': level,
                'password': password,
            })
            users[username] = user_details

        return users

    def traceroute(self,
                   destination,
                   source=C.TRACEROUTE_SOURCE,
                   ttl=C.TRACEROUTE_TTL,
                   timeout=C.TRACEROUTE_TIMEOUT):
        # same method as on EOS, different command send to CLI

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

        command = 'traceroute {source_opt} {ttl_opt} {timeout_opt} {destination}'.format(
            destination=destination,
            source_opt=source_opt,
            ttl_opt=ttl_opt,
            timeout_opt=timeout_opt
        )

        traceroute_raw_output = self.device.cli(command)

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
                ip_address = napalm_base.helpers.convert(
                        napalm_base.helpers.ip, hop_details[4+probe_index*5])
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

    def get_config(self, retrieve='all'):

        config = {
            'startup': '',
            'running': '',
            'candidate': ''
        }  # default values

        if retrieve.lower() in ['running', 'all']:
            config['running'] = py23_compat.text_type(self.device.show('running config'))
            # no startup as pluribus is WYSIWYG, no commit needed

        return config
