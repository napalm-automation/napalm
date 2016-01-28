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

from base import NetworkDriver

from pyPluribus import PluribusDevice

from utils import string_parsers


class PluribusDriver(NetworkDriver):

    def __init__(self, hostname, username, password, timeout = 60, optional_args = None):

        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout  = timeout

        if optional_args is None:
            optional_args = {}
        self.port = optional_args.get('port', 22)

        self.device = PluribusDevice(hostname, username, password, self.port, timeout)

    def open(self):

        self.device.open()

    def close(self):

        self.device.close()

    def get_facts(self):

        switch_info = self.device.execute_show('show switch-info')
        lines = switch_info.split('\n')[1:4]

        hostname = lines[0].split(';')[1].strip()
        model    = lines[1].split(';')[1].strip()
        serial   = lines[2].split(';')[1].strip()

        software_info = self.device.execute_show('software-show')
        lines = software_info.split('\n')[1:2]

        os_ver = lines[0].split(';')[1].strip()

        system_stats = self.device.execute_show('system-stats-show')
        lines = system_stats.split('\n')[1:2]

        uptime_str = lines[0].split(';')[9].strip()

        interfaces = []
        port_stats = self.device.execute_show('port-stats-show')
        lines = port_stats.split('\n')[1:-1]

        for line in lines:
            interface = line.split(';')[9].strip()
            interfaces.append(interface)

        facts = {
            'vendor'        : u'Pluribus',
            'os_version'    : unicode(os_ver),
            'hostname'      : unicode(hostname),
            'uptime'        : string_parsers.convert_uptime_string_seconds(uptime_str),
            'model'         : unicode(model),
            'serial_number' : unicode(serial),
            'interface_list': interfaces
        }

        return facts

    def get_bgp_neighbors_detail(self, neighbor_address = ''):

        bgp_neighbors = dict()

        return bgp_neighbors

    def cli(self, command = ''):

        return self.device.cli(command)

    def get_arp_table(self, interface = '', host = '', ip = '', mac = ''):

        arp_table = dict()

        return arp_table

    def get_mac_address_table(self, address = '', interface = '', dynamic = False, static = False, vlan = None):

        mac_table = dict()

        mac_show = self.device.execute_show('l2-table-show')
        lines = mac_show.split('\n')[1:-1]

        for line in lines:
            mac_details = line.split(';')
            mac         = mac_details[2].strip()
            vlan        = int(mac_details[3].strip())
            ports       = mac_details[8].strip()
            active      = (mac_details[9].strip == 'active')
            hostname    = mac_details[10].strip()
            status      = mac_details[11].strip()
            migrate     = mac_details[-1].strip()
            if vlan not in mac_table.keys():
                mac_table[vlan] = list()
            mac_table[vlan].append(
                {
                    'mac'       : mac,
                    'interface' : ports,
                    'active'    : active,
                    'hostname'  : hostname,
                    'status'    : status,
                    'migrate'   : migrate
                }
            )

        return mac_table

    def get_ntp_peers(self):

        ntp_peers = dict()

        return ntp_peers

    def get_lldp_neighbors_detail(self, interface = ''):

        lldp_neighbors = dict()

        lldp_show = self.device.execute_show('lldp-show')
        lines = lldp_show.split('\n')[1:-1]

        for line in lines:
            neighbor_details    = line.split(';')
            port                = neighbor_details[1].strip()
            chassis             = neighbor_details[2].strip()
            port_id             = neighbor_details[3].strip()
            port_descr          = neighbor_details[4].strip()
            system_name         = neighbor_details[6].strip()
            if port not in lldp_neighbors.keys():
                lldp_neighbors[port] = list()
            lldp_neighbors[port] = {
                'parent_interface'          : None,
                'remote_port'               : port_id,
                'remote_port_name'          : port_descr,
                'remote_system_chassis_id'  : chassis,
                'remote_system_name'        : system_name
            }

        return lldp_neighbors

    def show_route(self, destination = ''):

        route = dict()

        return route

    def get_interfaces_ip(self):

        ip_list = list()

        return ip_list
