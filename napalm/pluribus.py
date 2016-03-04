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
from pyPluribus.exceptions import ConnectionError

from exceptions import ConnectionException


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
        try:
            self.device.open()
        except ConnectionError as ce:
            raise ConnectionException(ce.message)

    def close(self):

        self.device.close()

    def get_facts(self):

        switch_info = self.device.execute_show('switch-info-show')
        lines = switch_info.splitlines()[1:4]

        hostname = lines[0].split(';')[1].strip()
        model    = lines[1].split(';')[1].strip()
        serial   = lines[2].split(';')[1].strip()

        software_info = self.device.execute_show('software-show')
        lines = software_info.splitlines()[1:2]

        os_ver = lines[0].split(';')[1].strip()

        system_stats = self.device.execute_show('system-stats-show')
        # one single line

        uptime_str = system_stats.split(';')[9].strip()
        uptime_days_split = uptime_str.split('d')
        uptime_days = int(uptime_days_split[0])
        uptime_hours_split = uptime_days_split[-1].split('h')
        uptime_hours = int(uptime_hours_split[0])
        uptime_minutes_split = uptime_hours_split[-1].split('m')
        uptime_minutes = int(uptime_minutes_split[0])
        uptime_seconds = int(uptime_minutes_split[-1].replace('s', ''))
        uptime = 24*3600*uptime_days + 60*uptime_minutes + uptime_seconds

        interfaces = []
        port_stats = self.device.execute_show('port-stats-show')
        lines = port_stats.splitlines()[1:-1]

        for line in lines:
            interface = line.split(';')[9].strip()
            interfaces.append(interface)

        facts = {
            'vendor'        : u'Pluribus',
            'os_version'    : unicode(os_ver),
            'hostname'      : unicode(hostname),
            'uptime'        : uptime,
            'model'         : unicode(model),
            'serial_number' : unicode(serial),
            'interface_list': interfaces,
            'fqdn'          : u''
        }

        return facts

    def cli(self, commands = None):

        cli_output = dict()

        if type(commands) is not list:
            raise TypeError('Please provide a valid list of commands!')

        for command in commands:
            cli_output[unicode(command)] = self.device.cli(command)

        return cli_output

    def get_interfaces(self):

        interfaces = dict()

        interface_info   = self.device.execute_show('port-config-show')
        interfaces_lines = interface_info.splitlines()[1:-1]

        for line in interfaces_lines:
            interface_details = line.split(';')
            interface_name  = unicode(interface_details[1])
            up              = (interface_details[4] != 'disable')
            enabled         = (interface_details[8] == 'on')
            speed          = 0
            if up and interface_details[4].replace('g', '').isdigit():
                speed = int(1e3 * int(interface_details[4].replace('g', '')))
                # > 1G interfaces
            last_flap       = 0.0
            description     = unicode(interface_details[17])
            mac_address     = unicode(interface_details[28])
            interfaces[interface_name] = {
                'is_up'         : up,
                'is_enabled'    : enabled,
                'description'   : description,
                'last_flapped'  : last_flap,
                'speed'         : speed,
                'mac_address'   : mac_address
            }

        return interfaces

    def get_mac_address_table(self):

        mac_table = list()

        mac_show = self.device.execute_show('l2-table-show')
        lines = mac_show.splitlines()[1:-1]

        for line in lines:
            mac_details = line.split(';')
            mac_raw     = unicode(mac_details[2].strip())
            mac_all     = mac_raw.replace('.', '').replace(':', '')
            mac_format  = unicode(':'.join([mac_all[i:i+2] for i in range(12)[::2]]))
            vlan        = int(mac_details[3].strip())
            ports       = unicode(mac_details[8].strip())
            active      = (mac_details[9].strip == 'active')
            mac_table.append(
                {
                    'mac'       : mac_format,
                    'interface' : ports,
                    'vlan'      : vlan,
                    'active'    : active,
                    'static'    : False,
                    'moves'     : 0,
                    'last_move' : 0.0
                }
            )

        return mac_table

    def get_lldp_neighbors(self):

        lldp_neighbors = dict()

        lldp_show = self.device.execute_show('lldp-show')
        lines = lldp_show.splitlines()[1:-1]

        for line in lines:
            neighbor_details    = line.split(';')
            port                = unicode(neighbor_details[1].strip())
            port_id             = unicode(neighbor_details[3].strip())
            system_name         = unicode(neighbor_details[6].strip())
            if port_id not in lldp_neighbors.keys():
                lldp_neighbors[port_id] = list()
            lldp_neighbors[port_id].append({
                'port'      : port,
                'hostname'  : system_name
            })

        return lldp_neighbors

    def get_lldp_neighbors_detail(self):

        lldp_neighbors = dict()

        lldp_show = self.device.execute_show('lldp-show')
        lines = lldp_show.splitlines()[1:-1]

        for line in lines:
            neighbor_details    = line.split(';')
            port                = unicode(neighbor_details[1].strip())
            chassis             = unicode(neighbor_details[2].strip())
            port_id             = unicode(neighbor_details[3].strip())
            port_descr          = unicode(neighbor_details[4].strip())
            system_name         = unicode(neighbor_details[6].strip())
            if port not in lldp_neighbors.keys():
                lldp_neighbors[port] = list()
            lldp_neighbors[port].append({
                'parent_interface'          : u'',
                'remote_port'               : port_id,
                'remote_port_description'   : port_descr,
                'remote_chassis_id'         : chassis,
                'remote_system_name'        : system_name,
                'remote_system_description' : u'',
                'remote_system_capab'       : u'',
                'remote_system_enable_capab': u''
            })

        return lldp_neighbors

    def get_ntp_peers(self):

        ntp_peers = dict()

        ntp_show    = self.device.execute_show('switch-setup-show')
        ntp_server  = unicode(ntp_show.splitlines()[10].split(';')[-1])
        # there's only one NTP peers, without providing any stats...
        # still better than nothing?

        ntp_peers[ntp_server] = {
            'referenceid'   : ntp_server,
            'stratum'       : 0,
            'type'          : u'',
            'when'          : u'',
            'hostpoll'      : 0,
            'reachability'  : 0,
            'delay'         : 0.0,
            'offset'        : 0.0,
            'jitter'        : 0.0
        }

        return ntp_peers

    def get_snmp_information(self):

        snmp_information = dict()

        _SNMP_MODE_MAP_ = {
            'read-write': u'rw',
            'read-only' : u'ro'
        }

        switch_info = self.device.execute_show('switch-info-show')
        chassis_id  = switch_info.splitlines()[2].split(';')[-1]

        snmp_information['chassis_id'] = unicode(chassis_id)
        snmp_information['contact']    = u''
        snmp_information['location']   = u''
        snmp_information['community']  = dict()

        snmp_communities = self.device.execute_show('snmp-community-show')
        snmp_lines       = snmp_communities.splitlines()

        for snmp_line in snmp_lines:
            snmp_line_details = snmp_line.split(';')
            snmp_community = unicode(snmp_line_details[1])
            snmp_mode      = _SNMP_MODE_MAP_.get(snmp_line_details[2], u'ro')
            snmp_acl       = u''
            snmp_information['community'][snmp_community] = {
                'acl' : snmp_acl,
                'mode': snmp_mode
            }

        return snmp_information
