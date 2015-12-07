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

from netmiko import ConnectHandler
from base import NetworkDriver

import re

class IOSDriver(NetworkDriver):

    def __init__(self, hostname, username, password, timeout=60):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.first_touch = True
        self.candidate_config = None
        self.candidate_config_commands = None
        self.device = None

    def open(self):
        """Opens a connection to the device."""
        self.device = ConnectHandler(
            device_type='cisco_ios',
            ip=self.hostname,
            username=self.username,
            password=self.password)

    def close(self):
        """Closes the connection to the device."""
        self.device.disconnect() 

    def rollback(self):
        if self.candidate_config is not None:
            if isinstance(self.candidate_config, dict):
                for command in self.candidate_config_commands:
                    if command in self.candidate_config:
                        if self.candidate_config[command] == 'changed':
                            output = self.device.send_command(command)
                        else:
                            no_command = 'no {0}'.format(command)
                            output = self.device.send_command(no_command)
                self.candidate_config = None
                self.candidate_config_commands = None
            else:
                self.candidate_config = None
                self.candidate_config_commands = None

    def load_merge_candidate(self, filename=None, config=None):
        commands = list()
        if self.first_touch:
            commands.append('enable')
            commands.append(self.password)
            commands.append('conf t')

        if filename is not None:
            with open(filename, 'r') as new_config:
                configuration = new_config.readlines()
        else:
            if isinstance(config, list):
                configuration = config
            else:
                configuration = config.splitlines()

        for line in configuration:
            if line.strip() == '' or line.strip() == '!':
                continue
            else:
                commands.append(line.strip())

        self.candidate_config = commands

    def compare_config(self):
        if self.candidate_config is not None:
            if 'enable' in self.candidate_config:
                commands = self.candidate_config[3::]
                for command in commands:
                    print "+ {0}".format(command)
            else:
                for command in self.candidate_config:
                    print "+ {0}".format(command)

    def discard_config(self):
        if self.candidate_config is not None:
            self.candidate_config = None

    def commit_config(self):
        if self.candidate_config is not None:
            commands = self.candidate_config
            commands.append('do copy run start')
            commands.append('\n')
            commands_dict = {}
            self.candidate_config_commands = commands

            try:
                index = 0
                prompt = self.device.find_prompt()
                for command in commands:
                    output = self.device.send_command(command)
                    new_prompt = self.device.find_prompt()
                    if (index > 2 and self.first_touch) or (self.first_touch is False):
                        self.candidate_config = commands_dict
                        if new_prompt == prompt or 'hostname' in command:
                            commands_dict[command] = "unchanged"
                        else:
                            commands_dict[command] = "changed"
                    prompt = self.device.find_prompt()
                    index += 1
                self.first_touch = False
            except:
                self.rollback()
                self.first_touch = False

    def get_lldp_neighbors(self):
        command = 'show lldp neighbors | begin Device ID'
        lldp = {}

        output = self.device.send_command(command)
        splitted_output = output.split('\n')
        for line in splitted_output:
            neighbor = {}
            if len(line) > 0 and 'Device ID' not in line and 'entries' not in line:
                splitted_line = line.split()
                device_id = unicode(splitted_line[0])
                device_port = unicode(splitted_line[1])
                port_id = unicode(splitted_line[-1])
                neighbor['hostname'] = device_id
                neighbor['port'] = port_id
                lldp[device_port] = neighbor
        return lldp

    def get_facts(self):
        """This function returns a set of facts from the devices."""
        results = {}
        # creating the parsing regex.
        uptime_regex = ".*uptime\sis\s(?P<uptime>\d+\s\w+(,\s\d+\s+\w+){0,4}).*"
        show_ver_regex = ".*Software\s\((?P<image>.+)\),\sVersion\s(?P<version>.+), RELEASE.*"
        model_regex = ".*Cisco\s(?P<model>\d+).*"

        # commands to execute.
        commands = [
            'show version',
            'show ip interface brief'
            ]

        # default values.
        vendor = unicode('Cisco')
        fqdn = unicode('N/A')
        serial_number = unicode('N/A')

        for command in commands:
            output = self.device.send_command(command)
            if command == 'show version':
                # uptime filter
                try:
                    match_uptime = re.match(uptime_regex, output, re.DOTALL)
                    group_uptime = match_uptime.groupdict()
                    uptime = unicode(group_uptime["uptime"])
                except AttributeError:
                    uptime = -1

                # model filter.
                try:
                    match_model = re.match(model_regex, output, re.DOTALL)
                    group_model = match_model.groupdict()
                    model = unicode(group_model["model"])
                except AttributeError:
                    model = -1

                # version filter.
                try:
                    match_version = re.match(show_ver_regex, output, re.DOTALL)
                    group_version = match_version.groupdict()
                    image = unicode(group_version["image"])
                    os_version = unicode(group_version["version"])
                except AttributeError:
                    os_version = -1

                # hostname filter.
                output_splittted = output.split('\n')
                for line in output_splittted:
                    if "uptime" in line:
                        hostname_line = line.split()
                        hostname = unicode(hostname_line[0])

            # interface_list filter.
            elif command == 'show ip interface brief':
                interface_list = []
                splitted_output = output.split('\n')
                for i in range(1, len(splitted_output)):
                    interface = splitted_output[i].split()[0]
                    interface_list.append(interface)
        # parsing results.
        results = {
            'uptime': uptime,
            'vendor': vendor,
            'os_version': os_version,
            'serial_number': serial_number,
            'model': model,
            'hostname': hostname,
            'fqdn': fqdn,
            'interface_list': interface_list
        }
        return results
                        

    def get_interfaces(self):
        interface_list = {}
        # default values.
        last_flapped = -1.0
        # command to execute.
        command = 'show interfaces description'
        # let's start.
        output = self.device.send_command(command)
        splitted_output = output.split('\n')
        # creating the parsing regex.
        mac_regex = ".*,\saddress\sis\s(?P<mac_address>\S+).*"
        speed_regex = ".*BW\s(?P<speed>\d+)\s(?P<speed_format>\S+).*"
        for i in range(1, len(splitted_output)):
            params = {}
            interface = splitted_output[i].split()[0]
            if splitted_output[i].split()[1] == 'up':
                is_enabled = True
            else:
                is_enabled = False
            if splitted_output[i].split()[2] == 'up':
                is_up = True
            else:
                is_up = False
            # parsing descriptions.
            if is_up and is_enabled and len(splitted_output[i].split()) > 3:
                description_list = splitted_output[i].split()[3::]
                description = ' '.join(description_list)
            elif is_enabled and len(splitted_output[i].split()) > 3:
                description_list = splitted_output[i].split()[3::]
                description = ' '.join(description_list)
            elif len(splitted_output[i].split()) > 4:
                description_list = splitted_output[i].split()[4::]
                description = ' '.join(description_list)
            else:
                description = ''
            # parsing all the values.
            params['is_up'] = is_up
            params['is_enabled'] = is_enabled
            params['description'] = description
            interface_list[interface] = params

        for interface in interface_list:
            show_command = "show interface {0}".format(interface)
            interface_output = self.device.send_command(show_command)
            try:
                # mac_address filter.
                match_mac = re.match(mac_regex, interface_output, re.DOTALL)
                group_mac = match_mac.groupdict()
                mac_address = group_mac["mac_address"]
                interface_list[interface]['mac_address'] = unicode(mac_address)
            except AttributeError:
                interface_list[interface]['mac_address'] = -1
            try:
                # BW filter.
                match_speed = re.match(speed_regex, interface_output, re.DOTALL)
                group_speed = match_speed.groupdict()
                speed = group_speed["speed"]
                speed_format = group_speed["speed_format"]
                if speed_format == 'Mbit':
                    interface_list[interface]['speed'] = int(speed)
                else:
                    speed = int(speed)/1000
                    interface_list[interface]['speed'] = int(speed)
            except AttributeError:
                interface_list[interface]['speed'] = -1

        return interface_list

    def get_bgp_neighbors(self):
        commands = [
            "show ip bgp summary",
            "show ip bgp summary | begin Neighbor"
            ]
        bgp_regex = ".*router\sidentifier\s(?P<router_id>\S+),\slocal\sAS\snumber\s(?P<local_as>\d+).*"
        bgp_neighbors = {}
        for command in commands:
            family = {}
            output = self.device.send_command(command)
            if command == "show ip bgp summary":
                try:
                    # router_id and local_as filters.
                    match_bgp = re.match(bgp_regex, output, re.DOTALL)
                    group_bgp = match_bgp.groupdict()
                    router_id = group_bgp["router_id"]
                    local_as = group_bgp["local_as"]
                except AttributeError:
                    router_id = -1
                    local_as = -1
            else:
                splitted_output = output.split('\n')
                for i in range(1, len(splitted_output)):
                    params = {}
                    neighbor_line = splitted_output[i].split()
                    peer = neighbor_line[0]
                    remote_as = neighbor_line[2]
                    uptime = neighbor_line[8]
                    try:
                        int(neighbor_line[-1])
                        is_up = True
                        is_enabled = True
                    except:
                        is_up = -1
                        is_enabled = -1
                    params["router_id"] = router_id
                    params["local_as"] = local_as
                    params["remote_as"] = remote_as
                    params["is_up"] = is_up
                    params["is_enabled"] = is_enabled
                    params["uptime"] = uptime
                    bgp_neighbors[peer] = params

            for neighbor in bgp_neighbors:
                flag = 0
                command = "show ip bgp neighbor {0}".format(neighbor)
                neighbor_output = self.device.send_command(command)
                splitted_output = neighbor_output.split('\n')
                for line in splitted_output:
                    family_params = {}
                    if 'Description' in line:
                        description_line = line.split()
                        description = ' '.join(description_line[1::]) 
                        flag = 1
                    if flag == 1:
                        bgp_neighbors[neighbor]['description'] = description
                    else:
                        bgp_neighbors[neighbor]['description'] = ""
                    if 'address family' in line:
                        addr_family_line = line.split()
                        address_family = addr_family_line[3]
                    if 'Prefixes Current:' in line:
                        current_prefix_line = line.split()
                        try:
                            sent_prefixes = int(current_prefix_line[2])
                        except:
                            sent_prefixes = -1
                        try:
                            received_prefixes = int(current_prefix_line[3])
                        except:
                            received_prefixes = -1
                        family_params['sent_prefixes'] = sent_prefixes
                        family_params['received_prefixes'] = received_prefixes
                        family_params['accepted_prefixes'] = unicode('N/A')
                        family[address_family] = family_params
                        bgp_neighbors[neighbor]['address_family'] = family

        return bgp_neighbors 


    def get_interfaces_counters(self):
        command = 'show interface counters'
        counters = {}
        output = self.device.send_command(command)
        if len(output) > 0:
            splitted_output = output.split('\n')
            for i in range(0, len(splitted_output)):
                if 'OutOctets' in splitted_output[i]:
                    marker = i
            rx_counters = splitted_output[1:marker]
            tx_counters = splitted_output[marker::]
            for line in range(1, len(rx_counters)):
                params = {}
                if len(rx_counters[line]) > 0:
                    rx_counters_splitted = rx_counters[line].split()
                    interface = rx_counters_splitted[0]
                    try:
                        rx_octets = int(rx_counters_splitted[1])
                    except:
                        rx_octets = -1
                    try:
                        rx_unicast_packets = int(rx_counters_splitted[2])
                    except:
                        rx_unicast_packets = -1
                    try:
                        rx_multicast_packets = int(rx_counters_splitted[3])
                    except:
                        rx_multicast_packets = -1
                    try:
                        rx_broadcast_packets = int(rx_counters_splitted[4])
                    except:
                        rx_broadcast_packets = -1
                    rx_discards = unicode('N/A')
                    rx_errors = unicode('N/A')
                    params['rx_octets'] = rx_octets
                    params['rx_unicast_packets'] = rx_unicast_packets
                    params['rx_broadcast_packets'] = rx_broadcast_packets
                    params['rx_multicast_packets'] = rx_multicast_packets
                    params['rx_discards'] = rx_discards
                    params['rx_errors'] = rx_errors
                    counters[interface] = params

            for line in range(1, len(tx_counters)):
                if len(tx_counters[line]) > 0:
                    tx_counters_splitted = tx_counters[line].split()
                    interface = tx_counters_splitted[0]
                    try:
                        tx_octets = int(tx_counters_splitted[1])
                    except:
                        tx_octets = -1
                    try:
                        tx_unicast_packets = int(tx_counters_splitted[2])
                    except:
                        tx_unicast_packets = -1
                    try:
                        tx_multicast_packets = int(tx_counters_splitted[3])
                    except:
                        tx_multicast_packets = -1
                    try:
                        tx_broadcast_packets = int(tx_counters_splitted[4])
                    except:
                        tx_broadcast_packets = -1
                    tx_discards = unicode('N/A')
                    tx_errors = unicode('N/A')
                    counters[interface]['tx_octets'] = tx_octets
                    counters[interface]['tx_unicast_packets'] = tx_unicast_packets
                    counters[interface]['tx_broadcast_packets'] = tx_broadcast_packets
                    counters[interface]['tx_multicast_packets'] = tx_multicast_packets
                    counters[interface]['tx_discards'] = tx_discards
                    counters[interface]['tx_errors'] = tx_errors

        return counters        