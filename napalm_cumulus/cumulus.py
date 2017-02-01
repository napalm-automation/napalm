# Copyright 2016 Dravetech AB. All rights reserved.
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
Napalm driver for Cumulus.

Read https://napalm.readthedocs.io for more information.
"""

from __future__ import print_function
from __future__ import unicode_literals

import re
import json

from netmiko import ConnectHandler
from netmiko import __version__ as netmiko_version
from netmiko.ssh_exception import NetMikoTimeoutException
from napalm_base.utils import py23_compat
from napalm_base.utils import string_parsers
from napalm_base.base import NetworkDriver
from napalm_base.exceptions import (
    ConnectionException,
    MergeConfigException,
    ReplaceConfigException
    )
from datetime import datetime


class CumulusDriver(NetworkDriver):
    """Napalm driver for Cumulus."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.loaded = False
        self.changed = False

        if optional_args is None:
            optional_args = {}

        # Netmiko possible arguments
        netmiko_argument_map = {
            'port': None,
            'verbose': False,
            'global_delay_factor': 1,
            'use_keys': False,
            'key_file': None,
            'ssh_strict': False,
            'system_host_keys': False,
            'alt_host_keys': False,
            'alt_key_file': '',
            'ssh_config_file': None,
        }

        fields = netmiko_version.split('.')
        fields = [int(x) for x in fields]
        maj_ver, min_ver, bug_fix = fields
        if maj_ver >= 2:
            netmiko_argument_map['allow_agent'] = False
        elif maj_ver == 1 and min_ver >= 1:
            netmiko_argument_map['allow_agent'] = False

        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {}
        for k, v in netmiko_argument_map.items():
            try:
                self.netmiko_optional_args[k] = optional_args[k]
            except KeyError:
                pass
        self.global_delay_factor = optional_args.get('global_delay_factor', 1)
        self.port = optional_args.get('port', 22)
        self.sudo_pwd = optional_args.get('sudo_pwd', self.password)

    def open(self):
        try:
            self.device = ConnectHandler(device_type='linux',
                                         host=self.hostname,
                                         username=self.username,
                                         password=self.password,
                                         **self.netmiko_optional_args)
        except NetMikoTimeoutException:
            raise ConnectionException('Cannot connect to {}'.format(self.hostname))

    def close(self):
        self.device.disconnect()

    def is_alive(self):
        return {
            'is_alive': self.device.remote_conn.transport.is_active()
        }

    def load_merge_candidate(self, filename=None, config=None):
        if not filename and not config:
            raise MergeConfigException('filename or config param must be provided.')

        self.loaded = True

        if filename is not None:
            with open(filename, 'r') as f:
                candidate = f.readlines()
        else:
            candidate = config

        if not isinstance(candidate, list):
            candidate = [candidate]

        candidate = [line for line in candidate if line]
        for command in candidate:
            if 'sudo' not in command:
                command = 'sudo {0}'.format(command)
            self._send_command(command)

    def discard_config(self):
        if self.loaded:
            self._send_command('sudo net abort')
            self.loaded = False

    def compare_config(self):
        if self.loaded:
            diff = self._send_command('sudo net pending')
            return re.sub('\x1b\[\d+m', '', diff)
        return ''

    def commit_config(self):
        if self.loaded:
            self._send_command('sudo net commit')
            self.changed = True
            self.loaded = False

    def rollback(self):
        if self.changed:
            self._send_command('sudo net rollback last')
            self.changed = False

    def _send_command(self, command, compare=False):
        response = self.device.send_command_timing(command)
        if '[sudo]' in response:
            response = self.device.send_command_timing(self.sudo_pwd)
        return response

    def get_facts(self):
        facts = {
            'vendor': py23_compat.text_type('Cumulus')
        }

        # Get "net show hostname" output.
        hostname = self.device.send_command('hostname')

        # Get "net show system" output.
        show_system_output = self._send_command('sudo net show system')
        for line in show_system_output.splitlines():
            if 'build' in line.lower():
                os_version = line.split()[-1]
                model = ' '.join(line.split()[1:3])
            elif 'uptime' in line.lower():
                uptime = line.split()[-1]

        # Get "decode-syseeprom" output.
        decode_syseeprom_output = self.device.send_command('decode-syseeprom')
        for line in decode_syseeprom_output.splitlines():
            if 'serial number' in line.lower():
                serial_number = line.split()[-1]

        # Get "net show interface all json" output.
        interfaces = self._send_command('sudo net show interface all json')
        # Handling bad send_command_timing return output.
        try:
            interfaces = json.loads(interfaces)
        except ValueError:
            interfaces = json.loads(self.device.send_command('sudo net show interface all json'))

        facts['hostname'] = facts['fqdn'] = py23_compat.text_type(hostname)
        facts['os_version'] = py23_compat.text_type(os_version)
        facts['model'] = py23_compat.text_type(model)
        facts['uptime'] = string_parsers.convert_uptime_string_seconds(uptime)
        facts['serial_number'] = py23_compat.text_type(serial_number)
        facts['interface_list'] = interfaces.keys()
        return facts



    def get_lldp_neighbors(self):
        """Cumulus get_lldp_neighbors."""
        lldp = {}
        command = 'net show lldp json'
        lldp_output = json.loads(self._send_command(command))
        for interface in lldp_output:
            hostname = lldp_output[interface]['iface_obj']['lldp'][0]['adj_hostname']
            port = lldp_output[interface]['iface_obj']['lldp'][0]['adj_port']
            lldp[interface] = dict([('hostname', hostname), ('port', port)])
        return lldp


    
    def get_interfaces(self):
        
        interfaces = {}
        # Get 'net show interface all json' output.
        output = self._send_command('sudo net show interface all json')
        # Handling bad send_command_timing return output.        
        try:
            output_json = json.loads(output)
        except ValueError:
            output_json = json.loads(self.device.send_command('sudo net show interface all json'))
            
        for interface in output_json:
            interfaces[interface] = {}
            
            if output_json[interface]['iface_obj']['linkstate'] is 0:
                interfaces[interface]['is_enabled'] = False
            else:
                interfaces[interface]['is_enabled'] = True
                
            if output_json[interface]['iface_obj']['linkstate'] is 2:
                interfaces[interface]['is_up'] = True
            else:
                interfaces[interface]['is_up'] = False 
            
            interfaces[interface]['description'] = py23_compat.text_type(output_json[interface]['iface_obj']['description'])

            # The last flapped information is not provided in Cumulus NCLU so setting this to -1
            interfaces[interface]['last_flapped'] = -1

            
            if output_json[interface]['iface_obj']['speed'] is None:
                interfaces[interface]['speed'] = -1
            else:
                interfaces[interface]['speed'] = output_json[interface]['iface_obj']['speed']
                
            interfaces[interface]['mac_address'] = py23_compat.text_type(output_json[interface]['iface_obj']['mac'])
        
        # Test if the quagga daemon is running.
        quagga_test = self._send_command('service quagga status')
        
        for line in quagga_test.splitlines():
            if 'Active:' in line:
                status = line.split()[1]
               
                if 'inactive' in status:
                    quagga_status = False
                elif 'active' in status:
                    quagga_status = True
                else:
                    quagga_status = False

        # If the quagga daemon is running for each interface run the show interface command to get information about the most recent interface change.
        if quagga_status is True:
            for interface in interfaces.keys():
                command = "sudo vtysh -c 'show interface %s'" % interface
                quagga_show_int_output = self._send_command(command)
                
                # Get the link up and link down datetimes if available.
                for line in quagga_show_int_output.splitlines():
                    if 'Link ups' in line:
                        if '(never)' in line.split()[4]:
                            last_flapped_1 = False
                        else:
                            last_flapped_1 = True
                            last_flapped_1_date = line.split()[4] + " " + line.split()[5]
                            last_flapped_1_date = datetime.strptime(last_flapped_1_date,"%Y/%m/%d %H:%M:%S.%f")
                        

                    if 'Link downs' in line:
                        if '(never)' in line.split()[4]:
                            last_flapped_2 = False
                        else:
                            last_flapped_2 = True
                            last_flapped_2_date = line.split()[4] + " " + line.split()[5]
                            last_flapped_2_date = datetime.strptime(last_flapped_2_date,"%Y/%m/%d %H:%M:%S.%f")
                
                # Compare the link up and link down datetimes to determine the most recent and set that as the last flapped after converting to seconds.                        
                if (last_flapped_1 and last_flapped_2) is True:
                    last_delta = last_flapped_1_date - last_flapped_2_date
                    if last_delta.days >= 0:
                        last_flapped = last_flapped_1_date
                    else:
                        last_flapped = last_flapped_2_date
                elif last_flapped_1 is True:
                    last_flapped = last_flapped_1_date
                elif last_flapped_2 is True:
                    last_flapped = last_flapped_2_date
                else:
                    last_flapped = -1
                
                now = datetime.now()
                if last_flapped == -1:
                    pass
                else:
                    last_flapped = (now-last_flapped).total_seconds()
                    
                interfaces[interface]['last_flapped']=last_flapped
        
        # If quagga daemon isn't running set all last_flapped values to -1.                       
        if quagga_status is False:
            for interface in interfaces.keys():
                interfaces[interface]['last_flapped']=-1
                               
         
        
        return interfaces
        
        

