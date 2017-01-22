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
        interfaces = json.loads(interfaces)

        facts['hostname'] = facts['fqdn'] = py23_compat.text_type(hostname)
        facts['os_version'] = py23_compat.text_type(os_version)
        facts['model'] = py23_compat.text_type(model)
        facts['uptime'] = string_parsers.convert_uptime_string_seconds(uptime)
        facts['serial_number'] = py23_compat.text_type(serial_number)
        facts['interface_list'] = interfaces.keys()
        return facts
