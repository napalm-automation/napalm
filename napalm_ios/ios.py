"""NAPALM Cisco IOS Handler."""
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

from __future__ import print_function
from __future__ import unicode_literals

import re

from netmiko import ConnectHandler, FileTransfer
from netmiko import __version__ as netmiko_version
from napalm_base.base import NetworkDriver
from napalm_base.exceptions import ReplaceConfigException, MergeConfigException
from napalm_base.utils import py23_compat
import napalm_base.constants as C

# Easier to store these as constants
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS

# STD REGEX PATTERNS
IP_ADDR_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
MAC_REGEX = r"[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}"
VLAN_REGEX = r"\d{1,4}"
RE_IPADDR = re.compile(r"{}".format(IP_ADDR_REGEX))
RE_IPADDR_STRIP = re.compile(r"({})\n".format(IP_ADDR_REGEX))
RE_MAC = re.compile(r"{}".format(MAC_REGEX))

IOS_COMMANDS = {
   'show_mac_address': ['show mac-address-table', 'show mac address-table'],
}


class IOSDriver(NetworkDriver):
    """NAPALM Cisco IOS Handler."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """NAPALM Cisco IOS Handler."""
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        # Retrieve file names
        self.candidate_cfg = optional_args.get('candidate_cfg', 'candidate_config.txt')
        self.merge_cfg = optional_args.get('merge_cfg', 'merge_config.txt')
        self.rollback_cfg = optional_args.get('rollback_cfg', 'rollback_config.txt')

        # None will cause autodetection of dest_file_system
        self.dest_file_system = optional_args.get('dest_file_system', None)
        self.auto_rollback_on_error = optional_args.get('auto_rollback_on_error', True)

        # Netmiko possible arguments
        netmiko_argument_map = {
            'port': None,
            'secret': '',
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

        self.device = None
        self.config_replace = False
        self.interface_map = {}

    def open(self):
        """Open a connection to the device."""
        self.device = ConnectHandler(device_type='cisco_ios',
                                     host=self.hostname,
                                     username=self.username,
                                     password=self.password,
                                     **self.netmiko_optional_args)
        # ensure in enable mode
        self.device.enable()
        if not self.dest_file_system:
            try:
                self.dest_file_system = self.device._autodetect_fs()
            except AttributeError:
                raise AttributeError("Netmiko _autodetect_fs not found please upgrade Netmiko or "
                                     "specify dest_file_system in optional_args.")

    def close(self):
        """Close the connection to the device."""
        self.device.disconnect()

    def _send_command(self, command):
        """Wrapper for self.device.send.command().

        If command is a list will iterate through commands until valid command.
        """
        if isinstance(command, list):
            for cmd in command:
                output = self.device.send_command(cmd)
                if "% Invalid" not in output:
                    break
        else:
            output = self.device.send_command(command)
        return self._send_command_postprocess(output)

    def is_alive(self):
        """Returns a flag with the state of the SSH connection."""
        return {
            'is_alive': self.device.remote_conn.transport.is_active()
        }

    def load_replace_candidate(self, filename=None, config=None):
        """
        SCP file to device filesystem, defaults to candidate_config.

        Return None or raise exception
        """
        self.config_replace = True
        if config:
            raise NotImplementedError
        if filename:
            (return_status, msg) = self._scp_file(source_file=filename,
                                                  dest_file=self.candidate_cfg,
                                                  file_system=self.dest_file_system)
            if not return_status:
                if msg == '':
                    msg = "SCP transfer to remote device failed"
                raise ReplaceConfigException(msg)

    def load_merge_candidate(self, filename=None, config=None):
        """
        SCP file to remote device.

        Merge configuration in: copy <file> running-config
        """
        self.config_replace = False
        if config:
            raise NotImplementedError
        if filename:
            (return_status, msg) = self._scp_file(source_file=filename,
                                                  dest_file=self.merge_cfg,
                                                  file_system=self.dest_file_system)
            if not return_status:
                if msg == '':
                    msg = "SCP transfer to remote device failed"
                raise MergeConfigException(msg)

    @staticmethod
    def _normalize_compare_config(diff):
        """Filter out strings that should not show up in the diff."""
        ignore_strings = ['Contextual Config Diffs', 'No changes were found',
                          'file prompt quiet', 'ntp clock-period']

        new_list = []
        for line in diff.splitlines():
            for ignore in ignore_strings:
                if ignore in line:
                    break
            else:  # nobreak
                new_list.append(line)
        return "\n".join(new_list)

    @staticmethod
    def _normalize_merge_diff(diff):
        """Make compare_config() for merge look similar to replace config diff."""
        new_diff = []
        for line in diff.splitlines():
            # Filter blank lines and prepend +sign
            if line.strip():
                new_diff.append('+' + line)
        if new_diff:
            new_diff.insert(0, '! Cisco IOS does not support true compare_config() for merge: '
                            'echo merge file.')
        else:
            new_diff.append('! No changes specified in merge file.')
        return "\n".join(new_diff)

    def compare_config(self):
        """
        show archive config differences <base_file> <new_file>.

        Default operation is to compare system:running-config to self.candidate_cfg
        """
        # Set defaults
        base_file = 'running-config'
        base_file_system = 'system:'
        if self.config_replace:
            new_file = self.candidate_cfg
        else:
            new_file = self.merge_cfg
        new_file_system = self.dest_file_system

        base_file_full = self._gen_full_path(filename=base_file, file_system=base_file_system)
        new_file_full = self._gen_full_path(filename=new_file, file_system=new_file_system)

        if self.config_replace:
            cmd = 'show archive config differences {} {}'.format(base_file_full, new_file_full)
            diff = self.device.send_command_expect(cmd)
            diff = self._normalize_compare_config(diff)
        else:
            cmd = 'more {}'.format(new_file_full)
            diff = self.device.send_command_expect(cmd)
            diff = self._normalize_merge_diff(diff)
        return diff.strip()

    def _commit_hostname_handler(self, cmd):
        """Special handler for hostname change on commit operation."""
        try:
            current_prompt = self.device.find_prompt()
            # Wait 12 seconds for output to come back (.2 * 60)
            output = self.device.send_command_expect(cmd, delay_factor=.2, max_loops=60)
        except IOError:
            # Check if hostname change
            if current_prompt == self.device.find_prompt():
                raise
            else:
                self.device.set_base_prompt()
                output = ''
        return output

    def commit_config(self):
        """
        If replacement operation, perform 'configure replace' for the entire config.

        If merge operation, perform copy <file> running-config.
        """
        # Always generate a rollback config on commit
        self._gen_rollback_cfg()

        if self.config_replace:
            # Replace operation
            filename = self.candidate_cfg
            cfg_file = self._gen_full_path(filename)
            if not self._check_file_exists(cfg_file):
                raise ReplaceConfigException("Candidate config file does not exist")
            if self.auto_rollback_on_error:
                cmd = 'configure replace {} force revert trigger error'.format(cfg_file)
            else:
                cmd = 'configure replace {} force'.format(cfg_file)
            output = self._commit_hostname_handler(cmd)
            if ('Failed to apply command' in output) or \
               ('original configuration has been successfully restored' in output):
                raise ReplaceConfigException("Candidate config could not be applied")
        else:
            # Merge operation
            filename = self.merge_cfg
            cfg_file = self._gen_full_path(filename)
            if not self._check_file_exists(cfg_file):
                raise MergeConfigException("Merge source config file does not exist")
            cmd = 'copy {} running-config'.format(cfg_file)
            self._disable_confirm()
            output = self._commit_hostname_handler(cmd)
            self._enable_confirm()
            if 'Invalid input detected' in output:
                self.rollback()
                merge_error = "Configuration merge failed; automatic rollback attempted"
                raise MergeConfigException(merge_error)

        # Save config to startup (both replace and merge)
        output += self.device.send_command_expect("write mem")

    def discard_config(self):
        """Set candidate_cfg to current running-config. Erase the merge_cfg file."""
        discard_candidate = 'copy running-config {}'.format(self._gen_full_path(self.candidate_cfg))
        discard_merge = 'copy null: {}'.format(self._gen_full_path(self.merge_cfg))
        self._disable_confirm()
        self.device.send_command_expect(discard_candidate)
        self.device.send_command_expect(discard_merge)
        self._enable_confirm()

    def rollback(self):
        """Rollback configuration to filename or to self.rollback_cfg file."""
        filename = self.rollback_cfg
        cfg_file = self._gen_full_path(filename)
        if not self._check_file_exists(cfg_file):
            raise ReplaceConfigException("Rollback config file does not exist")
        cmd = 'configure replace {} force'.format(cfg_file)
        self.device.send_command_expect(cmd)

    def _scp_file(self, source_file, dest_file, file_system):
        """
        SCP file to remote device.

        Return (status, msg)
        status = boolean
        msg = details on what happened
        """
        # Will automaticall enable SCP on remote device
        enable_scp = True

        with FileTransfer(self.device,
                          source_file=source_file,
                          dest_file=dest_file,
                          file_system=file_system) as scp_transfer:

            # Check if file already exists and has correct MD5
            if scp_transfer.check_file_exists() and scp_transfer.compare_md5():
                msg = "File already exists and has correct MD5: no SCP needed"
                return (True, msg)
            if not scp_transfer.verify_space_available():
                msg = "Insufficient space available on remote device"
                return (False, msg)

            if enable_scp:
                scp_transfer.enable_scp()

            # Transfer file
            scp_transfer.transfer_file()

            # Compares MD5 between local-remote files
            if scp_transfer.verify_file():
                msg = "File successfully transferred to remote device"
                return (True, msg)
            else:
                msg = "File transfer to remote device failed"
                return (False, msg)
            return (False, '')

    def _enable_confirm(self):
        """Enable IOS confirmations on file operations (global config command)."""
        cmd = 'no file prompt quiet'
        self.device.send_config_set([cmd])

    def _disable_confirm(self):
        """Disable IOS confirmations on file operations (global config command)."""
        cmd = 'file prompt quiet'
        self.device.send_config_set([cmd])

    def _gen_full_path(self, filename, file_system=None):
        """Generate full file path on remote device."""
        if file_system is None:
            return '{}/{}'.format(self.dest_file_system, filename)
        else:
            if ":" not in file_system:
                raise ValueError("Invalid file_system specified: {}".format(file_system))
            return '{}/{}'.format(file_system, filename)

    def _gen_rollback_cfg(self):
        """Save a configuration that can be used for rollback."""
        cfg_file = self._gen_full_path(self.rollback_cfg)
        cmd = 'copy running-config {}'.format(cfg_file)
        self._disable_confirm()
        self.device.send_command_expect(cmd)
        self._enable_confirm()

    def _check_file_exists(self, cfg_file):
        """
        Check that the file exists on remote device using full path.

        cfg_file is full path i.e. flash:/file_name

        For example
        # dir flash:/candidate_config.txt
        Directory of flash:/candidate_config.txt

        33  -rw-        5592  Dec 18 2015 10:50:22 -08:00  candidate_config.txt

        return boolean
        """
        cmd = 'dir {}'.format(cfg_file)
        success_pattern = 'Directory of {}'.format(cfg_file)
        output = self.device.send_command_expect(cmd)
        if 'Error opening' in output:
            return False
        elif success_pattern in output:
            return True
        return False

    def _expand_interface_name(self, interface_brief):
        """
        Obtain the full interface name from the abbreviated name.

        Cache mappings in self.interface_map.
        """
        if self.interface_map.get(interface_brief):
            return self.interface_map.get(interface_brief)
        command = 'show int {}'.format(interface_brief)
        output = self._send_command(command)
        first_line = output.splitlines()[0]
        if 'line protocol' in first_line:
            full_int_name = first_line.split()[0]
            self.interface_map[interface_brief] = full_int_name
            return self.interface_map.get(interface_brief)
        else:
            return interface_brief

    @staticmethod
    def _send_command_postprocess(output):
        """
        Cleanup actions on send_command() for NAPALM getters.

        Remove "Load for five sec; one minute if in output"
        Remove "Time source is"
        """
        output = re.sub(r"^Load for five secs.*$", "", output, flags=re.M)
        output = re.sub(r"^Time source is .*$", "", output, flags=re.M)
        return output.strip()

    def get_lldp_neighbors(self):
        """IOS implementation of get_lldp_neighbors."""
        lldp = {}
        command = 'show lldp neighbors'
        output = self._send_command(command)

        # Check if router supports the command
        if '% Invalid input' in output:
            return {}

        # Process the output to obtain just the LLDP entries
        try:
            split_output = re.split(r'^Device ID.*$', output, flags=re.M)[1]
            split_output = re.split(r'^Total entries displayed.*$', split_output, flags=re.M)[0]
        except IndexError:
            return {}

        split_output = split_output.strip()

        for lldp_entry in split_output.splitlines():
            # Example, twb-sf-hpsw1    Fa4   120   B   17
            device_id, local_int_brief, hold_time, capability, remote_port = lldp_entry.split()
            local_port = self._expand_interface_name(local_int_brief)

            entry = {'port': remote_port, 'hostname': device_id}
            lldp.setdefault(local_port, [])
            lldp[local_port].append(entry)

        return lldp

    def get_lldp_neighbors_detail(self, interface=''):
        """
        IOS implementation of get_lldp_neighbors_detail.

        Calls get_lldp_neighbors.
        """
        lldp = {}
        lldp_neighbors = self.get_lldp_neighbors()

        # Filter to specific interface
        if interface:
            lldp_data = lldp_neighbors.get(interface)
            if lldp_data:
                lldp_neighbors = {interface: lldp_data}
            else:
                lldp_neighbors = {}

        for interface in lldp_neighbors:
            command = "show lldp neighbors {} detail".format(interface)
            output = self._send_command(command)

            # Check if router supports the command
            if '% Invalid input' in output:
                return {}

            local_port = interface
            port_id = re.findall(r"Port id: (.+)", output)
            port_description = re.findall(r"Port Description: (.+)", output)
            chassis_id = re.findall(r"Chassis id: (.+)", output)
            system_name = re.findall(r"System Name: (.+)", output)
            system_description = re.findall(r"System Description: \n(.+)", output)
            system_capabilities = re.findall(r"System Capabilities: (.+)", output)
            enabled_capabilities = re.findall(r"Enabled Capabilities: (.+)", output)
            remote_address = re.findall(r"Management Addresses:\n    IP: (.+)", output)
            if not remote_address:
                remote_address = re.findall(r"Management Addresses:\n    Other: (.+)", output)
            number_entries = len(port_id)
            lldp_fields = [port_id, port_description, chassis_id, system_name, system_description,
                           system_capabilities, enabled_capabilities, remote_address]

            # re.findall will return a list. Make sure same number of entries always returned.
            for test_list in lldp_fields:
                if len(test_list) != number_entries:
                    raise ValueError("Failure processing show lldp neighbors detail")

            # Standardize the fields
            port_id, port_description, chassis_id, system_name, system_description, \
                system_capabilities, enabled_capabilities, remote_address = lldp_fields
            standardized_fields = zip(port_id, port_description, chassis_id, system_name,
                                      system_description, system_capabilities,
                                      enabled_capabilities, remote_address)

            lldp.setdefault(local_port, [])
            for entry in standardized_fields:
                remote_port_id, remote_port_description, remote_chassis_id, remote_system_name, \
                    remote_system_description, remote_system_capab, remote_enabled_capab, \
                    remote_mgmt_address = entry

                lldp[local_port].append({
                    'parent_interface': u'N/A',
                    'remote_port': remote_port_id,
                    'remote_port_description': remote_port_description,
                    'remote_chassis_id': remote_chassis_id,
                    'remote_system_name': remote_system_name,
                    'remote_system_description': remote_system_description,
                    'remote_system_capab': remote_system_capab,
                    'remote_system_enable_capab': remote_enabled_capab})

        return lldp

    @staticmethod
    def parse_uptime(uptime_str):
        """
        Extract the uptime string from the given Cisco IOS Device.

        Return the uptime in seconds as an integer
        """
        # Initialize to zero
        (years, weeks, days, hours, minutes) = (0, 0, 0, 0, 0)

        uptime_str = uptime_str.strip()
        time_list = uptime_str.split(',')
        for element in time_list:
            if re.search("year", element):
                years = int(element.split()[0])
            elif re.search("week", element):
                weeks = int(element.split()[0])
            elif re.search("day", element):
                days = int(element.split()[0])
            elif re.search("hour", element):
                hours = int(element.split()[0])
            elif re.search("minute", element):
                minutes = int(element.split()[0])

        uptime_sec = (years * YEAR_SECONDS) + (weeks * WEEK_SECONDS) + (days * DAY_SECONDS) + \
                     (hours * 3600) + (minutes * 60)
        return uptime_sec

    def get_facts(self):
        """Return a set of facts from the devices."""
        # default values.
        vendor = u'Cisco'
        uptime = -1
        serial_number, fqdn, os_version, hostname = (u'Unknown', u'Unknown', u'Unknown', u'Unknown')

        # obtain output from device
        show_ver = self._send_command('show version')
        show_hosts = self._send_command('show hosts')
        show_ip_int_br = self._send_command('show ip interface brief')

        # uptime/serial_number/IOS version
        for line in show_ver.splitlines():
            if ' uptime is ' in line:
                hostname, uptime_str = line.split(' uptime is ')
                uptime = self.parse_uptime(uptime_str)
                hostname = hostname.strip()

            if 'Processor board ID' in line:
                _, serial_number = line.split("Processor board ID ")
                serial_number = serial_number.strip()

            if re.search(r"Cisco IOS Software", line):
                try:
                    _, os_version = line.split("Cisco IOS Software, ")
                except ValueError:
                    # Handle 'Cisco IOS Software [Denali],'
                    _, os_version = re.split(r"Cisco IOS Software \[.*?\], ", line)
                os_version = os_version.strip()
            elif re.search(r"IOS (tm).+Software", line):
                _, os_version = line.split("IOS (tm) ")
                os_version = os_version.strip()

        # Determine domain_name and fqdn
        for line in show_hosts.splitlines():
            if 'Default domain' in line:
                _, domain_name = line.split("Default domain is ")
                domain_name = domain_name.strip()
                break
        if domain_name != 'Unknown' and hostname != 'Unknown':
            fqdn = u'{}.{}'.format(hostname, domain_name)

        # model filter
        try:
            match_model = re.search(r"Cisco (.+?) .+bytes of", show_ver, flags=re.IGNORECASE)
            model = match_model.group(1)
        except AttributeError:
            model = u'Unknown'

        # interface_list filter
        interface_list = []
        show_ip_int_br = show_ip_int_br.strip()
        for line in show_ip_int_br.splitlines():
            if 'Interface ' in line:
                continue
            interface = line.split()[0]
            interface_list.append(interface)

        return {
            'uptime': uptime,
            'vendor': vendor,
            'os_version': py23_compat.text_type(os_version),
            'serial_number': py23_compat.text_type(serial_number),
            'model': py23_compat.text_type(model),
            'hostname': py23_compat.text_type(hostname),
            'fqdn': fqdn,
            'interface_list': interface_list
        }

    def get_interfaces(self):
        """
        Get interface details.

        last_flapped is not implemented

        Example Output:

        {   u'Vlan1': {   'description': u'N/A',
                      'is_enabled': True,
                      'is_up': True,
                      'last_flapped': -1.0,
                      'mac_address': u'a493.4cc1.67a7',
                      'speed': 100},
        u'Vlan100': {   'description': u'Data Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 100},
        u'Vlan200': {   'description': u'Voice Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 100}}
        """
        interface_list = {}

        # default values.
        last_flapped = -1.0

        # creating the parsing regex.
        mac_regex = r".*,\saddress\sis\s(?P<mac_address>\S+).*"
        speed_regex = r".*BW\s(?P<speed>\d+)\s(?P<speed_format>\S+).*"

        command = 'show ip interface brief'
        output = self._send_command(command)
        for line in output.splitlines():
            if 'Interface' in line and 'Status' in line:
                continue
            fields = line.split()
            """
            router#sh ip interface brief
            Interface                  IP-Address      OK? Method Status                Protocol
            FastEthernet8              10.65.43.169    YES DHCP   up                    up
            GigabitEthernet0           unassigned      YES NVRAM  administratively down down
            Loopback234                unassigned      YES unset  up                    up
            Loopback555                unassigned      YES unset  up                    up
            NVI0                       unassigned      YES unset  administratively down down
            Tunnel0                    10.63.100.9     YES NVRAM  up                    up
            Tunnel1                    10.63.101.9     YES NVRAM  up                    up
            Vlan1                      unassigned      YES unset  up                    up
            Vlan100                    10.40.0.1       YES NVRAM  up                    up
            Vlan200                    10.63.176.57    YES NVRAM  up                    up
            Wlan-GigabitEthernet0      unassigned      YES unset  up                    up
            wlan-ap0                   10.40.0.1       YES unset  up                    up
            """

            # Check for administratively down
            if len(fields) == 6:
                interface, ip_address, ok, method, status, protocol = fields
            elif len(fields) == 7:
                # Administratively down is two fields in the output for status
                interface, ip_address, ok, method, status, status2, protocol = fields
            else:
                raise ValueError(u"Unexpected Response from the device")

            status = status.lower()
            protocol = protocol.lower()
            if 'admin' in status:
                is_enabled = False
            else:
                is_enabled = True
            is_up = bool('up' in protocol)
            interface_list[interface] = {
                'is_up': is_up,
                'is_enabled': is_enabled,
                'last_flapped': last_flapped,
            }

        for interface in interface_list:
            show_command = "show interface {0}".format(interface)
            interface_output = self._send_command(show_command)
            try:
                # description filter
                description = re.search(r"  Description: (.+)", interface_output)
                interface_list[interface]['description'] = description.group(1).strip('\r')
            except AttributeError:
                interface_list[interface]['description'] = u'N/A'

            try:
                # mac_address filter.
                match_mac = re.match(mac_regex, interface_output, flags=re.DOTALL)
                group_mac = match_mac.groupdict()
                mac_address = group_mac["mac_address"]
                interface_list[interface]['mac_address'] = py23_compat.text_type(mac_address)
            except AttributeError:
                interface_list[interface]['mac_address'] = u'N/A'
            try:
                # BW filter.
                match_speed = re.match(speed_regex, interface_output, flags=re.DOTALL)
                group_speed = match_speed.groupdict()
                speed = group_speed["speed"]
                speed_format = group_speed["speed_format"]
                if speed_format == 'Mbit':
                    interface_list[interface]['speed'] = int(speed)
                else:
                    speed = int(speed) / 1000
                    interface_list[interface]['speed'] = int(speed)
            except AttributeError:
                interface_list[interface]['speed'] = -1
            except ValueError:
                interface_list[interface]['speed'] = -1

        return interface_list

    def get_interfaces_ip(self):
        """
        Get interface ip details.

        Returns a dict of dicts

        Example Output:

        {   u'FastEthernet8': {   'ipv4': {   u'10.66.43.169': {   'prefix_length': 22}}},
            u'Loopback555': {   'ipv4': {   u'192.168.1.1': {   'prefix_length': 24}},
                                'ipv6': {   u'1::1': {   'prefix_length': 64},
                                            u'2001:DB8:1::1': {   'prefix_length': 64},
                                            u'2::': {   'prefix_length': 64},
                                            u'FE80::3': {   'prefix_length': u'N/A'}}},
            u'Tunnel0': {   'ipv4': {   u'10.63.100.9': {   'prefix_length': 24}}},
            u'Tunnel1': {   'ipv4': {   u'10.63.101.9': {   'prefix_length': 24}}},
            u'Vlan100': {   'ipv4': {   u'10.40.0.1': {   'prefix_length': 24},
                                        u'10.41.0.1': {   'prefix_length': 24},
                                        u'10.65.0.1': {   'prefix_length': 24}}},
            u'Vlan200': {   'ipv4': {   u'10.63.176.57': {   'prefix_length': 29}}}}
        """
        interfaces = {}

        command = 'show ip interface brief'
        output = self._send_command(command)
        for line in output.splitlines():
            if 'Interface' in line and 'Status' in line:
                continue
            fields = line.split()
            if len(fields) >= 3:
                interface = fields[0]
            else:
                raise ValueError("Unexpected response from the router")
            interfaces.update({interface: {}})

        # Parse IP Address and Subnet Mask from Interfaces
        for interface in interfaces:
            show_command = "show run interface {0}".format(interface)
            interface_output = self._send_command(show_command)
            for line in interface_output.splitlines():
                if 'ip address ' in line and 'no ip address' not in line:
                    fields = line.split()
                    if len(fields) == 3:
                        # Check for 'ip address dhcp', convert to ip address and mask
                        if fields[2] == 'dhcp':
                            cmd = "show interface {} | in Internet address is".format(interface)
                            show_int = self._send_command(cmd)
                            int_fields = show_int.split()
                            ip_address, subnet = int_fields[3].split(r'/')
                            interfaces[interface]['ipv4'] = {ip_address: {}}
                            try:
                                val = {'prefix_length': int(subnet)}
                            except ValueError:
                                val = {'prefix_length': u'N/A'}
                            interfaces[interface]['ipv4'][ip_address] = val
                    elif len(fields) in [4, 5]:
                        # Check for 'ip address 10.10.10.1 255.255.255.0'
                        # Check for 'ip address 10.10.11.1 255.255.255.0 secondary'
                        if 'ipv4' not in interfaces[interface].keys():
                            interfaces[interface].update({'ipv4': {}})
                        ip_address = fields[2]

                        try:
                            subnet = sum([bin(int(x)).count('1') for x in fields[3].split('.')])
                        except ValueError:
                            subnet = u'N/A'

                        ip_dict = {'prefix_length': subnet}
                        interfaces[interface]['ipv4'].update({ip_address: {}})
                        interfaces[interface]['ipv4'][ip_address].update(ip_dict)
                    else:
                        raise ValueError(u"Unexpected Response from the device")

                # Check IPv6
                if 'ipv6 address ' in line:
                    fields = line.split()
                    ip_address = fields[2]
                    if 'ipv6' not in interfaces[interface].keys():
                            interfaces[interface].update({'ipv6': {}})

                    try:
                        if r'/' in ip_address:
                            # check for 'ipv6 address 1::1/64'
                            ip_address, subnet = ip_address.split(r'/')
                            interfaces[interface]['ipv6'].update({ip_address: {}})
                            ip_dict = {'prefix_length': int(subnet)}
                        else:
                            # check for 'ipv6 address FE80::3 link-local'
                            interfaces[interface]['ipv6'].update({ip_address: {}})
                            ip_dict = {'prefix_length': u'N/A'}

                        interfaces[interface]['ipv6'][ip_address].update(ip_dict)
                    except AttributeError:
                        raise ValueError(u"Unexpected Response from the device")

        # remove keys with no data
        new_interfaces = {}
        for k, val in interfaces.items():
            if val:
                new_interfaces[k] = val
        return new_interfaces

    @staticmethod
    def bgp_time_conversion(bgp_uptime):
        """
        Convert string time to seconds.

        Examples
        00:14:23
        00:13:40
        00:00:21
        00:00:13
        00:00:49
        1d11h
        1d17h
        1w0d
        8w5d
        1y28w
        never
        """
        bgp_uptime = bgp_uptime.strip()
        uptime_letters = set(['w', 'h', 'd'])

        if 'never' in bgp_uptime:
            return -1
        elif ':' in bgp_uptime:
            times = bgp_uptime.split(":")
            times = [int(x) for x in times]
            hours, minutes, seconds = times
            return (hours * 3600) + (minutes * 60) + seconds
        # Check if any letters 'w', 'h', 'd' are in the time string
        elif uptime_letters & set(bgp_uptime):
            form1 = r'(\d+)d(\d+)h'  # 1d17h
            form2 = r'(\d+)w(\d+)d'  # 8w5d
            form3 = r'(\d+)y(\d+)w'  # 1y28w
            match = re.search(form1, bgp_uptime)
            if match:
                days = int(match.group(1))
                hours = int(match.group(2))
                return (days * DAY_SECONDS) + (hours * 3600)
            match = re.search(form2, bgp_uptime)
            if match:
                weeks = int(match.group(1))
                days = int(match.group(2))
                return (weeks * WEEK_SECONDS) + (days * DAY_SECONDS)
            match = re.search(form3, bgp_uptime)
            if match:
                years = int(match.group(1))
                weeks = int(match.group(2))
                return (years * YEAR_SECONDS) + (weeks * WEEK_SECONDS)
        raise ValueError("Unexpected value for BGP uptime string: {}".format(bgp_uptime))

    def get_bgp_neighbors(self):
        """
        BGP neighbor information.

        Currently, no VRF support
        Not tested with IPv6

        Example output of 'show ip bgp summary' only peer table
        Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down State/PfxRcd
        10.100.1.1      4   200      26      22      199    0    0 00:14:23 23
        10.200.1.1      4   300      21      51      199    0    0 00:13:40 0
        192.168.1.2     4   200      19      17        0    0    0 00:00:21 2
        1.1.1.1         4     1       0       0        0    0    0 never    Active
        3.3.3.3         4     2       0       0        0    0    0 never    Idle
        1.1.1.2         4     1      11       9        0    0    0 00:00:13 Idle (Admin)
        1.1.1.3         4 27506  256642   11327     2527    0    0 1w0d     519
        1.1.1.4         4 46887 1015641   19982     2527    0    0 1w0d     365
        192.168.1.237   4 60000    2139    2355 13683280    0    0 1d11h    4 (SE)
        10.90.1.4       4 65015    2508    2502      170    0    0 1d17h    163
        172.30.155.20   4   111       0       0        0    0    0 never    Active
        1.1.1.5         4  6500      54      28        0    0    0 00:00:49 Idle (PfxCt)
        10.1.4.46       4  3979   95244   98874   267067    0    0 8w5d     254
        10.1.4.58       4  3979    2715    3045   267067    0    0 1d21h    2
        10.1.1.85       4 65417 8344303 8343570      235    0    0 1y28w    2
        """
        cmd_bgp_summary = 'show ip bgp summary'
        bgp_neighbor_data = {}
        bgp_neighbor_data['global'] = {}

        output = self._send_command(cmd_bgp_summary).strip()
        # Cisco issue where new lines are inserted after neighbor IP
        output = re.sub(RE_IPADDR_STRIP, r"\1", output)
        if 'Neighbor' not in output:
            return {}
        for line in output.splitlines():
            if 'router identifier' in line:
                # BGP router identifier 172.16.1.1, local AS number 100
                rid_regex = r'^.* router identifier (\d+\.\d+\.\d+\.\d+), local AS number (\d+)'
                match = re.search(rid_regex, line)
                router_id = match.group(1)
                local_as = int(match.group(2))
                break
        bgp_neighbor_data['global']['router_id'] = py23_compat.text_type(router_id)
        bgp_neighbor_data['global']['peers'] = {}

        cmd_neighbor_table = 'show ip bgp summary | begin Neighbor'
        output = self._send_command(cmd_neighbor_table).strip()
        # Cisco issue where new lines are inserted after neighbor IP
        output = re.sub(RE_IPADDR_STRIP, r"\1", output)
        for line in output.splitlines():
            line = line.strip()
            if 'Neighbor' in line or line == '':
                continue
            fields = line.split()[:10]
            peer_id, bgp_version, remote_as, msg_rcvd, msg_sent, table_version, in_queue, \
                out_queue, up_time, state_prefix = fields
            peer_id = peer_id.replace('*', '')

            if '(Admin)' in state_prefix:
                is_enabled = False
            else:
                is_enabled = True
            try:
                state_prefix = int(state_prefix)
                is_up = True
            except ValueError:
                is_up = False

            if bgp_version == '4':
                address_family = 'ipv4'
            elif bgp_version == '6':
                address_family = 'ipv6'
            else:
                raise ValueError("BGP neighbor parsing failed")

            cmd_remote_rid = 'show ip bgp neighbors {} | inc router ID'.format(peer_id)
            # output: BGP version 4, remote router ID 1.1.1.1
            remote_rid_out = self._send_command(cmd_remote_rid)
            remote_rid = remote_rid_out.split()[-1]

            bgp_neighbor_data['global']['peers'].setdefault(peer_id, {})
            peer_dict = {}
            peer_dict['uptime'] = self.bgp_time_conversion(up_time)
            peer_dict['remote_as'] = int(remote_as)
            peer_dict['description'] = u''
            peer_dict['local_as'] = local_as
            peer_dict['is_enabled'] = is_enabled
            peer_dict['is_up'] = is_up
            peer_dict['remote_id'] = py23_compat.text_type(remote_rid)

            cmd_current_prefixes = 'show ip bgp neighbors {} | inc Prefixes Current'.format(peer_id)
            # output: Prefixes Current:               0          0
            current_prefixes_out = self._send_command(cmd_current_prefixes)
            pattern = r'Prefixes Current:\s+(\d+)\s+(\d+).*'  # Prefixes Current:    0     0
            match = re.search(pattern, current_prefixes_out)
            if match:
                sent_prefixes = int(match.group(1))
                accepted_prefixes = int(match.group(2))
            else:
                sent_prefixes = accepted_prefixes = -1

            cmd_filtered_prefix = 'show ip bgp neighbors {} | section Local Policy'.format(peer_id)
            # output:
            # Local Policy Denied Prefixes:    --------    -------
            # prefix-list                           0          2
            # Total:                                0          2
            filtered_prefixes_out = self._send_command(cmd_filtered_prefix)
            sent_prefixes = int(sent_prefixes)
            pattern = r'Total:\s+\d+\s+(\d+).*'  # Total:     0          2
            match = re.search(pattern, filtered_prefixes_out)
            if match:
                filtered_prefixes = int(match.group(1))
                received_prefixes = filtered_prefixes + accepted_prefixes
            else:
                # If unable to determine filtered prefixes set received prefixes to accepted
                received_prefixes = accepted_prefixes

            af_dict = {}
            af_dict.setdefault(address_family, {})
            af_dict[address_family]['sent_prefixes'] = sent_prefixes
            af_dict[address_family]['accepted_prefixes'] = accepted_prefixes
            af_dict[address_family]['received_prefixes'] = received_prefixes

            peer_dict['address_family'] = af_dict
            bgp_neighbor_data['global']['peers'][peer_id] = peer_dict

        return bgp_neighbor_data

    def get_interfaces_counters(self):
        """
        Return interface counters and errors.

        'tx_errors': int,
        'rx_errors': int,
        'tx_discards': int,
        'rx_discards': int,
        'tx_octets': int,
        'rx_octets': int,
        'tx_unicast_packets': int,
        'rx_unicast_packets': int,
        'tx_multicast_packets': int,
        'rx_multicast_packets': int,
        'tx_broadcast_packets': int,
        'rx_broadcast_packets': int,

        Currently doesn't determine output broadcasts, multicasts
        Doesn't determine tx_discards or rx_discards
        """
        counters = {}
        command = 'show interfaces'
        output = self._send_command(command)

        # Break output into per-interface sections
        interface_strings = re.split(r'.* line protocol is .*', output, flags=re.M)
        header_strings = re.findall(r'.* line protocol is .*', output, flags=re.M)

        empty = interface_strings.pop(0).strip()
        if empty:
            raise ValueError("Unexpected output from: {}".format(command))

        # Parse out the interface names
        intf = []
        for intf_line in header_strings:
            interface, _ = re.split(r" is .* line protocol is ", intf_line)
            intf.append(interface.strip())

        if len(intf) != len(interface_strings):
            raise ValueError("Unexpected output from: {}".format(command))

        # Re-join interface names with interface strings
        for interface, interface_str in zip(intf, interface_strings):
            counters.setdefault(interface, {})
            for line in interface_str.splitlines():
                if 'packets input' in line:
                    # '0 packets input, 0 bytes, 0 no buffer'
                    match = re.search(r"(\d+) packets input.*(\d+) bytes", line)
                    counters[interface]['rx_unicast_packets'] = int(match.group(1))
                    counters[interface]['rx_octets'] = int(match.group(2))
                elif 'broadcast' in line:
                    # 'Received 0 broadcasts (0 multicasts)'
                    # 'Received 264071 broadcasts (39327 IP multicasts)'
                    # 'Received 338 broadcasts, 0 runts, 0 giants, 0 throttles'
                    match = re.search(r"Received (\d+) broadcasts.*(\d+).*multicasts", line)
                    alt_match = re.search(r"Received (\d+) broadcasts.*", line)
                    if match:
                        counters[interface]['rx_broadcast_packets'] = int(match.group(1))
                        counters[interface]['rx_multicast_packets'] = int(match.group(2))
                    elif alt_match:
                        counters[interface]['rx_broadcast_packets'] = int(alt_match.group(1))
                        counters[interface]['rx_multicast_packets'] = -1
                    else:
                        counters[interface]['rx_broadcast_packets'] = -1
                        counters[interface]['rx_multicast_packets'] = -1
                elif 'packets output' in line:
                    # '0 packets output, 0 bytes, 0 underruns'
                    match = re.search(r"(\d+) packets output.*(\d+) bytes", line)
                    counters[interface]['tx_unicast_packets'] = int(match.group(1))
                    counters[interface]['tx_octets'] = int(match.group(2))
                    counters[interface]['tx_broadcast_packets'] = -1
                    counters[interface]['tx_multicast_packets'] = -1
                elif 'input errors' in line:
                    # '0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored'
                    match = re.search(r"(\d+) input errors", line)
                    counters[interface]['rx_errors'] = int(match.group(1))
                    counters[interface]['rx_discards'] = -1
                elif 'output errors' in line:
                    # '0 output errors, 0 collisions, 1 interface resets'
                    match = re.search(r"(\d+) output errors", line)
                    counters[interface]['tx_errors'] = int(match.group(1))
                    counters[interface]['tx_discards'] = -1

        return counters

    def get_environment(self):
        """
        Get environment facts.

        power, fan, temperature are currently not implemented
        cpu is using 1-minute average
        cpu hard-coded to cpu0 (i.e. only a single CPU)
        """
        environment = {}
        cpu_cmd = 'show proc cpu'
        mem_cmd = 'show memory statistics'

        output = self._send_command(cpu_cmd)
        environment.setdefault('cpu', {})
        environment['cpu'][0] = {}
        environment['cpu'][0]['%usage'] = 0.0
        for line in output.splitlines():
            if 'CPU utilization' in line:
                # CPU utilization for five seconds: 2%/0%; one minute: 2%; five minutes: 1%
                cpu_regex = r'^.*one minute: (\d+)%; five.*$'
                match = re.search(cpu_regex, line)
                environment['cpu'][0]['%usage'] = float(match.group(1))
                break

        output = self._send_command(mem_cmd)
        for line in output.splitlines():
            if 'Processor' in line:
                _, _, _, proc_used_mem, proc_free_mem = line.split()[:5]
            elif 'I/O' in line or 'io' in line:
                _, _, _, io_used_mem, io_free_mem = line.split()[:5]
        used_mem = int(proc_used_mem) + int(io_used_mem)
        free_mem = int(proc_free_mem) + int(io_free_mem)
        environment.setdefault('memory', {})
        environment['memory']['used_ram'] = used_mem
        environment['memory']['available_ram'] = free_mem

        # Initialize 'power', 'fan', and 'temperature' to default values (not implemented)
        environment.setdefault('power', {})
        environment['power']['invalid'] = {'status': True, 'output': -1.0, 'capacity': -1.0}
        environment.setdefault('fans', {})
        environment['fans']['invalid'] = {'status': True}
        environment.setdefault('temperature', {})
        env_value = {'is_alert': False, 'is_critical': False, 'temperature': -1.0}
        environment['temperature']['invalid'] = env_value
        return environment

    def get_arp_table(self):
        """
        Get arp table information.

        Return a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float)

        For example::
            [
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '5c:5e:ab:da:3c:f0',
                    'ip'        : '172.17.17.1',
                    'age'       : 1454496274.84
                },
                {
                    'interface': 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '66:0e:94:96:e0:ff',
                    'ip'        : '172.17.17.2',
                    'age'       : 1435641582.49
                }
            ]
        """
        arp_table = []

        command = 'show arp | exclude Incomplete'
        output = self._send_command(command)

        # Skip the first line which is a header
        output = output.split('\n')
        output = output[1:]

        for line in output:
            if len(line) == 0:
                return {}
            if len(line.split()) == 5:
                # Static ARP entries have no interface
                # Internet  10.0.0.1                -   0010.2345.1cda  ARPA
                interface = ''
                protocol, address, age, mac, eth_type = line.split()
            elif len(line.split()) == 6:
                protocol, address, age, mac, eth_type, interface = line.split()
            else:
                raise ValueError("Unexpected output from: {}".format(line.split()))

            try:
                if age == '-':
                    age = 0
                age = float(age)
            except ValueError:
                raise ValueError("Unable to convert age value to float: {}".format(age))

            # Validate we matched correctly
            if not re.search(RE_IPADDR, address):
                raise ValueError("Invalid IP Address detected: {}".format(address))
            if not re.search(RE_MAC, mac):
                raise ValueError("Invalid MAC Address detected: {}".format(mac))
            entry = {
                'interface': interface,
                'mac': mac,
                'ip': address,
                'age': age
            }
            arp_table.append(entry)
        return arp_table

    def cli(self, commands):
        """
        Execute a list of commands and return the output in a dictionary format using the command
        as the key.

        Example input:
        ['show clock', 'show calendar']

        Output example:
        {   'show calendar': u'22:02:01 UTC Thu Feb 18 2016',
            'show clock': u'*22:01:51.165 UTC Thu Feb 18 2016'}

        """
        cli_output = dict()
        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            output = self._send_command(command)
            if 'Invalid input detected' in output:
                raise ValueError('Unable to execute command "{}"'.format(command))
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    def get_ntp_servers(self):
        """Implementation of get_ntp_servers for IOS.

        Returns the NTP servers configuration as dictionary.
        The keys of the dictionary represent the IP Addresses of the servers.
        Inner dictionaries do not have yet any available keys.
        Example::
            {
                '192.168.0.1': {},
                '17.72.148.53': {},
                '37.187.56.220': {},
                '162.158.20.18': {}
            }
        """
        ntp_servers = {}
        command = 'show run | include ntp server'
        output = self._send_command(command)

        for line in output.splitlines():
            split_line = line.split()
            if "vrf" == split_line[2]:
                ntp_servers[split_line[4]] = {}
            else:
                ntp_servers[split_line[2]] = {}

        return ntp_servers

    def get_ntp_stats(self):
        """Implementation of get_ntp_stats for IOS."""
        ntp_stats = []

        command = 'show ntp associations'
        output = self._send_command(command)

        for line in output.splitlines():
            # Skip first two lines and last line of command output
            if line == "" or 'address' in line or 'sys.peer' in line:
                continue

            if '%NTP is not enabled' in line:
                return []

            elif len(line.split()) == 9:
                address, ref_clock, st, when, poll, reach, delay, offset, disp = line.split()
                address_regex = re.match('(\W*)([0-9.*]*)', address)
            try:
                ntp_stats.append({
                    'remote': py23_compat.text_type(address_regex.group(2)),
                    'synchronized': ('*' in address_regex.group(1)),
                    'referenceid': py23_compat.text_type(ref_clock),
                    'stratum': int(st),
                    'type': u'-',
                    'when': py23_compat.text_type(when),
                    'hostpoll': int(poll),
                    'reachability': int(reach),
                    'delay': float(delay),
                    'offset': float(offset),
                    'jitter': float(disp)
                })
            except Exception:
                continue

        return ntp_stats

    def get_mac_address_table(self):
        """
        Returns a lists of dictionaries. Each dictionary represents an entry in the MAC Address
        Table, having the following keys
            * mac (string)
            * interface (string)
            * vlan (int)
            * active (boolean)
            * static (boolean)
            * moves (int)
            * last_move (float)

        Format1:
        Destination Address  Address Type  VLAN  Destination Port
        -------------------  ------------  ----  --------------------
        6400.f1cf.2cc6          Dynamic       1     Wlan-GigabitEthernet0

        Cat 6500:
        Legend: * - primary entry
                age - seconds since last seen
                n/a - not available

          vlan   mac address     type    learn     age              ports
        ------+----------------+--------+-----+----------+--------------------------
        *  999  1111.2222.3333   dynamic  Yes          0   Port-channel1
           999  1111.2222.3333   dynamic  Yes          0   Port-channel1

        Cat 4948
        Unicast Entries
         vlan   mac address     type        protocols               port
        -------+---------------+--------+---------------------+--------------------
         999    1111.2222.3333   dynamic ip                    Port-channel1

        Cat 2960
        Mac Address Table
        -------------------------------------------

        Vlan    Mac Address       Type        Ports
        ----    -----------       --------    -----
        All    1111.2222.3333    STATIC      CPU
        """

        RE_MACTABLE_DEFAULT = r"^" + MAC_REGEX
        RE_MACTABLE_6500_1 = r"^\*\s+{}\s+{}\s+".format(VLAN_REGEX, MAC_REGEX)  # 7 fields
        RE_MACTABLE_6500_2 = r"^{}\s+{}\s+".format(VLAN_REGEX, MAC_REGEX)   # 6 fields
        RE_MACTABLE_4500 = r"^{}\s+{}\s+".format(VLAN_REGEX, MAC_REGEX)     # 5 fields
        RE_MACTABLE_2960_1 = r"^All\s+{}".format(MAC_REGEX)
        RE_MACTABLE_2960_2 = r"^{}\s+{}\s+".format(VLAN_REGEX, MAC_REGEX)   # 4 fields

        def process_mac_fields(vlan, mac, mac_type, interface):
            """Return proper data for mac address fields."""
            if mac_type.lower() in ['self', 'static']:
                static = True
                if vlan.lower() == 'all':
                    vlan = 0
                if interface.lower() == 'cpu':
                    interface = ''
            else:
                static = False
            if mac_type.lower() in ['dynamic']:
                active = True
            else:
                active = False
            return {
                'mac': mac,
                'interface': interface,
                'vlan': int(vlan),
                'static': static,
                'active': active,
                'moves': -1,
                'last_move': -1.0
            }

        mac_address_table = []
        command = IOS_COMMANDS['show_mac_address']
        output = self._send_command(command)

        # Skip the header lines
        output = re.split(r'^----.*', output, flags=re.M)[1:]
        output = "\n".join(output).strip()
        for line in output.splitlines():
            line = line.strip()
            if line == '':
                continue
            # Format1
            elif re.search(RE_MACTABLE_DEFAULT, line):
                if len(line.split()) == 4:
                    mac, mac_type, vlan, interface = line.split()
                    mac_address_table.append(process_mac_fields(vlan, mac, mac_type, interface))
                else:
                    raise ValueError("Unexpected output from: {}".format(line.split()))
            # Cat6500 format
            elif (re.search(RE_MACTABLE_6500_1, line) or re.search(RE_MACTABLE_6500_2, line)) and \
                    len(line.split()) >= 6:
                if len(line.split()) == 7:
                    _, vlan, mac, mac_type, _, _, interface = line.split()
                elif len(line.split()) == 6:
                    vlan, mac, mac_type, _, _, interface = line.split()
                mac_address_table.append(process_mac_fields(vlan, mac, mac_type, interface))
            # Cat4948 format
            elif re.search(RE_MACTABLE_4500, line) and len(line.split()) == 5:
                vlan, mac, mac_type, _, interface = line.split()
                mac_address_table.append(process_mac_fields(vlan, mac, mac_type, interface))
            # Cat2960 format - ignore extra header line
            elif re.search(r"^Vlan\s+Mac Address\s+", line):
                continue
            # Cat2960 format
            elif (re.search(RE_MACTABLE_2960_1, line) or re.search(RE_MACTABLE_2960_2, line)) and \
                    len(line.split()) == 4:
                vlan, mac, mac_type, interface = line.split()
                mac_address_table.append(process_mac_fields(vlan, mac, mac_type, interface))
            else:
                raise ValueError("Unexpected output from: {}".format(repr(line)))
        return mac_address_table

    def get_snmp_information(self):
        """
        Returns a dict of dicts

        Example Output:

        {   'chassis_id': u'Asset Tag 54670',
        'community': {   u'private': {   'acl': u'12', 'mode': u'rw'},
                         u'public': {   'acl': u'11', 'mode': u'ro'},
                         u'public_named_acl': {   'acl': u'ALLOW-SNMP-ACL',
                                                  'mode': u'ro'},
                         u'public_no_acl': {   'acl': u'N/A', 'mode': u'ro'}},
        'contact': u'Joe Smith',
        'location': u'123 Anytown USA Rack 404'}

        """
        # default values
        snmp_dict = {
            'chassis_id': u'unknown',
            'community': {},
            'contact': u'unknown',
            'location': u'unknown'
        }
        command = 'show run | include snmp-server'
        output = self._send_command(command)
        for line in output.splitlines():
            fields = line.split()
            if 'snmp-server community' in line:
                name = fields[2]
                if 'community' not in snmp_dict.keys():
                    snmp_dict.update({'community': {}})
                snmp_dict['community'].update({name: {}})
                try:
                    snmp_dict['community'][name].update({'mode': fields[3].lower()})
                except IndexError:
                    snmp_dict['community'][name].update({'mode': u'N/A'})
                try:
                    snmp_dict['community'][name].update({'acl': fields[4]})
                except IndexError:
                    snmp_dict['community'][name].update({'acl': u'N/A'})
            elif 'snmp-server location' in line:
                snmp_dict['location'] = ' '.join(fields[2:])
            elif 'snmp-server contact' in line:
                snmp_dict['contact'] = ' '.join(fields[2:])
            elif 'snmp-server chassis-id' in line:
                snmp_dict['chassis_id'] = ' '.join(fields[2:])
        # If SNMP Chassis wasn't found; obtain using direct command
        if snmp_dict['chassis_id'] == 'unknown':
            command = 'show snmp chassis'
            snmp_chassis = self._send_command(command)
            snmp_dict['chassis_id'] = snmp_chassis
        return snmp_dict

    def ping(self, destination, source='', ttl=255, timeout=2, size=100, count=5):
        """
        Execute ping on the device and returns a dictionary with the result.

        Output dictionary has one of following keys:
            * success
            * error
        In case of success, inner dictionary will have the followin keys:
            * probes_sent (int)
            * packet_loss (int)
            * rtt_min (float)
            * rtt_max (float)
            * rtt_avg (float)
            * rtt_stddev (float)
            * results (list)
        'results' is a list of dictionaries with the following keys:
            * ip_address (str)
            * rtt (float)
        """
        ping_dict = {}
        command = 'ping {}'.format(destination)
        command += ' timeout {}'.format(timeout)
        command += ' size {}'.format(size)
        command += ' repeat {}'.format(count)
        if source != '':
            command += ' source {}'.format(source)

        output = self._send_command(command)
        if '%' in output:
            ping_dict['error'] = output
        elif 'Sending' in output:
            ping_dict['success'] = {
                                'probes_sent': 0,
                                'probes_sent': 0,
                                'packet_loss': 0,
                                'rtt_min': 0.0,
                                'rtt_max': 0.0,
                                'rtt_avg': 0.0,
                                'rtt_stddev': 0.0,
                                'results': []
            }

            for line in output.splitlines():
                fields = line.split()
                if 'Success rate is 0' in line:
                    sent_and_received = re.search(r'\((\d*)/(\d*)\)', fields[5])
                    probes_sent = int(sent_and_received.groups()[0])
                    probes_received = int(sent_and_received.groups()[1])
                    ping_dict['success']['probes_sent'] = probes_sent
                    ping_dict['success']['packet_loss'] = probes_sent - probes_received
                elif 'Success rate is' in line:
                    sent_and_received = re.search(r'\((\d*)/(\d*)\)', fields[5])
                    probes_sent = int(sent_and_received.groups()[0])
                    probes_received = int(sent_and_received.groups()[1])
                    min_avg_max = re.search(r'(\d*)/(\d*)/(\d*)', fields[9])
                    ping_dict['success']['probes_sent'] = probes_sent
                    ping_dict['success']['packet_loss'] = probes_sent - probes_received
                    ping_dict['success'].update({
                                    'rtt_min': float(min_avg_max.groups()[0]),
                                    'rtt_avg': float(min_avg_max.groups()[1]),
                                    'rtt_max': float(min_avg_max.groups()[2]),
                    })
                    results_array = []
                    for i in range(probes_received):
                        results_array.append({'ip_address': py23_compat.text_type(destination),
                                             'rtt': 0.0})
                    ping_dict['success'].update({'results': results_array})

        return ping_dict

    def traceroute(self, destination, source=C.TRACEROUTE_SOURCE,
                   ttl=C.TRACEROUTE_TTL, timeout=C.TRACEROUTE_TIMEOUT):
        """
        Executes traceroute on the device and returns a dictionary with the result.

        :param destination: Host or IP Address of the destination
        :param source (optional): Use a specific IP Address to execute the traceroute
        :param ttl (optional): Maimum number of hops -> int (0-255)
        :param timeout (optional): Number of seconds to wait for response -> int (1-3600)

        Output dictionary has one of the following keys:

            * success
            * error

        In case of success, the keys of the dictionary represent the hop ID, while values are
        dictionaries containing the probes results:
            * rtt (float)
            * ip_address (str)
            * host_name (str)
        """

        command = "traceroute {}".format(destination)
        if source:
            command += " source {}".format(source)
        if ttl:
            if isinstance(ttl, int) and 0 <= timeout <= 255:
                command += " ttl 0 {}".format(str(ttl))
        if timeout:
            # Timeout should be an integer between 1 and 3600
            if isinstance(timeout, int) and 1 <= timeout <= 3600:
                command += " timeout {}".format(str(timeout))

        # Calculation to leave enough time for traceroute to complete assumes send_command
        # delay of .2 seconds.
        max_loops = (5 * ttl * timeout) + 150
        if max_loops < 500:     # Make sure max_loops isn't set artificially low
            max_loops = 500
        output = self.device.send_command(command, max_loops=max_loops)

        # Prepare return dict
        traceroute_dict = dict()
        if re.search('Unrecognized host or address', output):
            traceroute_dict['error'] = 'unknown host %s' % destination
            return traceroute_dict
        else:
            traceroute_dict['success'] = dict()

        results = dict()
        # Find all hops
        hops = re.findall('\\n\s+[0-9]{1,3}\s', output)
        for hop in hops:
            # Search for hop in the output
            hop_match = re.search(hop, output)
            # Find the start index for hop
            start_index = hop_match.start()
            # If this is last hop
            if hops.index(hop) + 1 == len(hops):
                # Set the stop index for hop to len of output
                stop_index = len(output)
            # else, find the start index for next hop
            else:
                next_hop_match = re.search(hops[hops.index(hop) + 1], output)
                stop_index = next_hop_match.start()
                # Now you have the start and stop index for each hop
                # and you can parse the probes
            # Set the hop_variable, and remove spaces between msec for easier matching
            hop_string = output[start_index:stop_index].replace(' msec', 'msec')
            hop_list = hop_string.split()
            current_hop = int(hop_list.pop(0))
            # Prepare dictionary for each hop (assuming there are 3 probes in each hop)
            results[current_hop] = dict()
            results[current_hop]['probes'] = dict()
            results[current_hop]['probes'][1] = {'rtt': float(),
                                                 'ip_address': '',
                                                 'host_name': ''}
            results[current_hop]['probes'][2] = {'rtt': float(),
                                                 'ip_address': '',
                                                 'host_name': ''}
            results[current_hop]['probes'][3] = {'rtt': float(),
                                                 'ip_address': '',
                                                 'host_name': ''}
            current_probe = 1
            ip_address = ''
            host_name = ''
            while hop_list:
                current_element = hop_list.pop(0)
                # If current_element is * move index in dictionary to next probe
                if current_element == '*':
                    current_probe += 1
                # If current_element contains msec record the entry for probe
                elif 'msec' in current_element:
                    ip_address = py23_compat.text_type(ip_address)
                    host_name = py23_compat.text_type(host_name)
                    rtt = float(current_element.replace('msec', ''))
                    results[current_hop]['probes'][current_probe]['ip_address'] = ip_address
                    results[current_hop]['probes'][current_probe]['host_name'] = host_name
                    results[current_hop]['probes'][current_probe]['rtt'] = rtt
                    # After recording the entry move the index to next probe
                    current_probe += 1
                # If element contains '(' and ')', the output format is 'FQDN (IP_ADDRESS)'
                # Save the IP address
                elif '(' in current_element:
                    ip_address = current_element.replace('(', '').replace(')', '')
                # Save the probe's ip_address and host_name
                else:
                    host_name = current_element
                    ip_address = current_element

        traceroute_dict['success'] = results
        return traceroute_dict

    def get_config(self, retrieve='all'):
        """Implementation of get_config for IOS.

        Returns the startup or/and running configuration as dictionary.
        The keys of the dictionary represent the type of configuration
        (startup or running). The candidate is always empty string,
        since IOS does not support candidate configuration.
        """

        configs = {
            'startup': '',
            'running': '',
            'candidate': '',
        }

        if retrieve in ('startup', 'all'):
            command = 'show startup-config'
            output = self._send_command(command)
            configs['startup'] = output

        if retrieve in ('running', 'all'):
            command = 'show running-config'
            output = self._send_command(command)
            configs['running'] = output

        return configs
