'''NAPALM Cisco IOS Handler'''

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

import re
from datetime import datetime

from netmiko import ConnectHandler, FileTransfer
from napalm.base import NetworkDriver
from napalm.exceptions import ReplaceConfigException, MergeConfigException

# Easier to store these as constants
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS

class IOSDriver(NetworkDriver):
    '''NAPALM Cisco IOS Handler'''
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.candidate_cfg = optional_args.get('candidate_cfg', 'candidate_config.txt')
        self.merge_cfg = optional_args.get('merge_cfg', 'merge_config.txt')
        self.rollback_cfg = optional_args.get('rollback_cfg', 'rollback_config.txt')
        self.dest_file_system = optional_args.get('dest_file_system', 'flash:')
        self.global_delay_factor = optional_args.get('global_delay_factor', .5)
        self.port = optional_args.get('port', 22)
        self.auto_rollback_on_error = optional_args.get('auto_rollback_on_error', True)
        self.device = None
        self.config_replace = False

    def open(self):
        """Opens a connection to the device."""
        self.device = ConnectHandler(device_type='cisco_ios', ip=self.hostname, port=self.port,
                                     username=self.username, password=self.password,
                                     global_delay_factor=self.global_delay_factor, verbose=False)

    def close(self):
        """Closes the connection to the device."""
        self.device.disconnect()

    def load_replace_candidate(self, filename=None, config=None):
        '''
        SCP file to device filesystem, defaults to candidate_config

        Return None or raise exception
        '''
        self.config_replace = True
        if config:
            raise NotImplementedError
        if filename:
            (return_status, msg) = self.scp_file(source_file=filename,
                                                 dest_file=self.candidate_cfg,
                                                 file_system=self.dest_file_system)
            if not return_status:
                if msg == '':
                    msg = "SCP transfer to remote device failed"
                raise ReplaceConfigException(msg)

    def load_merge_candidate(self, filename=None, config=None):
        '''
        SCP file to remote device

        Merge configuration in: copy <file> running-config
        '''
        self.config_replace = False
        if config:
            raise NotImplementedError
        if filename:
            (return_status, msg) = self.scp_file(source_file=filename, dest_file=self.merge_cfg,
                                                 file_system=self.dest_file_system)
            if not return_status:
                if msg == '':
                    msg = "SCP transfer to remote device failed"
                raise MergeConfigException(msg)

    @staticmethod
    def normalize_compare_config(diff):
        '''Filter out strings that should not show up in the diff'''
        ignore_strings = [
            'Contextual Config Diffs',
            'No changes were found',
            'file prompt quiet',
            'ntp clock-period'
        ]

        new_list = []
        for line in diff.splitlines():
            for ignore in ignore_strings:
                if ignore in line:
                    break
            else:   # nobreak
                new_list.append(line)
        return "\n".join(new_list)

    def compare_config(self, base_file='running-config', new_file=None,
                       base_file_system='system:', new_file_system=None):
        '''
        show archive config differences <base_file> <new_file>

        Default operation is to compare system:running-config to self.candidate_cfg
        '''
        # Set defaults if not passed as arguments
        if new_file is None:
            new_file = self.candidate_cfg
        if new_file_system is None:
            new_file_system = self.dest_file_system
        base_file_full = self.gen_full_path(filename=base_file, file_system=base_file_system)
        new_file_full = self.gen_full_path(filename=new_file, file_system=new_file_system)

        cmd = 'show archive config differences {} {}'.format(base_file_full, new_file_full)
        diff = self.device.send_command_expect(cmd)
        diff = self.normalize_compare_config(diff)
        return diff.strip()

    def commit_config(self, filename=None):
        '''
        If replacement operation, perform 'configure replace' for the entire config.

        If merge operation, perform copy <file> running-config.
        '''
        # Always generate a rollback config on commit
        self._gen_rollback_cfg()

        # Replace operation
        if self.config_replace:
            if filename is None:
                filename = self.candidate_cfg
            cfg_file = self.gen_full_path(filename)
            if not self._check_file_exists(cfg_file):
                raise ReplaceConfigException("Candidate config file does not exist")
            if self.auto_rollback_on_error:
                cmd = 'configure replace {} force revert trigger error'.format(cfg_file)
            else:
                cmd = 'configure replace {} force'.format(cfg_file)
            output = self.device.send_command_expect(cmd)
            if ('Failed to apply command' in output) or \
                ('original configuration has been successfully restored' in output):
                raise ReplaceConfigException("Candidate config could not be applied")
        # Merge operation
        else:
            if filename is None:
                filename = self.merge_cfg
            cfg_file = self.gen_full_path(filename)
            if not self._check_file_exists(cfg_file):
                raise MergeConfigException("Merge source config file does not exist")
            cmd = 'copy {} running-config'.format(cfg_file)
            self._disable_confirm()
            output = self.device.send_command_expect(cmd)
            self._enable_confirm()
            if 'Invalid input detected' in output:
                self.rollback()
                merge_error = "Configuration merge failed; automatic rollback attempted"
                raise MergeConfigException(merge_error)

    def discard_config(self):
        '''Set candidate_cfg to current running-config. Erase the merge_cfg file'''
        discard_candidate = 'copy running-config {}'.format(self.gen_full_path(self.candidate_cfg))
        discard_merge = 'copy null: {}'.format(self.gen_full_path(self.merge_cfg))
        self._disable_confirm()
        self.device.send_command_expect(discard_candidate)
        self.device.send_command_expect(discard_merge)
        self._enable_confirm()

    def rollback(self, filename=None):
        '''Rollback configuration to filename or to self.rollback_cfg file'''
        if filename is None:
            filename = self.rollback_cfg
        cfg_file = self.gen_full_path(filename)
        if not self._check_file_exists(cfg_file):
            raise ReplaceConfigException("Rollback config file does not exist")
        cmd = 'configure replace {} force'.format(cfg_file)
        self.device.send_command_expect(cmd)

    def scp_file(self, source_file, dest_file, file_system):
        '''
        SCP file to remote device

        Return (status, msg)
        status = boolean
        msg = details on what happened
        '''
        # Will automaticall enable SCP on remote device
        enable_scp = True
        debug = False

        with FileTransfer(self.device, source_file=source_file,
                          dest_file=dest_file, file_system=file_system) as scp_transfer:

            if debug:
                print("check1: {}".format(datetime.now()))
            # Check if file already exists and has correct MD5
            if scp_transfer.check_file_exists() and scp_transfer.compare_md5():
                msg = "File already exists and has correct MD5: no SCP needed"
                return (True, msg)
            if not scp_transfer.verify_space_available():
                msg = "Insufficient space available on remote device"
                return (False, msg)

            if debug:
                print("check2: {}".format(datetime.now()))
            if enable_scp:
                scp_transfer.enable_scp()

            if debug:
                print("check3: {}".format(datetime.now()))
            # Transfer file
            scp_transfer.transfer_file()
            if debug:
                print("check4: {}".format(datetime.now()))

            # Compares MD5 between local-remote files
            if scp_transfer.verify_file():
                msg = "File successfully transferred to remote device"
                return (True, msg)
            else:
                msg = "File transfer to remote device failed"
                return (False, msg)
            if debug:
                print("check5: {}".format(datetime.now()))

            return (False, '')

    def _enable_confirm(self):
        '''Enable IOS confirmations on file operations (global config command)'''
        cmd = 'no file prompt quiet'
        self.device.send_config_set([cmd])

    def _disable_confirm(self):
        '''Disable IOS confirmations on file operations (global config command)'''
        cmd = 'file prompt quiet'
        self.device.send_config_set([cmd])

    def gen_full_path(self, filename, file_system=None):
        '''Generate full file path on remote device'''
        if file_system is None:
            return '{}/{}'.format(self.dest_file_system, filename)
        else:
            if ":" not in file_system:
                raise ValueError("Invalid file_system specified: {}".format(file_system))
            return '{}/{}'.format(file_system, filename)

    def _gen_rollback_cfg(self):
        '''
        Save a configuration that can be used for rollback
        '''
        cfg_file = self.gen_full_path(self.rollback_cfg)
        cmd = 'copy running-config {}'.format(cfg_file)
        self._disable_confirm()
        self.device.send_command_expect(cmd)
        self._enable_confirm()

    def _check_file_exists(self, cfg_file):
        '''
        Check that the file exists on remote device using full path

        cfg_file is full path i.e. flash:/file_name

        For example
        # dir flash:/candidate_config.txt
        Directory of flash:/candidate_config.txt

        33  -rw-        5592  Dec 18 2015 10:50:22 -08:00  candidate_config.txt

        return boolean
        '''
        cmd = 'dir {}'.format(cfg_file)
        success_pattern = 'Directory of {}'.format(cfg_file)
        output = self.device.send_command_expect(cmd)
        if 'Error opening' in output:
            return False
        elif success_pattern in output:
            return True
        return False

    def get_lldp_neighbors(self):
        '''
        Output command format:
        Device ID           Local Intf     Hold-time  Capability      Port ID
        twb-sf-hpsw1        Fa4            120        B               17

        Total entries displayed: 1

        return data structure is a dictionary, key is local_port
        {u'Fa4': [{'hostname': u'twb-sf-hpsw1', 'port': u'17'}]}

        value is a list where each entry in the list is a dict
        '''
        lldp = {}

        command = 'show lldp neighbors | begin Device ID'
        output = self.device.send_command(command)
        for line in output.splitlines():
            line = line.strip()
            if 'Device ID' in line or 'entries' in line or line == '':
                continue
            device_id, local_port, _, _, remote_port = line.split()
            lldp.setdefault(local_port, [])
            lldp[local_port].append({
                'hostname': device_id,
                'port': remote_port,
            })
        return lldp

    @staticmethod
    def parse_uptime(uptime_str):
        '''
        Extract the uptime string from the given Cisco IOS Device.

        Return the uptime in seconds as an integer
        '''
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
        """This function returns a set of facts from the devices."""
        # creating the parsing regex.
        model_regex = r".*Cisco\s(?P<model>\d+).*"

        # default values.
        vendor = u'Cisco'
        uptime = -1
        serial_number, fqdn, os_version, hostname = (u'Unknown', u'Unknown',
                                                     u'Unknown', u'Unknown')

        # obtain output from device
        show_ver = self.device.send_command('show version')
        show_hosts = self.device.send_command('show hosts')
        show_ip_int_br = self.device.send_command('show ip int brief')

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
                _, os_version = line.split("Cisco IOS Software, ")
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
            match_model = re.match(model_regex, show_ver, re.DOTALL)
            group_model = match_model.groupdict()
            model = group_model["model"]
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
            'os_version': os_version,
            'serial_number': serial_number,
            'model': model,
            'hostname': hostname,
            'fqdn': fqdn,
            'interface_list': interface_list
        }

    def get_interfaces(self):
        '''
        Get interface details

        last_flapped is not implemented
        '''
        interface_list = {}

        # default values.
        last_flapped = -1.0

        # creating the parsing regex.
        mac_regex = r".*,\saddress\sis\s(?P<mac_address>\S+).*"
        speed_regex = r".*BW\s(?P<speed>\d+)\s(?P<speed_format>\S+).*"

        command = 'show interfaces description'
        output = self.device.send_command(command)
        for line in output.splitlines():
            if 'Interface' in line and 'Status' in line:
                continue
            fields = line.split()
            if len(fields) == 3:
                interface, status, protocol = fields
                description = u''
            elif fields > 3:
                interface, status, protocol = fields[:3]
                description = u" ".join(fields[3:])
            else:
                raise ValueError("Unexpected response from the router")

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
                'description': description,
                'last_flapped': last_flapped,
            }

        for interface in interface_list:
            show_command = "show interface {0}".format(interface)
            interface_output = self.device.send_command(show_command)
            try:
                # mac_address filter.
                match_mac = re.match(mac_regex, interface_output, re.DOTALL)
                group_mac = match_mac.groupdict()
                mac_address = group_mac["mac_address"]
                interface_list[interface]['mac_address'] = mac_address
            except AttributeError:
                interface_list[interface]['mac_address'] = u'N/A'
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
            except ValueError:
                interface_list[interface]['speed'] = -1

        return interface_list

    @staticmethod
    def bgp_time_conversion(bgp_uptime):
        '''
        Convert string time to seconds

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
        '''
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
            form1 = r'(\d+)d(\d+)h'     # 1d17h
            form2 = r'(\d+)w(\d+)d'     # 8w5d
            form3 = r'(\d+)y(\d+)w'     # 1y28w
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
        '''
        BGP neighbor information

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
        '''
        cmd_bgp_summary = 'show ip bgp summary'
        bgp_neighbor_data = {}
        bgp_neighbor_data['global'] = {}

        output = self.device.send_command(cmd_bgp_summary).strip()
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
        bgp_neighbor_data['global']['router_id'] = router_id
        bgp_neighbor_data['global']['peers'] = {}

        cmd_neighbor_table = 'show ip bgp summary | begin Neighbor'
        output = self.device.send_command(cmd_neighbor_table).strip()
        for line in output.splitlines():
            line = line.strip()
            if 'Neighbor' in line or line == '':
                continue
            fields = line.split()[:10]
            peer_id, bgp_version, remote_as, msg_rcvd, msg_sent, table_version, in_queue, \
            out_queue, up_time, state_prefix = fields

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
            remote_rid_out = self.device.send_command(cmd_remote_rid).strip()
            remote_rid = remote_rid_out.split()[-1]

            bgp_neighbor_data['global']['peers'].setdefault(peer_id, {})
            peer_dict = {}
            peer_dict['uptime'] = self.bgp_time_conversion(up_time)
            peer_dict['remote_as'] = int(remote_as)
            peer_dict['description'] = u''
            peer_dict['local_as'] = local_as
            peer_dict['is_enabled'] = is_enabled
            peer_dict['is_up'] = is_up
            peer_dict['remote_id'] = remote_rid

            cmd_current_prefixes = 'show ip bgp neighbors {} | inc Prefixes Current'.format(peer_id)
            # output: Prefixes Current:               0          0
            current_prefixes_out = self.device.send_command(cmd_current_prefixes).strip()
            pattern = r'Prefixes Current:\s+(\d+)\s+(\d+).*'  # Prefixes Current:    0     0
            match = re.search(pattern, current_prefixes_out)
            if match:
                sent_prefixes = int(match.group(1))
                accepted_prefixes = int(match.group(1))
            else:
                sent_prefixes = accepted_prefixes = -1

            cmd_filtered_prefix = 'show ip bgp neighbors {} | section Local Policy'.format(peer_id)
            # output:
            # Local Policy Denied Prefixes:    --------    -------
            # prefix-list                           0          2
            # Total:                                0          2
            filtered_prefixes_out = self.device.send_command(cmd_filtered_prefix).strip()
            accepted_prefixes = int(accepted_prefixes)
            sent_prefixes = int(sent_prefixes)
            pattern = r'Total:\s+\d+\s+(\d+).*'    # Total:     0          2
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
        '''
        Return
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
        '''
        counters = {}
        command = 'show interfaces'
        output = self.device.send_command(command)
        output = output.strip()

        # Break output into per-interface sections
        interface_strings = re.split(r'.* line protocol is .*', output, re.M)
        header_strings = re.findall(r'.* line protocol is .*', output, re.M)

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
                    match = re.search(r"Received (\d+) broadcasts.*(\d+).*multicasts", line)
                    counters[interface]['rx_broadcast_packets'] = int(match.group(1))
                    counters[interface]['rx_multicast_packets'] = int(match.group(2))
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
        '''
        power, fan, temperature are currently not implemented
        cpu is using 1-minute average
        cpu hard-coded to cpu0 (i.e. only a single CPU)
        '''
        environment = {}
        cpu_cmd = 'show proc cpu'
        mem_cmd = 'show memory statistics'

        output = self.device.send_command(cpu_cmd)
        output = output.strip()
        for line in output.splitlines():
            if 'CPU utilization' in line:
                # CPU utilization for five seconds: 2%/0%; one minute: 2%; five minutes: 1%
                cpu_regex = r'^.*one minute: (\d+)%; five.*$'
                match = re.search(cpu_regex, line)
                break
        environment.setdefault('cpu', {})
        environment['cpu'][0] = {}
        environment['cpu'][0]['%usage'] = float(match.group(1))

        output = self.device.send_command(mem_cmd)
        output = output.strip()
        for line in output.splitlines():
            if 'Processor' in line:
                _, _, _, proc_used_mem, proc_free_mem = line.split()[:5]
            elif 'I/O' in line:
                _, _, _, io_used_mem, io_free_mem = line.split()[:5]
        used_mem = int(proc_used_mem) + int(io_used_mem)
        free_mem = int(proc_free_mem) + int(io_free_mem)
        environment.setdefault('memory', {})
        environment['memory']['used_ram'] = used_mem
        environment['memory']['available_ram'] = free_mem

        # Initialize 'power', 'fan', and 'temperature' to default values (not implemented)
        environment.setdefault('power', {})
        environment['power']['invalid'] = {
            'status': True,
            'output': -1.0,
            'capacity': -1.0,
        }
        environment.setdefault('fans', {})
        environment['fans']['invalid'] = {
            'status': True,
        }
        environment.setdefault('temperature', {})
        environment['temperature']['invalid'] = {
            'is_alert': False,
            'is_critical': False,
            'temperature': -1.0,
        }
        return environment
