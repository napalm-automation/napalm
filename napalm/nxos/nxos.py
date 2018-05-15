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
import time
import tempfile
from datetime import datetime
from requests.exceptions import ConnectionError

# import third party lib
from netaddr import IPAddress
from netaddr.core import AddrFormatError

from pynxos.device import Device as NXOSDevice
from pynxos.features.file_copy import FileTransferError as NXOSFileTransferError
from pynxos.features.file_copy import FileCopy
from pynxos.errors import CLIError

# import NAPALM Base
import napalm.base.helpers
from napalm.base import NetworkDriver
from napalm.base.utils import py23_compat
from napalm.base.exceptions import ConnectionException
from napalm.base.exceptions import MergeConfigException
from napalm.base.exceptions import CommandErrorException
from napalm.base.exceptions import ReplaceConfigException
import napalm.base.constants as c


class NXOSDriverBase(NetworkDriver):
    """Common code shared between nx-api and nxos_ssh."""

    def commit_config(self, message=""):
        if message:
            raise NotImplementedError('Commit message not implemented for this platform')
        if self.loaded:
            # Create checkpoint from current running-config
            self.backup_file = 'config_' + str(datetime.now()).replace(' ', '_')
            self._save_to_checkpoint(self.backup_file)

            if self.replace:
                # Replace operation
                self._load_cfg_from_checkpoint()
            else:
                # Merge operation
                self._commit_merge()

            self._copy_run_start()
            self.changed = True
            self.loaded = False
        else:
            raise ReplaceConfigException('No config loaded.')

    def ping(self,
             destination,
             source=c.PING_SOURCE,
             ttl=c.PING_TTL,
             timeout=c.PING_TIMEOUT,
             size=c.PING_SIZE,
             count=c.PING_COUNT,
             vrf=c.PING_VRF):
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

        version = ''
        try:
            version = '6' if IPAddress(destination).version == 6 else ''
        except AddrFormatError:
            # Allow use of DNS names
            pass

        command = 'ping{version} {destination}'.format(
            version=version,
            destination=destination)
        command += ' timeout {}'.format(timeout)
        command += ' packet-size {}'.format(size)
        command += ' count {}'.format(count)
        if source != '':
            command += ' source {}'.format(source)

        if vrf != '':
            command += ' vrf {}'.format(vrf)
        output = self._send_command(command)

        if 'connect:' in output:
            ping_dict['error'] = output
        elif 'PING' in output:
            ping_dict['success'] = {
                'probes_sent': 0,
                'packet_loss': 0,
                'rtt_min': 0.0,
                'rtt_max': 0.0,
                'rtt_avg': 0.0,
                'rtt_stddev': 0.0,
                'results': []
            }
            results_array = []
            for line in output.splitlines():
                fields = line.split()
                if 'icmp' in line:
                    if 'Unreachable' in line:
                        if "(" in fields[2]:
                            results_array.append(
                                {
                                    'ip_address': py23_compat.text_type(fields[2][1:-1]),
                                    'rtt': 0.0,
                                }
                            )
                        else:
                            results_array.append({'ip_address': py23_compat.text_type(fields[1]),
                                                  'rtt': 0.0})
                    elif 'truncated' in line:
                        if "(" in fields[4]:
                            results_array.append(
                                {
                                    'ip_address': py23_compat.text_type(fields[4][1:-2]),
                                    'rtt': 0.0,
                                }
                            )
                        else:
                            results_array.append(
                                {
                                    'ip_address': py23_compat.text_type(fields[3][:-1]),
                                    'rtt': 0.0,
                                }
                            )
                    elif fields[1] == 'bytes':
                        if version == '6':
                            m = fields[5][5:]
                        else:
                            m = fields[6][5:]
                        results_array.append({'ip_address': py23_compat.text_type(fields[3][:-1]),
                                              'rtt': float(m)})
                elif 'packets transmitted' in line:
                    ping_dict['success']['probes_sent'] = int(fields[0])
                    ping_dict['success']['packet_loss'] = int(fields[0]) - int(fields[3])
                elif 'min/avg/max' in line:
                    m = fields[3].split('/')
                    ping_dict['success'].update({
                        'rtt_min': float(m[0]),
                        'rtt_avg': float(m[1]),
                        'rtt_max': float(m[2]),
                    })
            ping_dict['success'].update({'results': results_array})
        return ping_dict


class NXOSDriver(NXOSDriverBase):
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
        self.replace_file = None
        self.merge_candidate = ''

        # nxos_protocol is there for backwards compatibility, transport is the preferred method
        self.transport = optional_args.get('transport', optional_args.get('nxos_protocol', 'https'))
        if self.transport == 'https':
            self.port = optional_args.get('port', 443)
        elif self.transport == 'http':
            self.port = optional_args.get('port', 80)

    def open(self):
        try:
            self.device = NXOSDevice(self.hostname,
                                     self.username,
                                     self.password,
                                     timeout=self.timeout,
                                     port=self.port,
                                     transport=self.transport)
            self.device.show('show hostname')
            self.up = True
        except (CLIError, ValueError):
            # unable to open connection
            raise ConnectionException('Cannot connect to {}'.format(self.hostname))

    def close(self):
        if self.changed:
            self._delete_file(self.backup_file)
        self.device = None

    def _send_command(self, command):
        """Wrapper for CLI method in NX-API.

        Allows more code sharing between NX-API and SSH.
        """
        return self.cli([command]).get(command)

    @staticmethod
    def _compute_timestamp(stupid_cisco_output):
        """
        Some fields such `uptime` are returned as: 23week(s) 3day(s)
        This method will determine the epoch of the event.
        e.g.: 23week(s) 3day(s) -> 1462248287
        """
        if not stupid_cisco_output or stupid_cisco_output == 'never':
            return -1.0

        if '(s)' in stupid_cisco_output:
            pass
        elif ':' in stupid_cisco_output:
            stupid_cisco_output = stupid_cisco_output.replace(':', 'hour(s) ', 1)
            stupid_cisco_output = stupid_cisco_output.replace(':', 'minute(s) ', 1)
            stupid_cisco_output += 'second(s)'
        else:
            stupid_cisco_output = stupid_cisco_output.replace('d', 'day(s) ')
            stupid_cisco_output = stupid_cisco_output.replace('h', 'hour(s)')

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
                'weight': 24 * 3600
            },
            'week(s)': {
                'weight': 7 * 24 * 3600
            },
            'year(s)': {
                'weight': 365.25 * 24 * 3600
            }
        }

        things_keys = things.keys()
        for part in stupid_cisco_output.split():
            for key in things_keys:
                if key in part:
                    things[key]['count'] = napalm.base.helpers.convert(
                        int, part.replace(key, ''), 0)

        delta = sum([det.get('count', 0) * det.get('weight') for det in things.values()])
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

    @staticmethod
    def fix_checkpoint_string(string, filename):
        # used to generate checkpoint-like files
        pattern = '''!Command: Checkpoint cmd vdc 1'''

        if '!Command' in string:
            return re.sub('!Command.*', pattern.format(filename), string)
        else:
            return "{0}\n{1}".format(pattern.format(filename), string)

    def _get_reply_table(self, result, table_name, row_name):
        return self._get_table_rows(result, table_name, row_name)

    def _get_command_table(self, command, table_name, row_name):
        json_output = self.device.show(command)
        return self._get_reply_table(json_output, table_name, row_name)

    def is_alive(self):
        if self.device:
            return {'is_alive': True}
        else:
            return {'is_alive': False}

    def load_replace_candidate(self, filename=None, config=None):
        self.replace = True
        self.loaded = True

        if not filename and not config:
            raise ReplaceConfigException('filename or config param must be provided.')

        if filename is None:
            temp_file = tempfile.NamedTemporaryFile()
            temp_file.write(config)
            temp_file.flush()
            cfg_filename = temp_file.name
        else:
            cfg_filename = filename

        self.replace_file = cfg_filename

        with open(self.replace_file, 'r') as f:
            file_content = f.read()

        file_content = self.fix_checkpoint_string(file_content, self.replace_file)
        temp_file = tempfile.NamedTemporaryFile()
        temp_file.write(file_content.encode())
        temp_file.flush()
        self.replace_file = cfg_filename

        self._send_file(temp_file.name, cfg_filename)

    def load_merge_candidate(self, filename=None, config=None):
        self.replace = False
        self.loaded = True

        if not filename and not config:
            raise MergeConfigException('filename or config param must be provided.')

        self.merge_candidate += '\n'  # insert one extra line
        if filename is not None:
            with open(filename, "r") as f:
                self.merge_candidate += f.read()
        else:
            self.merge_candidate += config

    def _send_file(self, filename, dest):
        self.fc = FileCopy(self.device, filename, dst=dest.split('/')[-1])
        try:
            if not self.fc.remote_file_exists():
                self.fc.send()
            elif not self.fc.file_already_exists():
                commands = ['terminal dont-ask',
                            'delete {0}'.format(self.fc.dst)]
                self.device.config_list(commands)
                self.fc.send()
        except NXOSFileTransferError as fte:
            raise ReplaceConfigException(py23_compat.text_type(fte))

    def _create_sot_file(self):
        """Create Source of Truth file to compare."""
        commands = ['terminal dont-ask', 'checkpoint file sot_file']
        self.device.config_list(commands)

    def _get_diff(self, cp_file):
        """Get a diff between running config and a proposed file."""
        diff = []
        self._create_sot_file()
        diff_out = self.device.show(
            'show diff rollback-patch file {0} file {1}'.format(
                'sot_file', self.replace_file.split('/')[-1]), raw_text=True)
        try:
            diff_out = diff_out.split(
                'Generating Rollback Patch')[1].replace(
                'Rollback Patch is Empty', '').strip()
            for line in diff_out.splitlines():
                if line:
                    if line[0].strip() != '!':
                        diff.append(line.rstrip(' '))
        except (AttributeError, KeyError):
            raise ReplaceConfigException(
                'Could not calculate diff. It\'s possible the given file doesn\'t exist.')
        return '\n'.join(diff)

    def _get_merge_diff(self):
        diff = []
        running_config = self.get_config(retrieve='running')['running']
        running_lines = running_config.splitlines()
        for line in self.merge_candidate.splitlines():
            if line not in running_lines and line:
                if line[0].strip() != '!':
                    diff.append(line)
        return '\n'.join(diff)
        # the merge diff is not necessarily what needs to be loaded
        # for example under NTP, as the `ntp commit` command might be
        # alread configured, it is mandatory to be sent
        # otherwise it won't take the new configuration - see #59
        # https://github.com/napalm-automation/napalm-nxos/issues/59
        # therefore this method will return the real diff
        # but the merge_candidate will remain unchanged
        # previously: self.merge_candidate = '\n'.join(diff)

    def compare_config(self):
        if self.loaded:
            if not self.replace:
                return self._get_merge_diff()
                # return self.merge_candidate
            diff = self._get_diff(self.fc.dst)
            return diff
        return ''

    def _copy_run_start(self, filename='startup-config'):
        results = self.device.save(filename=filename)
        if not results:
            msg = 'Unable to save running-config to {}!'.format(filename)
            raise CommandErrorException(msg)

    def _commit_merge(self):
        try:
            commands = [command for command in self.merge_candidate.splitlines() if command]
            self.device.config_list(commands)
        except Exception as e:
            raise MergeConfigException(str(e))
        # clear the merge buffer
        self.merge_candidate = ''

    def _save_to_checkpoint(self, filename):
        """Save the current running config to the given file."""
        command = 'checkpoint file {}'.format(filename)
        self.device.show(command, raw_text=True)

    def _disable_confirmation(self):
        self.device.config('terminal dont-ask')

    def _load_cfg_from_checkpoint(self):
        cmd = 'rollback running file {0}'.format(self.replace_file.split('/')[-1])
        self._disable_confirmation()
        try:
            rollback_result = self.device.config(cmd)
        except ConnectionError:
            # requests will raise an error with verbose warning output (don't fail on this).
            return
        if 'Rollback failed.' in rollback_result['msg'] or 'ERROR' in rollback_result:
            raise ReplaceConfigException(rollback_result['msg'])

    def _delete_file(self, filename):
        commands = ['terminal dont-ask',
                    'delete {}'.format(filename),
                    'no terminal dont-ask']
        self.device.show_list(commands, raw_text=True)

    def discard_config(self):
        if self.loaded:
            self.merge_candidate = ''  # clear the buffer
        if self.loaded and self.replace:
            try:
                self._delete_file(self.fc.dst)
            except CLIError:
                pass
        self.loaded = False

    def rollback(self):
        if self.changed:
            self.device.rollback(self.backup_file)
            self._copy_run_start()
            self.changed = False

    def get_facts(self):
        pynxos_facts = self.device.facts
        final_facts = {key: value for key, value in pynxos_facts.items() if
                       key not in ['interfaces', 'uptime_string', 'vlans']}

        if pynxos_facts['interfaces']:
            final_facts['interface_list'] = pynxos_facts['interfaces']
        else:
            final_facts['interface_list'] = self.get_interfaces().keys()

        final_facts['vendor'] = 'Cisco'

        hostname_cmd = 'show hostname'
        hostname = self.device.show(hostname_cmd).get('hostname')
        if hostname:
            final_facts['fqdn'] = hostname

        return final_facts

    def get_interfaces(self):
        interfaces = {}
        iface_cmd = 'show interface'
        interfaces_out = self.device.show(iface_cmd)
        interfaces_body = interfaces_out['TABLE_interface']['ROW_interface']

        for interface_details in interfaces_body:
            interface_name = interface_details.get('interface')
            # Earlier version of Nexus returned a list for 'eth_bw' (observed on 7.1(0)N1(1a))
            interface_speed = interface_details.get('eth_bw', 0)
            if isinstance(interface_speed, list):
                interface_speed = interface_speed[0]
            interface_speed = int(interface_speed / 1000)
            if 'admin_state' in interface_details:
                is_up = interface_details.get('admin_state', '') == 'up'
            else:
                is_up = interface_details.get('state', '') == 'up'
            interfaces[interface_name] = {
                'is_up': is_up,
                'is_enabled': (interface_details.get('state') == 'up'),
                'description': py23_compat.text_type(interface_details.get('desc', '').strip('"')),
                'last_flapped': self._compute_timestamp(
                    interface_details.get('eth_link_flapped', '')),
                'speed': interface_speed,
                'mac_address': napalm.base.helpers.convert(
                    napalm.base.helpers.mac, interface_details.get('eth_hw_addr')),
            }
        return interfaces

    def get_lldp_neighbors(self):
        results = {}
        try:
            command = 'show lldp neighbors'
            lldp_raw_output = self.cli([command]).get(command, '')
            lldp_neighbors = napalm.base.helpers.textfsm_extractor(
                self, 'lldp_neighbors', lldp_raw_output)
        except CLIError:
            lldp_neighbors = []

        for neighbor in lldp_neighbors:
            local_iface = neighbor.get('local_interface')
            if neighbor.get(local_iface) is None:
                if local_iface not in results:
                    results[local_iface] = []

            neighbor_dict = {'hostname': py23_compat.text_type(neighbor.get('neighbor')),
                             'port': py23_compat.text_type(neighbor.get('neighbor_interface'))}

            results[local_iface].append(neighbor_dict)
        return results

    def get_bgp_neighbors(self):
        results = {}
        bgp_state_dict = {
            'Idle': {'is_up': False, 'is_enabled': True},
            'Active': {'is_up': False, 'is_enabled': True},
            'Open': {'is_up': False, 'is_enabled': True},
            'Established': {'is_up': True, 'is_enabled': True},
            'Closing': {'is_up': True, 'is_enabled': True},
            'Shutdown': {'is_up': False, 'is_enabled': False},
        }

        try:
            cmd = 'show bgp sessions vrf all'
            vrf_list = self._get_command_table(cmd, 'TABLE_vrf', 'ROW_vrf')
        except CLIError:
            vrf_list = []

        for vrf_dict in vrf_list:
            result_vrf_dict = {
                'router_id': py23_compat.text_type(vrf_dict['router-id']),
                'peers': {}
            }
            neighbors_list = vrf_dict.get('TABLE_neighbor', {}).get('ROW_neighbor', [])

            if isinstance(neighbors_list, dict):
                neighbors_list = [neighbors_list]

            for neighbor_dict in neighbors_list:
                neighborid = napalm.base.helpers.ip(neighbor_dict['neighbor-id'])
                remoteas = napalm.base.helpers.as_number(neighbor_dict['remoteas'])
                state = py23_compat.text_type(neighbor_dict['state'])

                bgp_state = bgp_state_dict[state]

                result_peer_dict = {
                    'local_as': int(vrf_dict['local-as']),
                    'remote_as': remoteas,
                    'remote_id': neighborid,
                    'is_enabled': bgp_state['is_enabled'],
                    'uptime': -1,
                    'description': '',
                    'is_up': bgp_state['is_up'],
                    'address_family': {
                        'ipv4': {
                            'sent_prefixes': -1,
                            'accepted_prefixes': -1,
                            'received_prefixes': -1
                        }
                    }
                }
                result_vrf_dict['peers'][neighborid] = result_peer_dict

            vrf_name = vrf_dict['vrf-name-out']
            if vrf_name == 'default':
                vrf_name = 'global'
            results[vrf_name] = result_vrf_dict
        return results

    def _set_checkpoint(self, filename):
        commands = ['terminal dont-ask', 'checkpoint file {0}'.format(filename)]
        self.device.config_list(commands)

    def _get_checkpoint_file(self):
        filename = 'temp_cp_file_from_napalm'
        self._set_checkpoint(filename)
        cp_out = self.device.show('show file {0}'.format(filename), raw_text=True)
        self._delete_file(filename)
        return cp_out

    def get_lldp_neighbors_detail(self, interface=''):
        lldp_neighbors = {}
        filter = ''
        if interface:
            filter = 'interface {name} '.format(name=interface)

        command = 'show lldp neighbors {filter}detail'.format(filter=filter)
        # seems that some old devices may not return JSON output...

        try:
            lldp_neighbors_table_str = self.cli([command]).get(command)
            # thus we need to take the raw text output
            lldp_neighbors_list = lldp_neighbors_table_str.splitlines()
        except CLIError:
            lldp_neighbors_list = []

        if not lldp_neighbors_list:
            return lldp_neighbors  # empty dict

        CHASSIS_REGEX = r'^(Chassis id:)\s+([a-z0-9\.]+)$'
        PORT_REGEX = r'^(Port id:)\s+([0-9]+)$'
        LOCAL_PORT_ID_REGEX = r'^(Local Port id:)\s+(.*)$'
        PORT_DESCR_REGEX = r'^(Port Description:)\s+(.*)$'
        SYSTEM_NAME_REGEX = r'^(System Name:)\s+(.*)$'
        SYSTEM_DESCR_REGEX = r'^(System Description:)\s+(.*)$'
        SYST_CAPAB_REEGX = r'^(System Capabilities:)\s+(.*)$'
        ENABL_CAPAB_REGEX = r'^(Enabled Capabilities:)\s+(.*)$'
        VLAN_ID_REGEX = r'^(Vlan ID:)\s+(.*)$'

        lldp_neighbor = {}
        interface_name = None

        for line in lldp_neighbors_list:
            chassis_rgx = re.search(CHASSIS_REGEX, line, re.I)
            if chassis_rgx:
                lldp_neighbor = {
                    'remote_chassis_id': napalm.base.helpers.mac(chassis_rgx.groups()[1])
                }
                continue
            lldp_neighbor['parent_interface'] = ''
            port_rgx = re.search(PORT_REGEX, line, re.I)
            if port_rgx:
                lldp_neighbor['parent_interface'] = py23_compat.text_type(port_rgx.groups()[1])
                continue
            local_port_rgx = re.search(LOCAL_PORT_ID_REGEX, line, re.I)
            if local_port_rgx:
                interface_name = local_port_rgx.groups()[1]
                continue
            port_descr_rgx = re.search(PORT_DESCR_REGEX, line, re.I)
            if port_descr_rgx:
                lldp_neighbor['remote_port'] = py23_compat.text_type(port_descr_rgx.groups()[1])
                lldp_neighbor['remote_port_description'] = py23_compat.text_type(
                    port_descr_rgx.groups()[1])
                continue
            syst_name_rgx = re.search(SYSTEM_NAME_REGEX, line, re.I)
            if syst_name_rgx:
                lldp_neighbor['remote_system_name'] = py23_compat.text_type(
                    syst_name_rgx.groups()[1])
                continue
            syst_descr_rgx = re.search(SYSTEM_DESCR_REGEX, line, re.I)
            if syst_descr_rgx:
                lldp_neighbor['remote_system_description'] = py23_compat.text_type(
                    syst_descr_rgx.groups()[1])
                continue
            syst_capab_rgx = re.search(SYST_CAPAB_REEGX, line, re.I)
            if syst_capab_rgx:
                lldp_neighbor['remote_system_capab'] = py23_compat.text_type(
                    syst_capab_rgx.groups()[1])
                continue
            syst_enabled_rgx = re.search(ENABL_CAPAB_REGEX, line, re.I)
            if syst_enabled_rgx:
                lldp_neighbor['remote_system_enable_capab'] = py23_compat.text_type(
                    syst_enabled_rgx.groups()[1])
                continue
            vlan_rgx = re.search(VLAN_ID_REGEX, line, re.I)
            if vlan_rgx:
                # at the end of the loop
                if interface_name not in lldp_neighbors.keys():
                    lldp_neighbors[interface_name] = []
                lldp_neighbors[interface_name].append(lldp_neighbor)
        return lldp_neighbors

    def cli(self, commands):
        cli_output = {}
        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            command_output = self.device.show(command, raw_text=True)
            cli_output[py23_compat.text_type(command)] = command_output
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
            if age == '-':
                age_sec = -1.0
            elif ':' not in age:
                # Cisco sometimes returns a sub second arp time 0.411797
                try:
                    age_sec = float(age)
                except ValueError:
                    age_sec = -1.0
            else:
                fields = age.split(':')
                if len(fields) == 3:
                    try:
                        fields = [float(x) for x in fields]
                        hours, minutes, seconds = fields
                        age_sec = 3600 * hours + 60 * minutes + seconds
                    except ValueError:
                        age_sec = -1.0
            age_sec = round(age_sec, 1)

            interface = py23_compat.text_type(arp_table_entry.get('intf-out'))
            arp_table.append({
                'interface': interface,
                'mac': napalm.base.helpers.convert(
                    napalm.base.helpers.mac, raw_mac, raw_mac),
                'ip': napalm.base.helpers.ip(raw_ip),
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
            peer_addr = napalm.base.helpers.ip(ntp_peer.get('PeerIPAddress').strip())
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
            peer_address = napalm.base.helpers.ip(ntp_peer.get('remote').strip())
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
                'type': '',
                'when': '',
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
            interface_name = py23_compat.text_type(interface.get('intf-name', ''))
            addr_str = interface.get('prefix')
            unnumbered = py23_compat.text_type(interface.get('unnum-intf', ''))
            if addr_str:
                address = napalm.base.helpers.ip(addr_str)
                prefix = int(interface.get('masklen', ''))
                if interface_name not in interfaces_ip.keys():
                    interfaces_ip[interface_name] = {}
                if 'ipv4' not in interfaces_ip[interface_name].keys():
                    interfaces_ip[interface_name]['ipv4'] = {}
                if address not in interfaces_ip[interface_name].get('ipv4'):
                    interfaces_ip[interface_name]['ipv4'][address] = {}
                interfaces_ip[interface_name]['ipv4'][address].update({
                    'prefix_length': prefix
                })
            elif unnumbered:
                for interf in ipv4_interf_table_vrf:
                    interf_name = py23_compat.text_type(interf.get('intf-name', ''))
                    if interf_name == unnumbered:
                        address = napalm.base.helpers.ip(interf.get('prefix'))
                        prefix = int(interf.get('masklen', ''))
                        if interface_name not in interfaces_ip.keys():
                            interfaces_ip[interface_name] = {}
                        if 'ipv4' not in interfaces_ip[interface_name].keys():
                            interfaces_ip[interface_name]['ipv4'] = {}
                        if address not in interfaces_ip[interface_name].get('ipv4'):
                            interfaces_ip[interface_name]['ipv4'][address] = {}
                        interfaces_ip[interface_name]['ipv4'][address].update({
                            'prefix_length': prefix
                        })

            secondary_addresses = interface.get('TABLE_secondary_address', {}) \
                .get('ROW_secondary_address', [])
            if type(secondary_addresses) is dict:
                secondary_addresses = [secondary_addresses]
            for secondary_address in secondary_addresses:
                secondary_address_ip = napalm.base.helpers.ip(secondary_address.get('prefix1'))
                secondary_address_prefix = int(secondary_address.get('masklen1', ''))
                if 'ipv4' not in interfaces_ip[interface_name].keys():
                    interfaces_ip[interface_name]['ipv4'] = {}
                if secondary_address_ip not in interfaces_ip[interface_name].get('ipv4'):
                    interfaces_ip[interface_name]['ipv4'][secondary_address_ip] = {}
                interfaces_ip[interface_name]['ipv4'][secondary_address_ip].update({
                    'prefix_length': secondary_address_prefix
                })

        ipv6_command = 'show ipv6 interface'
        ipv6_interf_table_vrf = self._get_command_table(ipv6_command, 'TABLE_intf', 'ROW_intf')

        for interface in ipv6_interf_table_vrf:
            interface_name = py23_compat.text_type(interface.get('intf-name', ''))

            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = {}
            if 'ipv6' not in interfaces_ip[interface_name].keys():
                interfaces_ip[interface_name]['ipv6'] = {}

            if type(interface.get('addr', '')) is list:
                for ipv6_address in interface.get('addr', ''):
                    address = napalm.base.helpers.ip(ipv6_address.split('/')[0])
                    prefix = int(ipv6_address.split('/')[-1])
                    if address not in interfaces_ip[interface_name].get('ipv6'):
                        interfaces_ip[interface_name]['ipv6'][address] = {}
                    interfaces_ip[interface_name]['ipv6'][address].update({
                        'prefix_length': prefix
                    })
            else:
                address = napalm.base.helpers.ip(interface.get('addr', '').split('/')[0])
                prefix = interface.get('prefix', '').split('/')[-1]
                if prefix:
                    prefix = int(interface.get('prefix', '').split('/')[-1])
                else:
                    prefix = 128

                if address not in interfaces_ip[interface_name].get('ipv6'):
                    interfaces_ip[interface_name]['ipv6'][address] = {}
                interfaces_ip[interface_name]['ipv6'][address].update({
                    'prefix_length': prefix
                })
        return interfaces_ip

    def get_mac_address_table(self):
        mac_table = []
        command = 'show mac address-table'
        mac_table_raw = self._get_command_table(command, 'TABLE_mac_address', 'ROW_mac_address')

        for mac_entry in mac_table_raw:
            raw_mac = mac_entry.get('disp_mac_addr')
            interface = py23_compat.text_type(mac_entry.get('disp_port'))
            vlan = int(mac_entry.get('disp_vlan'))
            active = True
            static = (mac_entry.get('disp_is_static') != '0')
            moves = 0
            last_move = 0.0
            mac_table.append({
                'mac': napalm.base.helpers.mac(raw_mac),
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
        snmp_command = 'show running-config'
        snmp_raw_output = self.cli([snmp_command]).get(snmp_command, '')
        snmp_config = napalm.base.helpers.textfsm_extractor(self, 'snmp_config', snmp_raw_output)

        if not snmp_config:
            return snmp_information

        snmp_information = {
            'contact': py23_compat.text_type(''),
            'location': py23_compat.text_type(''),
            'community': {},
            'chassis_id': py23_compat.text_type('')
        }

        for snmp_entry in snmp_config:
            contact = py23_compat.text_type(snmp_entry.get('contact', ''))
            if contact:
                snmp_information['contact'] = contact
            location = py23_compat.text_type(snmp_entry.get('location', ''))
            if location:
                snmp_information['location'] = location

            community_name = py23_compat.text_type(snmp_entry.get('community', ''))
            if not community_name:
                continue

            if community_name not in snmp_information['community'].keys():
                snmp_information['community'][community_name] = {
                    'acl': py23_compat.text_type(snmp_entry.get('acl', '')),
                    'mode': py23_compat.text_type(snmp_entry.get('mode', '').lower())
                }
            else:
                acl = py23_compat.text_type(snmp_entry.get('acl', ''))
                if acl:
                    snmp_information['community'][community_name]['acl'] = acl
                mode = py23_compat.text_type(snmp_entry.get('mode', '').lower())
                if mode:
                    snmp_information['community'][community_name]['mode'] = mode
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
        command = 'show running-config'
        section_username_raw_output = self.cli([command]).get(command, '')
        section_username_tabled_output = napalm.base.helpers.textfsm_extractor(
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

    def traceroute(self,
                   destination,
                   source=c.TRACEROUTE_SOURCE,
                   ttl=c.TRACEROUTE_TTL,
                   timeout=c.TRACEROUTE_TIMEOUT,
                   vrf=c.TRACEROUTE_VRF):
        _HOP_ENTRY_PROBE = [
            r'\s+',
            r'(',  # beginning of host_name (ip_address) RTT group
            r'(',  # beginning of host_name (ip_address) group only
            r'([a-zA-Z0-9\.:-]*)',  # hostname
            r'\s+',
            r'\(?([a-fA-F0-9\.:][^\)]*)\)?'  # IP Address between brackets
            r')?',  # end of host_name (ip_address) group only
            # also hostname/ip are optional -- they can or cannot be specified
            # if not specified, means the current probe followed the same path as the previous
            r'\s+',
            r'(\d+\.\d+)\s+ms',  # RTT
            r'|\*',  # OR *, when non responsive hop
            r')'  # end of host_name (ip_address) RTT group
        ]

        _HOP_ENTRY = [
            r'\s?',  # space before hop index?
            r'(\d+)',  # hop index
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
        if traceroute_raw_output:
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
                    host_name = hop_details[3 + probe_index * 5]
                    ip_address_raw = hop_details[4 + probe_index * 5]
                    ip_address = napalm.base.helpers.convert(
                        napalm.base.helpers.ip, ip_address_raw, ip_address_raw)
                    rtt = hop_details[5 + probe_index * 5]
                    if rtt:
                        rtt = float(rtt)
                    else:
                        rtt = timeout * 1000.0
                    if not host_name:
                        host_name = previous_probe_host_name
                    if not ip_address:
                        ip_address = previous_probe_ip_address
                    if hop_details[1 + probe_index * 5] == '*':
                        host_name = '*'
                        ip_address = '*'
                    traceroute_result['success'][hop_index]['probes'][probe_index + 1] = {
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

        if retrieve.lower() in ('running', 'all'):
            _cmd = 'show running-config'
            config['running'] = py23_compat.text_type(self.cli([_cmd]).get(_cmd))
        if retrieve.lower() in ('startup', 'all'):
            _cmd = 'show startup-config'
            config['startup'] = py23_compat.text_type(self.cli([_cmd]).get(_cmd))
        return config
