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
import napalm_base.constants as C
from napalm_base.utils import py23_compat
from napalm_base.utils import string_parsers
from napalm_base.base import NetworkDriver
from napalm_base.exceptions import (
    ConnectionException,
    MergeConfigException,
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
        # Handling bad send_command_timing return output.
        try:
            interfaces = json.loads(interfaces)
        except ValueError:
            interfaces = json.loads(self.device.send_command('sudo net show interface all json'))

        interface_list = interfaces.keys()
        interface_list.sort()
        facts['hostname'] = facts['fqdn'] = py23_compat.text_type(hostname)
        facts['os_version'] = py23_compat.text_type(os_version)
        facts['model'] = py23_compat.text_type(model)
        facts['uptime'] = string_parsers.convert_uptime_string_seconds(uptime)
        facts['serial_number'] = py23_compat.text_type(serial_number)
        facts['interface_list'] = interface_list
        return facts

    def get_arp_table(self):

        """
        'show arp' output example:
        Address                  HWtype  HWaddress           Flags Mask            Iface
        10.129.2.254             ether   00:50:56:97:af:b1   C                     eth0
        192.168.1.134                    (incomplete)                              eth1
        192.168.1.1              ether   00:50:56:ba:26:7f   C                     eth1
        10.129.2.97              ether   00:50:56:9f:64:09   C                     eth0
        192.168.1.3              ether   00:50:56:86:7b:06   C                     eth1
        """
        output = self.device.send_command('arp -n')
        output = output.split("\n")
        output = output[1:]
        arp_table = list()

        for line in output:
            line = line.split()
            if "incomplete" in line[1]:
                macaddr = py23_compat.text_type("00:00:00:00:00:00")
            else:
                macaddr = py23_compat.text_type(line[2])

            arp_table.append(
                {
                    'interface': py23_compat.text_type(line[-1]),
                    'mac': macaddr,
                    'ip': py23_compat.text_type(line[0]),
                    'age': 0.0
                }
            )
        return arp_table

    def get_ntp_stats(self):
        """
        'ntpq -np' output example
             remote           refid      st t when poll reach   delay   offset  jitter
        ==============================================================================
         116.91.118.97   133.243.238.244  2 u   51   64  377    5.436  987971. 1694.82
         219.117.210.137 .GPS.            1 u   17   64  377   17.586  988068. 1652.00
         133.130.120.204 133.243.238.164  2 u   46   64  377    7.717  987996. 1669.77
        """

        output = self.device.send_command("ntpq -np")
        output = output.split("\n")[2:]
        ntp_stats = list()

        for ntp_info in output:
            if len(ntp_info) > 0:
                remote, refid, st, t, when, hostpoll, reachability, delay, offset, \
                    jitter = ntp_info.split()

                # 'remote' contains '*' if the machine synchronized with NTP server
                synchronized = "*" in remote

                match = re.search("(\d+\.\d+\.\d+\.\d+)", remote)
                ip = match.group(1)

                when = when if when != '-' else 0

                ntp_stats.append({
                    "remote": py23_compat.text_type(ip),
                    "referenceid": py23_compat.text_type(refid),
                    "synchronized": bool(synchronized),
                    "stratum": int(st),
                    "type": py23_compat.text_type(t),
                    "when": py23_compat.text_type(when),
                    "hostpoll": int(hostpoll),
                    "reachability": int(reachability),
                    "delay": float(delay),
                    "offset": float(offset),
                    "jitter": float(jitter)
                })

        return ntp_stats

    def ping(self,
             destination,
             source=C.PING_SOURCE,
             ttl=C.PING_TTL,
             timeout=C.PING_TIMEOUT,
             size=C.PING_SIZE,
             count=C.PING_COUNT,
             vrf=C.PING_VRF):

        deadline = timeout * count

        command = "ping %s " % destination
        command += "-t %d " % int(ttl)
        command += "-w %d " % int(deadline)
        command += "-s %d " % int(size)
        command += "-c %d " % int(count)
        if source != "":
            command += "interface %s " % source

        ping_result = dict()
        output_ping = self.device.send_command(command)

        if "Unknown host" in output_ping:
            err = "Unknown host"
        else:
            err = ""

        if err is not "":
            ping_result["error"] = err
        else:
            # 'packet_info' example:
            # ['5', 'packets', 'transmitted,' '5', 'received,' '0%', 'packet',
            # 'loss,', 'time', '3997ms']
            packet_info = output_ping.split("\n")

            if ('transmitted' in packet_info[-2]):
                packet_info = packet_info[-2]
            else:
                packet_info = packet_info[-3]

            packet_info = [x.strip() for x in packet_info.split()]

            sent = int(packet_info[0])
            received = int(packet_info[3])
            lost = sent - received

            # 'rtt_info' example:
            # ["0.307/0.396/0.480/0.061"]
            rtt_info = output_ping.split("\n")

            if len(rtt_info[-1]) > 0:
                rtt_info = rtt_info[-1]
            else:
                rtt_info = rtt_info[-2]

            match = re.search("([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)", rtt_info)

            if match is not None:
                rtt_min = float(match.group(1))
                rtt_avg = float(match.group(2))
                rtt_max = float(match.group(3))
                rtt_stddev = float(match.group(4))
            else:
                rtt_min = None
                rtt_avg = None
                rtt_max = None
                rtt_stddev = None

            ping_responses = list()
            response_info = output_ping.split("\n")

            for res in response_info:
                match_res = re.search("from\s([\d\.]+).*time=([\d\.]+)", res)
                if match_res is not None:
                    ping_responses.append(
                      {
                        "ip_address": match_res.group(1),
                        "rtt": float(match_res.group(2))
                      }
                    )

            ping_result["success"] = dict()

            ping_result["success"] = {
                "probes_sent": sent,
                "packet_loss": lost,
                "rtt_min": rtt_min,
                "rtt_max": rtt_max,
                "rtt_avg": rtt_avg,
                "rtt_stddev": rtt_stddev,
                "results": ping_responses
            }

            return ping_result

    def _get_interface_neighbors(self, neighbors_list):
        neighbors = []
        for neighbor in neighbors_list:
            temp = {}
            temp['hostname'] = neighbor['adj_hostname']
            temp['port'] = neighbor['adj_port']
            neighbors.append(temp)
        return neighbors

    def get_lldp_neighbors(self):
        """Cumulus get_lldp_neighbors."""
        lldp = {}
        command = 'sudo net show lldp json'

        try:
            lldp_output = json.loads(self._send_command(command))
        except ValueError:
            lldp_output = json.loads(self.device.send_command(command))

        for interface in lldp_output:
            lldp[interface] = self._get_interface_neighbors(
                                    lldp_output[interface]['iface_obj']['lldp'])
        return lldp
