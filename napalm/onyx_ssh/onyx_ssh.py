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
import json
import os
import time
import uuid
import tempfile
from scp import SCPClient
import paramiko
import hashlib
import socket

# import third party lib
from netaddr import IPAddress
from netaddr.core import AddrFormatError

# import NAPALM Base
from napalm.base import NetworkDriver
import napalm.base.helpers
from napalm.base.netmiko_helpers import netmiko_args
from napalm.base.utils import py23_compat
from napalm.base.exceptions import MergeConfigException
from napalm.base.exceptions import CommandErrorException
from napalm.base.exceptions import ReplaceConfigException
from napalm.base.helpers import canonical_interface_name
from napalm.onyx import ONYXDriverBase
import napalm.base.constants as c

# Easier to store these as constants
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS

# STD REGEX PATTERNS
IP_ADDR_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
IPV4_ADDR_REGEX = IP_ADDR_REGEX
IPV6_ADDR_REGEX_1 = r"::"
IPV6_ADDR_REGEX_2 = r"[0-9a-fA-F:]{1,39}::[0-9a-fA-F:]{1,39}"
IPV6_ADDR_REGEX_3 = r"[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:" \
                     r"[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}"
# Should validate IPv6 address using an IP address library after matching with this regex
IPV6_ADDR_REGEX = r"(?:{}|{}|{})".format(IPV6_ADDR_REGEX_1, IPV6_ADDR_REGEX_2, IPV6_ADDR_REGEX_3)
IPV4_OR_IPV6_REGEX = r"(?:{}|{})".format(IPV4_ADDR_REGEX, IPV6_ADDR_REGEX)

MAC_REGEX = r"[a-fA-F0-9:]{17}|[a-fA-F0-9]{12}$"
VLAN_REGEX = r"\d{1,4}"

RE_IPADDR = re.compile(r"{}".format(IP_ADDR_REGEX))
RE_MAC = re.compile(r"{}".format(MAC_REGEX))

# Period needed for 32-bit AS Numbers
ASN_REGEX = r"[\d\.]+"


def parse_intf_section(interface):
    """Parse a single entry from show interfaces output.

    Different cases:
    mgmt0 is up
    admin state is up

    Ethernet2/1 is up
    admin state is up, Dedicated Interface

    Vlan1 is down (Administratively down), line protocol is down, autostate enabled

    Ethernet154/1/48 is up (with no 'admin state')
    """
    interface = interface.strip()
    re_protocol = r"^(?P<intf_name>\S+?)\s+is\s+(?P<status>.+?)" \
                  r",\s+line\s+protocol\s+is\s+(?P<protocol>\S+).*$"
    re_intf_name_state = r"^(?P<intf_name>\S+) is (?P<intf_state>\S+).*"
    re_is_enabled_1 = r"^admin state is (?P<is_enabled>\S+)$"
    re_is_enabled_2 = r"^admin state is (?P<is_enabled>\S+), "
    re_is_enabled_3 = r"^.* is down.*Administratively down.*$"
    re_mac = r"^\s+Hardware:\s+(?P<hardware>.*), address:\s+(?P<mac_address>\S+) "
    re_speed = r"\s+MTU .*, BW (?P<speed>\S+) (?P<speed_unit>\S+), "
    re_description_1 = r"^\s+Description:\s+(?P<description>.*)  (?:MTU|Internet)"
    re_description_2 = r"^\s+Description:\s+(?P<description>.*)$"
    re_hardware = r"^.* Hardware: (?P<hardware>\S+)$"

    # Check for 'protocol is ' lines
    match = re.search(re_protocol, interface, flags=re.M)
    if match:
        intf_name = match.group('intf_name')
        status = match.group('status')
        protocol = match.group('protocol')

        if 'admin' in status.lower():
            is_enabled = False
        else:
            is_enabled = True
        is_up = bool('up' in protocol)

    else:
        # More standard is up, next line admin state is lines
        match = re.search(re_intf_name_state, interface)
        intf_name = match.group('intf_name')
        intf_state = match.group('intf_state').strip()
        is_up = True if intf_state == 'up' else False

        admin_state_present = re.search("admin state is", interface)
        if admin_state_present:
            # Parse cases where 'admin state' string exists
            for x_pattern in [re_is_enabled_1, re_is_enabled_2]:
                match = re.search(x_pattern, interface, flags=re.M)
                if match:
                    is_enabled = match.group('is_enabled').strip()
                    is_enabled = True if re.search("up", is_enabled) else False
                    break
            else:
                msg = "Error parsing intf, 'admin state' never detected:\n\n{}".format(interface)
                raise ValueError(msg)
        else:
            # No 'admin state' should be 'is up' or 'is down' strings
            # If interface is up; it is enabled
            is_enabled = True
            if not is_up:
                match = re.search(re_is_enabled_3, interface, flags=re.M)
                if match:
                    is_enabled = False

    match = re.search(re_mac, interface, flags=re.M)
    if match:
        mac_address = match.group('mac_address')
        mac_address = napalm.base.helpers.mac(mac_address)
    else:
        mac_address = ""

    match = re.search(re_hardware, interface, flags=re.M)
    speed_exist = True
    if match:
        if match.group('hardware') == "NVE":
            speed_exist = False

    if speed_exist:
        match = re.search(re_speed, interface, flags=re.M)
        speed = int(match.group('speed'))
        speed_unit = match.group('speed_unit')
        # This was alway in Kbit (in the data I saw)
        if speed_unit != "Kbit":
            msg = "Unexpected speed unit in show interfaces parsing:\n\n{}".format(interface)
            raise ValueError(msg)
        speed = int(round(speed / 1000.0))
    else:
        speed = -1

    description = ''
    for x_pattern in [re_description_1, re_description_2]:
        match = re.search(x_pattern, interface, flags=re.M)
        if match:
            description = match.group('description')
            break

    return {
             intf_name: {
                    'description': description,
                    'is_enabled': is_enabled,
                    'is_up': is_up,
                    'last_flapped': -1.0,
                    'mac_address': mac_address,
                    'speed': speed}
           }


def convert_hhmmss(hhmmss):
    """Convert hh:mm:ss to seconds."""
    fields = hhmmss.split(":")
    if len(fields) != 3:
        raise ValueError("Received invalid HH:MM:SS data: {}".format(hhmmss))
    fields = [int(x) for x in fields]
    hours, minutes, seconds = fields
    return (hours * 3600) + (minutes * 60) + seconds


def bgp_time_conversion(bgp_uptime):
    """Convert string time to seconds.

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


def bgp_normalize_table_data(bgp_table):
    """The 'show bgp all summary vrf all' table can have entries that wrap multiple lines.

    2001:db8:4:701::2
                4 65535  163664  163693      145    0    0     3w2d 3
    2001:db8:e0:dd::1
                4    10  327491  327278      145    0    0     3w1d 4

    Normalize this so the line wrap doesn't exit.
    """
    bgp_table = bgp_table.strip()
    bgp_multiline_pattern = r"({})\s*\n".format(IPV4_OR_IPV6_REGEX)
    # Strip out the newline
    return re.sub(bgp_multiline_pattern, r'\1', bgp_table)


def bgp_table_parser(bgp_table):
    """Generator that parses a line of bgp summary table and returns a dict compatible with NAPALM

    Example line:
    10.2.1.14       4    10  472516  472238      361    0    0     3w1d 9
    """
    bgp_table = bgp_table.strip()
    for bgp_entry in bgp_table.splitlines():
        bgp_table_fields = bgp_entry.split()

        try:
            if re.search(r'Shut.*Admin', bgp_entry):
                (peer_ip, bgp_version, remote_as, msg_rcvd, msg_sent, _, _, _,
                    uptime, state_1, state_2) = bgp_table_fields
                state_pfxrcd = "{} {}".format(state_1, state_2)
            else:
                (peer_ip, bgp_version, remote_as, msg_rcvd, msg_sent, _, _, _,
                    uptime, state_pfxrcd) = bgp_table_fields
        except ValueError:
            raise ValueError("Unexpected entry ({}) in BGP summary table".format(bgp_table_fields))

        is_enabled = True
        try:
            received_prefixes = int(state_pfxrcd)
            is_up = True
        except ValueError:
            received_prefixes = -1
            is_up = False
            if re.search(r'Shut.*Admin', state_pfxrcd):
                is_enabled = False

        if not is_up:
            uptime = -1
        if uptime != -1:
            uptime = bgp_time_conversion(uptime)

        yield {
            peer_ip: {
                "is_enabled": is_enabled,
                "uptime": uptime,
                "remote_as": napalm.base.helpers.as_number(remote_as),
                "is_up": is_up,
                "description": "",
                "received_prefixes": received_prefixes,
            }
        }


def bgp_summary_parser(bgp_summary):
    """Parse 'show bgp all summary vrf' output information from NX-OS devices."""

    bgp_summary_dict = {}
    # Check for BGP summary information lines that have no data
    if len(bgp_summary.strip().splitlines()) <= 1:
        return {}

    allowed_afi = ['ipv4', 'ipv6', 'l2vpn']
    vrf_regex = r"^BGP summary information for VRF\s+(?P<vrf>\S+),"
    afi_regex = r"^BGP summary information.*address family (?P<afi>\S+ (?:Unicast|EVPN))"
    local_router_regex = (r"^BGP router identifier\s+(?P<router_id>\S+)"
                          r",\s+local AS number\s+(?P<local_as>\S+)")

    for pattern in [vrf_regex, afi_regex, local_router_regex]:
        match = re.search(pattern, bgp_summary, flags=re.M)
        if match:
            bgp_summary_dict.update(match.groupdict(1))

    # Some post regex cleanup and validation
    vrf = bgp_summary_dict['vrf']
    if vrf.lower() == 'default':
        bgp_summary_dict['vrf'] = 'global'

    afi = bgp_summary_dict['afi']
    afi = afi.split()[0].lower()
    if afi not in allowed_afi:
        raise ValueError("AFI ({}) is invalid and not supported.".format(afi))
    bgp_summary_dict['afi'] = afi

    local_as = bgp_summary_dict['local_as']
    local_as = napalm.base.helpers.as_number(local_as)

    match = re.search(IPV4_ADDR_REGEX, bgp_summary_dict['router_id'])
    if not match:
        raise ValueError("BGP router_id ({}) is not valid".format(bgp_summary_dict['router_id']))

    vrf = bgp_summary_dict['vrf']
    bgp_return_dict = {
        vrf: {
            "router_id": bgp_summary_dict['router_id'],
            "peers": {},
        }
    }

    # Extract and process the tabular data
    tabular_divider = r"^Neighbor\s+.*PfxRcd$"
    tabular_data = re.split(tabular_divider, bgp_summary, flags=re.M)
    if len(tabular_data) != 2:
        msg = "Unexpected data processing BGP summary information:\n\n{}".format(bgp_summary)
        raise ValueError(msg)
    tabular_data = tabular_data[1]
    bgp_table = bgp_normalize_table_data(tabular_data)
    for bgp_entry in bgp_table_parser(bgp_table):
        bgp_return_dict[vrf]["peers"].update(bgp_entry)

    bgp_new_dict = {}
    for neighbor, bgp_data in bgp_return_dict[vrf]["peers"].items():
        received_prefixes = bgp_data.pop("received_prefixes")
        bgp_data["address_family"] = {}
        prefixes_dict = {"sent_prefixes": -1,
                         "accepted_prefixes": -1,
                         "received_prefixes": received_prefixes}
        bgp_data["address_family"][afi] = prefixes_dict
        bgp_data["local_as"] = local_as
        # FIX, hard-coding
        bgp_data["remote_id"] = "0.0.0.0"
        bgp_new_dict[neighbor] = bgp_data

    bgp_return_dict[vrf]["peers"] = bgp_new_dict

    return bgp_return_dict


class ONYXSSHDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.replace = True
        self.loaded = False
        self.changed = False
        self.up = False
        self.replace_file = None
        self.merge_candidate = ''
        self.netmiko_optional_args = netmiko_args(optional_args)
        self.device = None

    def open(self):
        self.device = self._netmiko_open(
            device_type='mellanox',
            netmiko_optional_args=self.netmiko_optional_args,
        )
        if self.device is not None:
            self.up = True

    def close(self):
        if self.changed:
            self._delete_file(self.backup_file)
        self._netmiko_close()

    def _send_command(self, command):
        """Wrapper for Netmiko's send_command method."""
        return self.device.send_command(command)

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
            elif re.search("second", element):
                seconds = int(element.split()[0])

        uptime_sec = (years * YEAR_SECONDS) + (weeks * WEEK_SECONDS) + (days * DAY_SECONDS) + \
                     (hours * 3600) + (minutes * 60) + seconds
        return uptime_sec

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

    def is_alive(self):
        """Returns a flag with the state of the SSH connection."""
        null = chr(0)
        try:
            if self.device is None:
                return {'is_alive': False}
            else:
                # Try sending ASCII null byte to maintain the connection alive
                self.device.send_command(null)
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure that the connection is unusable,
            # hence return False.
            return {'is_alive': False}
        return {
            'is_alive': self.device.remote_conn.transport.is_active()
        }

    def load_replace_candidate(self, filename=None, config=None):
        self._replace_candidate(filename, config)
        self.replace = True
        self.loaded = True

    def _get_flash_size(self):
        command = 'dir {}'.format('bootflash:')
        output = self.device.send_command(command)

        match = re.search(r'(\d+) bytes free', output)
        bytes_free = match.group(1)

        return int(bytes_free)

    def _enough_space(self, filename):
        flash_size = self._get_flash_size()
        file_size = os.path.getsize(filename)
        if file_size > flash_size:
            return False
        return True

    def _verify_remote_file_exists(self, dst, file_system='bootflash:'):
        command = 'dir {0}/{1}'.format(file_system, dst)
        output = self.device.send_command(command)
        if 'No such file' in output:
            raise ReplaceConfigException('Could not transfer file.')

    def _replace_candidate(self, filename, config):
        if not filename:
            filename = self._create_tmp_file(config)
        else:
            if not os.path.isfile(filename):
                raise ReplaceConfigException("File {} not found".format(filename))

        self.replace_file = filename
        if not self._enough_space(self.replace_file):
            msg = 'Could not transfer file. Not enough space on device.'
            raise ReplaceConfigException(msg)

        self._check_file_exists(self.replace_file)
        dest = os.path.basename(self.replace_file)
        full_remote_path = 'bootflash:{}'.format(dest)
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=self.hostname, username=self.username, password=self.password)

            try:
                with SCPClient(ssh.get_transport()) as scp_client:
                    scp_client.put(self.replace_file, full_remote_path)
            except Exception:
                time.sleep(10)
                file_size = os.path.getsize(filename)
                temp_size = self._verify_remote_file_exists(dest)
                if int(temp_size) != int(file_size):
                    msg = ('Could not transfer file. There was an error '
                           'during transfer. Please make sure remote '
                           'permissions are set.')
                raise ReplaceConfigException(msg)
        self.config_replace = True
        if config and os.path.isfile(self.replace_file):
            os.remove(self.replace_file)

    def _file_already_exists(self, dst):
        dst_hash = self._get_remote_md5(dst)
        src_hash = self._get_local_md5(dst)
        if src_hash == dst_hash:
            return True
        return False

    def _check_file_exists(self, cfg_file):
        command = 'dir {}'.format(cfg_file)
        output = self.device.send_command(command)
        if 'No such file' in output:
            return False
        else:
            return self._file_already_exists(cfg_file)

    def _get_remote_md5(self, dst):
        command = 'show file {0} md5sum'.format(dst)
        return self.device.send_command(command).strip()

    def _get_local_md5(self, dst, blocksize=2**20):
        md5 = hashlib.md5()
        local_file = open(dst, 'rb')
        buf = local_file.read(blocksize)
        while buf:
            md5.update(buf)
            buf = local_file.read(blocksize)
        local_file.close()
        return md5.hexdigest()

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

    @staticmethod
    def _create_tmp_file(config):
        tmp_dir = tempfile.gettempdir()
        rand_fname = py23_compat.text_type(uuid.uuid4())
        filename = os.path.join(tmp_dir, rand_fname)
        with open(filename, 'wt') as fobj:
            fobj.write(config)
        return filename

    def _create_sot_file(self):
        """Create Source of Truth file to compare."""
        commands = ['terminal dont-ask', 'checkpoint file sot_file']
        self._send_config_commands(commands)

    def _get_diff(self):
        """Get a diff between running config and a proposed file."""
        diff = []
        self._create_sot_file()
        command = ('show diff rollback-patch file {0} file {1}'.format(
                   'sot_file', self.replace_file.split('/')[-1]))
        diff_out = self.device.send_command(command)
        try:
            diff_out = diff_out.split(
                'Generating Rollback Patch')[1].replace(
                    'Rollback Patch is Empty', '').strip()
            for line in diff_out.splitlines():
                if line:
                    if line[0].strip() != '!' and line[0].strip() != '.':
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
            diff = self._get_diff()
            return diff
        return ''

    def _copy_run_start(self, filename='startup-config'):
        command = 'copy run {}'.format(filename)
        output = self.device.send_command(command)
        if 'complete' in output.lower():
            return True
        else:
            msg = 'Unable to save running-config to {}!'.format(filename)
            raise CommandErrorException(msg)

    def _commit_merge(self):
        try:
            commands = [command for command in self.merge_candidate.splitlines() if command]
            output = self.device.send_config_set(commands)
        except Exception as e:
            raise MergeConfigException(str(e))
        if 'Invalid command' in output:
            raise MergeConfigException('Error while applying config!')
        # clear the merge buffer
        self.merge_candidate = ''

    def _save_to_checkpoint(self, filename):
        """Save the current running config to the given file."""
        command = 'checkpoint file {}'.format(filename)
        self.device.send_command(command)

    def _disable_confirmation(self):
        self._send_config_commands(['terminal dont-ask'])

    def _load_cfg_from_checkpoint(self):
        command = 'rollback running file {0}'.format(self.replace_file.split('/')[-1])
        self._disable_confirmation()
        rollback_result = self.device.send_command(command)
        if 'Rollback failed.' in rollback_result or 'ERROR' in rollback_result:
            raise ReplaceConfigException(rollback_result)
        elif rollback_result == []:
            raise ReplaceConfigException

    def _delete_file(self, filename):
        commands = [
            'terminal dont-ask',
            'delete {}'.format(filename),
            'no terminal dont-ask'
        ]
        for command in commands:
            self.device.send_command(command)

    def discard_config(self):
        if self.loaded:
            self.merge_candidate = ''  # clear the buffer
        if self.loaded and self.replace:
            self._delete_file(self.replace_file)
        self.loaded = False

    def rollback(self):
        if self.changed:
            command = 'rollback running-config file {}'.format(self.backup_file)
            result = self.device.send_command(command)
            if 'completed' not in result.lower():
                raise ReplaceConfigException(result)
            self._copy_run_start()
            self.changed = False

    def _apply_key_map(self, key_map, table):
        new_dict = {}
        for key, value in table.items():
            new_key = key_map.get(key)
            if new_key:
                new_dict[new_key] = str(value)
        return new_dict

    def _convert_uptime_to_seconds(self, uptime_facts):
        seconds = int(uptime_facts['up_days']) * 24 * 60 * 60
        seconds += int(uptime_facts['up_hours']) * 60 * 60
        seconds += int(uptime_facts['up_mins']) * 60
        seconds += int(uptime_facts['up_secs'])
        return seconds

    def get_facts(self):
        """Return a set of facts from the devices."""
        # default values.
        vendor = u'Onyx'
        uptime = -1
        serial_number, fqdn, os_version, hostname, domain_name, model = ('',) * 6

        # obtain output from device
        show_ver = self.device.send_command('show version | json-print')
        show_ver = json.loads(show_ver)
        show_hosts = self.device.send_command('show hosts | json-print')
        show_hosts = json.loads(show_hosts)
        show_int_status = self.device.send_command('show interfaces status | json-print')
        show_int_status = json.loads(show_int_status)

        # uptime/serial_number/IOS version
        uptime = show_ver.get('Uptime')
        os_version = show_ver.get('Product release')
        vendor = show_ver.get('Product name')
        # for line in show_ver.splitlines():
        #     if ' uptime is ' in line:
        #         _, uptime_str = line.split(' uptime is ')
        #         uptime = self.parse_uptime(uptime_str)
        #
        #     if 'Processor Board ID' in line:
        #         _, serial_number = line.split("Processor Board ID ")
        #         serial_number = serial_number.strip()
        #
        #     if 'system: ' in line or 'Onyx: ' in line:
        #         line = line.strip()
        #         os_version = line.split()[2]
        #         os_version = os_version.strip()
        #
        #     if 'cisco' in line and 'hassis' in line:
        #         match = re.search(r'.cisco (.*) \(', line)
        #         if match:
        #             model = match.group(1).strip()
        #         match = re.search(r'.cisco (.* [cC]hassis)', line)
        #         if match:
        #             model = match.group(1).strip()

        hostname = show_hosts[0].get('Hostname')
        domain_name = show_hosts[2].get('Domain names')

        # Determine domain_name and fqdn
        # for line in show_hosts.splitlines():
        #     if 'Default domain' in line:
        #         _, domain_name = re.split(r".*Default domain.*is ", line)
        #         domain_name = domain_name.strip()
        #         break
        # if hostname.count(".") >= 2:
        #     fqdn = hostname
        #     # Remove domain name from hostname
        #     if domain_name:
        #         hostname = re.sub(re.escape(domain_name) + '$', '', hostname)
        #         hostname = hostname.strip('.')
        # elif domain_name:
        #     fqdn = '{}.{}'.format(hostname, domain_name)

        # interface_list filter
        interface_list = []
        # show_int_status = show_int_status
        # interfaces = json.loads(show_int_status)
        # Remove the header information
        # show_int_status = re.sub(r'(?:^---------+$|^Port .*$|^ .*$)', '',
        #                          show_int_status, flags=re.M)
        # for line in show_int_status.splitlines():
        #     if not line:
        #         continue
        #     interface = line.split()[0]
        #     # Return canonical interface name
        #     interface_list.append(canonical_interface_name(interface))

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

        {   u'Vlan1': {   'description': u'',
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
        no_paging_enable_command = 'no cli session paging enable'
        self.device.send_command(no_paging_enable_command)
        command = 'show interfaces | json-print'
        output = self.device.send_command(command)
        if not output:
            return {}

        return output

    def disable_paging(self):
        no_paging_enable_command = 'no cli session paging enable'
        self.device.disable_paging(command=no_paging_enable_command)

    def enable(self):
        self.device.enable(cmd='enable', pattern=r'\s#\s')

    def config_terminal(self):
        self.device.config_mode(config_command='configure terminal', pattern=r'\(config\)')

    def exit(self):
        self.device.send_command("exit", expect_string=r'\(config\)')

    def show_vlans(self):
        self.disable_paging()
        command = 'show vlan | json-print'
        output = self.device.send_command(command)
        return output

    def get_vlan(self, vlan_id):
        no_paging_enable_command = 'no cli session paging enable'
        self.device.send_command(no_paging_enable_command)
        command = 'show vlan id {0} | json-print'.format(vlan_id)
        output = self.device.send_command(command)
        return output

    def create_vlan(self, vlan_id, interfaces):
        no_paging_enable_command = 'no cli session paging enable'
        self.device.disable_paging(command=no_paging_enable_command)
        vlan = self.get_vlan(vlan_id)
        vlan = json.loads(vlan)
        if not vlan:
            self.device.enable(cmd='enable', pattern=r'\s#\s')
            self.device.config_mode(config_command='configure terminal', pattern=r'\(config\)')
            self.device.send_command("vlan {0}".format(vlan_id), expect_string=r'\(config vlan')
            self.device.send_command("exit", expect_string=r'\(config\)')
            if interfaces is not None:
                if type(interfaces) is not list:
                    raise TypeError('Please enter a valid list of interfaces!')
                for interface in interfaces:
                    interface = interface.replace('Eth', 'ethernet ')
                    self.device.send_command("interface {0} switchport access vlan {1}".format(interface, vlan_id))
                    return 'Created Vlan with id {} has Done Successfully'.format(vlan_id)

    def get_lldp_neighbors(self):
        results = {}
        command = 'show lldp neighbors'
        output = self.device.send_command(command)
        lldp_neighbors = napalm.base.helpers.textfsm_extractor(
                            self, 'lldp_neighbors', output)

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
        """BGP neighbor information.

        Supports VRFs and IPv4 and IPv6 AFIs

        {
        "global": {
            "router_id": "1.1.1.103",
            "peers": {
                "10.99.99.2": {
                    "is_enabled": true,
                    "uptime": -1,
                    "remote_as": 22,
                    "address_family": {
                        "ipv4": {
                            "sent_prefixes": -1,
                            "accepted_prefixes": -1,
                            "received_prefixes": -1
                        }
                    },
                    "remote_id": "0.0.0.0",
                    "local_as": 22,
                    "is_up": false,
                    "description": ""
                 }
            }
        }
        """
        bgp_dict = {}

        # get summary output from device
        cmd_bgp_all_sum = 'show bgp all summary vrf all'
        bgp_summary_output = self.device.send_command(cmd_bgp_all_sum).strip()

        section_separator = r"BGP summary information for "
        bgp_summary_sections = re.split(section_separator, bgp_summary_output)
        if len(bgp_summary_sections):
            bgp_summary_sections.pop(0)

        for bgp_section in bgp_summary_sections:
            bgp_section = section_separator + bgp_section
            bgp_dict.update(bgp_summary_parser(bgp_section))

        # FIX -- look up logical or behavior we did in Cisco IOS bgp parser (make consistent here)
        # FIX -- need to merge IPv6 and IPv4 AFI for same neighbor
        return bgp_dict

    def _send_config_commands(self, commands):
        for command in commands:
            self.device.send_command(command)

    def _set_checkpoint(self, filename):
        commands = ['terminal dont-ask', 'checkpoint file {0}'.format(filename)]
        self._send_config_commands(commands)

    def _get_checkpoint_file(self):
        filename = 'temp_cp_file_from_napalm'
        self._set_checkpoint(filename)
        command = 'show file {0}'.format(filename)
        output = self.device.send_command(command)
        self._delete_file(filename)
        return output

    def get_lldp_neighbors_detail(self, interface=''):
        lldp_neighbors = {}
        filter = ''
        if interface:
            filter = 'interface {name} '.format(name=interface)

        command = 'show lldp neighbors {filter}detail'.format(filter=filter)
        # seems that some old devices may not return JSON output...

        output = self.device.send_command(command)
        # thus we need to take the raw text output
        lldp_neighbors_list = output.splitlines()

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
            output = self.device.send_command(command)
            cli_output[py23_compat.text_type(command)] = output
        return cli_output

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
                    'age'       : 12.0
                },
                {
                    'interface': 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '66:0e:94:96:e0:ff',
                    'ip'        : '172.17.17.2',
                    'age'       : 14.0
                }
            ]
        """
        arp_table = []

        command = 'show ip arp vrf default | exc INCOMPLETE'
        output = self.device.send_command(command)
        output = output.split('\n')
        arp_entries = output[7:-1]

        for line in arp_entries:
            if len(line.split()) >= 5:
                # Search for extra characters to strip, currently strip '*', '+', '#', 'D'
                line = re.sub(r"\s+[\*\+\#D]{1,4}\s*$", "", line, flags=re.M)
                line_list = line.split()
                address = line_list[0]
                type = line_list[1] + ' ' + line_list[2]
                mac = line_list[3]
                interface = line_list[4]
            else:
                raise ValueError("Unexpected output from: {}".format(line.split()))

            # Validate we matched correctly
            if not re.search(RE_IPADDR, address):
                raise ValueError("Invalid IP Address detected: {}".format(address))
            if not re.search(RE_MAC, mac):
                raise ValueError("Invalid MAC Address detected: {}".format(mac))
            entry = {
                'interface': interface,
                'mac': napalm.base.helpers.mac(mac),
                'ip': address,
                'type': type
            }
            arp_table.append(entry)
        return arp_table

    def _get_ntp_entity(self, peer_type):
        ntp_entities = {}
        command = 'show ntp peers'
        output = self.device.send_command(command)

        for line in output.splitlines():
            # Skip first two lines and last line of command output
            if line == "" or '-----' in line or 'Peer IP Address' in line:
                continue
            elif IPAddress(len(line.split()[0])).is_unicast:
                peer_addr = line.split()[0]
                ntp_entities[peer_addr] = {}
            else:
                raise ValueError("Did not correctly find a Peer IP Address")

        return ntp_entities

    def get_ntp_peers(self):
        return self._get_ntp_entity('Peer')

    def get_ntp_servers(self):
        return self._get_ntp_entity('Server')

    def __get_ntp_stats(self):
        ntp_stats = []
        command = 'show ntp peer-status'
        output = self.device.send_command(command) # noqa
        return ntp_stats

    def get_interfaces_ip(self):
        """
        Get interface IP details. Returns a dictionary of dictionaries.

        Sample output:
        {
            "Ethernet2/3": {
                "ipv4": {
                    "4.4.4.4": {
                        "prefix_length": 16
                    }
                },
                "ipv6": {
                    "2001:db8::1": {
                        "prefix_length": 10
                    },
                    "fe80::2ec2:60ff:fe4f:feb2": {
                        "prefix_length": "128"
                    }
                }
            },
            "Ethernet2/2": {
                "ipv4": {
                    "2.2.2.2": {
                        "prefix_length": 27
                    }
                }
            }
        }
        """
        interfaces_ip = {}
        ipv4_command = 'show ip interface vrf default | json-print'
        output_v4 = self.device.send_command(ipv4_command)
        output_v4 = json.loads(output_v4)

        v4_interfaces = {}
        interface_mgmt0_status = output_v4[0].get('Interface mgmt0 status')
        interface = 'mgmt0'
        ip_address = interface_mgmt0_status[0].get('IP address')
        netmask = interface_mgmt0_status[0].get('Netmask')
        prefix_len = sum([bin(int(x)).count("1") for x in netmask.split(".")])
        val = {'prefix_length': prefix_len}
        v4_interfaces.setdefault(interface, {})[ip_address] = val

        # Join data from intermediate dictionaries.
        for interface, data in v4_interfaces.items():
            interfaces_ip.setdefault(interface, {'ipv4': {}})['ipv4'] = data

        return interfaces_ip

    def get_mac_address_table(self):
        """
        Returns a lists of dictionaries. Each dictionary represents an entry in the MAC Address
        Table, having the following keys
            * mac (string)
            * interface (string)
            * vlan (int)
            * mac_type (string)
        Format1:

        Legend:
        * - primary entry, G - Gateway MAC, (R) - Routed MAC, O - Overlay MAC
        age - seconds since last seen,+ - primary entry using vPC Peer-Link,
        (T) - True, (F) - False
        ---------------------------------------------------
        Vlan    Mac Address         Type         Port
        ---------------------------------------------------
        1       E4:1D:2D:66:DF:9B   Dynamic      Eth1/19
        1       EC:0D:9A:42:EA:00   Dynamic      Eth1/19
        1       EC:0D:9A:42:EA:01   Dynamic      Eth1/31


        Number of unicast:    3
        Number of multicast:  0


        """

        mac_address_table = []
        command = 'show mac-address-table'
        mac_table_output = self.device.send_command(command) # noqa
        output = mac_table_output.split('\n')
        mac_entries = output[3:-5]

        for line in mac_entries:
            if len(line.split()) >= 4:
                # Search for extra characters to strip, currently strip '*', '+', '#', 'D'
                line = re.sub(r"\s+[\*\+\#D]{1,4}\s*$", "", line, flags=re.M)
                line_list = line.split()
                vlan = line_list[0]
                mac = line_list[1]
                mac_type = line_list[2]
                interface = line_list[3]
                mac_address_table.append({
                    'mac': napalm.base.helpers.mac(mac),
                    'interface': interface,
                    'vlan': int(vlan),
                    'type': mac_type
                })
            else:
                raise ValueError("Unexpected output from: {}".format(line.split()))

        return mac_address_table

    def get_snmp_information(self):
        snmp_information = {}
        command = 'show running-config'
        output = self.device.send_command(command)
        snmp_config = napalm.base.helpers.textfsm_extractor(self, 'snmp_config', output)

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
        output = self.device.send_command(command)
        section_username_tabled_output = napalm.base.helpers.textfsm_extractor(
            self, 'users', output)

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
            # Allow use of DNS names
            pass

        if source:
            source_opt = 'source {source}'.format(source=source)
            command = 'traceroute{version} {destination} {source_opt}'.format(
                version=version,
                destination=destination,
                source_opt=source_opt)
        else:
            command = 'traceroute{version} {destination}'.format(
                version=version,
                destination=destination)

        try:
            traceroute_raw_output = self.device.send_command(command)
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
                    host_name = hop_details[3+probe_index*5]
                    ip_address_raw = hop_details[4+probe_index*5]
                    ip_address = napalm.base.helpers.convert(
                        napalm.base.helpers.ip, ip_address_raw, ip_address_raw)
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

        if retrieve.lower() in ('running', 'all'):
            command = 'show running-config'
            config['running'] = py23_compat.text_type(self.device.send_command(command))
        if retrieve.lower() in ('startup', 'all'):
            command = 'show startup-config'
            config['startup'] = py23_compat.text_type(self.device.send_command(command))
        return config
