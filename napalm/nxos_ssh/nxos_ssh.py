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

# import stdlib
from builtins import super
import re
import socket

# import third party lib
from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError

# import NAPALM Base
from napalm.base import helpers
from napalm.base.exceptions import CommandErrorException, ReplaceConfigException
from napalm.nxos import NXOSDriverBase

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
IPV6_ADDR_REGEX_3 = (
    r"[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:"
    r"[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}"
)
# Should validate IPv6 address using an IP address library after matching with this regex
IPV6_ADDR_REGEX = r"(?:{}|{}|{})".format(
    IPV6_ADDR_REGEX_1, IPV6_ADDR_REGEX_2, IPV6_ADDR_REGEX_3
)
IPV4_OR_IPV6_REGEX = r"(?:{}|{})".format(IPV4_ADDR_REGEX, IPV6_ADDR_REGEX)

MAC_REGEX = r"[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}"
VLAN_REGEX = r"\d{1,4}"

RE_IPADDR = re.compile(r"{}".format(IP_ADDR_REGEX))
RE_MAC = re.compile(r"{}".format(MAC_REGEX))

# Period needed for 32-bit AS Numbers
ASN_REGEX = r"[\d\.]+"

RE_IP_ROUTE_VIA_REGEX = re.compile(
    r"    (?P<used>[\*| ])via ((?P<ip>" + IPV4_ADDR_REGEX + r")"
    r"(%(?P<vrf>\S+))?, )?"
    r"((?P<int>[\w./:]+), )?\[(\d+)/(?P<metric>\d+)\]"
    r", (?P<age>[\d\w:]+), (?P<source>[\w]+)(-(?P<procnr>\d+))?"
    r"(?P<rest>.*)"
)
RE_RT_VRF_NAME = re.compile(r"VRF \"(\S+)\"")
RE_RT_IPV4_ROUTE_PREF = re.compile(r"(" + IPV4_ADDR_REGEX + r"/\d{1,2}), ubest.*")

RE_BGP_PROTO_TAG = re.compile(r"BGP Protocol Tag\s+: (\d+)")
RE_BGP_REMOTE_AS = re.compile(r"remote AS (" + ASN_REGEX + r")")
RE_BGP_COMMUN = re.compile(r"[ ]{10}([\S ]+)")


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
    re_protocol = (
        r"^(?P<intf_name>\S+?)\s+is\s+(?P<status>.+?)"
        r",\s+line\s+protocol\s+is\s+(?P<protocol>\S+).*$"
    )
    re_intf_name_state = r"^(?P<intf_name>\S+) is (?P<intf_state>\S+).*"
    re_is_enabled_1 = r"^admin state is (?P<is_enabled>\S+)$"
    re_is_enabled_2 = r"^admin state is (?P<is_enabled>\S+), "
    re_is_enabled_3 = r"^.* is down.*Administratively down.*$"
    re_mac = r"^\s+Hardware:\s+(?P<hardware>.*),\s+address:\s+(?P<mac_address>\S+) "
    re_speed = (
        r"\s+MTU (?P<mtu>\S+)\s+bytes,\s+BW\s+(?P<speed>\S+)\s+(?P<speed_unit>\S+).*$"
    )
    re_mtu_nve = r"\s+MTU (?P<mtu_nve>\S+)\s+bytes.*$"
    re_description_1 = r"^\s+Description:\s+(?P<description>.*)  (?:MTU|Internet)"
    re_description_2 = r"^\s+Description:\s+(?P<description>.*)$"
    re_hardware = r"^.* Hardware: (?P<hardware>\S+)$"

    # Check for 'protocol is ' lines
    match = re.search(re_protocol, interface, flags=re.M)
    if match:
        intf_name = match.group("intf_name")
        status = match.group("status")
        protocol = match.group("protocol")

        if "admin" in status.lower():
            is_enabled = False
        else:
            is_enabled = True
        is_up = bool("up" in protocol)

    else:
        # More standard is up, next line admin state is lines
        match = re.search(re_intf_name_state, interface)
        intf_name = helpers.canonical_interface_name(match.group("intf_name"))
        intf_state = match.group("intf_state").strip()
        is_up = True if intf_state == "up" else False

        admin_state_present = re.search("admin state is", interface)
        if admin_state_present:
            # Parse cases where 'admin state' string exists
            for x_pattern in [re_is_enabled_1, re_is_enabled_2]:
                match = re.search(x_pattern, interface, flags=re.M)
                if match:
                    is_enabled = match.group("is_enabled").strip()
                    is_enabled = True if re.search("up", is_enabled) else False
                    break
            else:
                msg = "Error parsing intf, 'admin state' never detected:\n\n{}".format(
                    interface
                )
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
        mac_address = match.group("mac_address")
        mac_address = helpers.mac(mac_address)
    else:
        mac_address = ""

    match = re.search(re_hardware, interface, flags=re.M)
    speed_exist = True
    if match:
        if match.group("hardware") == "NVE":
            match = re.search(re_mtu_nve, interface, flags=re.M)
            mtu = int(match.group("mtu_nve"))
            speed_exist = False

    if speed_exist:
        match = re.search(re_speed, interface, flags=re.M)
        speed = int(match.group("speed"))
        mtu = int(match.group("mtu"))
        speed_unit = match.group("speed_unit")
        speed_unit = speed_unit.rstrip(",")
        # This was alway in Kbit (in the data I saw)
        if speed_unit != "Kbit":
            msg = "Unexpected speed unit in show interfaces parsing:\n\n{}".format(
                interface
            )
            raise ValueError(msg)
        speed = int(round(speed / 1000.0))
    else:
        speed = -1

    description = ""
    for x_pattern in [re_description_1, re_description_2]:
        match = re.search(x_pattern, interface, flags=re.M)
        if match:
            description = match.group("description")
            break

    return {
        intf_name: {
            "description": description,
            "is_enabled": is_enabled,
            "is_up": is_up,
            "last_flapped": -1.0,
            "mac_address": mac_address,
            "mtu": mtu,
            "speed": speed,
        }
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
    uptime_letters = set(["w", "h", "d"])

    if "never" in bgp_uptime:
        return -1
    elif ":" in bgp_uptime:
        times = bgp_uptime.split(":")
        times = [int(x) for x in times]
        hours, minutes, seconds = times
        return (hours * 3600) + (minutes * 60) + seconds
    # Check if any letters 'w', 'h', 'd' are in the time string
    elif uptime_letters & set(bgp_uptime):
        form1 = r"(\d+)d(\d+)h"  # 1d17h
        form2 = r"(\d+)w(\d+)d"  # 8w5d
        form3 = r"(\d+)y(\d+)w"  # 1y28w
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
    return re.sub(bgp_multiline_pattern, r"\1", bgp_table)


def bgp_table_parser(bgp_table):
    """Generator that parses a line of bgp summary table and returns a dict compatible with NAPALM

    Example line:
    10.2.1.14       4    10  472516  472238      361    0    0     3w1d 9
    """
    bgp_table = bgp_table.strip()
    for bgp_entry in bgp_table.splitlines():
        bgp_table_fields = bgp_entry.split()

        try:
            if re.search(r"Shut.*Admin", bgp_entry):
                (
                    peer_ip,
                    bgp_version,
                    remote_as,
                    msg_rcvd,
                    msg_sent,
                    _,
                    _,
                    _,
                    uptime,
                    state_1,
                    state_2,
                ) = bgp_table_fields
                state_pfxrcd = "{} {}".format(state_1, state_2)
            else:
                (
                    peer_ip,
                    bgp_version,
                    remote_as,
                    msg_rcvd,
                    msg_sent,
                    _,
                    _,
                    _,
                    uptime,
                    state_pfxrcd,
                ) = bgp_table_fields
        except ValueError:
            raise ValueError(
                "Unexpected entry ({}) in BGP summary table".format(bgp_table_fields)
            )

        is_enabled = True
        try:
            received_prefixes = int(state_pfxrcd)
            is_up = True
        except ValueError:
            received_prefixes = -1
            is_up = False
            if re.search(r"Shut.*Admin", state_pfxrcd):
                is_enabled = False

        if not is_up:
            uptime = -1
        if uptime != -1:
            uptime = bgp_time_conversion(uptime)

        yield {
            peer_ip: {
                "is_enabled": is_enabled,
                "uptime": uptime,
                "remote_as": helpers.as_number(remote_as),
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

    allowed_afi = ["ipv4", "ipv6", "l2vpn"]
    vrf_regex = r"^BGP summary information for VRF\s+(?P<vrf>\S+),"
    afi_regex = (
        r"^BGP summary information.*address family (?P<afi>\S+ (?:Unicast|EVPN))"
    )
    local_router_regex = (
        r"^BGP router identifier\s+(?P<router_id>\S+)"
        r",\s+local AS number\s+(?P<local_as>\S+)"
    )

    for pattern in [vrf_regex, afi_regex, local_router_regex]:
        match = re.search(pattern, bgp_summary, flags=re.M)
        if match:
            bgp_summary_dict.update(match.groupdict(1))

    # Some post regex cleanup and validation
    vrf = bgp_summary_dict["vrf"]
    if vrf.lower() == "default":
        bgp_summary_dict["vrf"] = "global"

    afi = bgp_summary_dict["afi"]
    afi = afi.split()[0].lower()
    if afi not in allowed_afi:
        raise ValueError("AFI ({}) is invalid and not supported.".format(afi))
    bgp_summary_dict["afi"] = afi

    local_as = bgp_summary_dict["local_as"]
    local_as = helpers.as_number(local_as)

    match = re.search(IPV4_ADDR_REGEX, bgp_summary_dict["router_id"])
    if not match:
        raise ValueError(
            "BGP router_id ({}) is not valid".format(bgp_summary_dict["router_id"])
        )

    vrf = bgp_summary_dict["vrf"]
    bgp_return_dict = {vrf: {"router_id": bgp_summary_dict["router_id"], "peers": {}}}

    # Extract and process the tabular data
    tabular_divider = r"^Neighbor\s+.*PfxRcd$"
    tabular_data = re.split(tabular_divider, bgp_summary, flags=re.M)
    if len(tabular_data) != 2:
        msg = "Unexpected data processing BGP summary information:\n\n{}".format(
            bgp_summary
        )
        raise ValueError(msg)
    tabular_data = tabular_data[1]
    bgp_table = bgp_normalize_table_data(tabular_data)
    for bgp_entry in bgp_table_parser(bgp_table):
        bgp_return_dict[vrf]["peers"].update(bgp_entry)

    bgp_new_dict = {}
    for neighbor, bgp_data in bgp_return_dict[vrf]["peers"].items():
        received_prefixes = bgp_data.pop("received_prefixes")
        bgp_data["address_family"] = {}
        prefixes_dict = {
            "sent_prefixes": -1,
            "accepted_prefixes": -1,
            "received_prefixes": received_prefixes,
        }
        bgp_data["address_family"][afi] = prefixes_dict
        bgp_data["local_as"] = local_as
        # FIX, hard-coding
        bgp_data["remote_id"] = "0.0.0.0"
        bgp_new_dict[neighbor] = bgp_data

    bgp_return_dict[vrf]["peers"] = bgp_new_dict

    return bgp_return_dict


class NXOSSSHDriver(NXOSDriverBase):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(
            hostname, username, password, timeout=timeout, optional_args=optional_args
        )
        self.platform = "nxos_ssh"

    def open(self):
        self.device = self._netmiko_open(
            device_type="cisco_nxos", netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        self._netmiko_close()

    def _send_command(self, command, raw_text=False, cmd_verify=True):
        """
        Wrapper for Netmiko's send_command method.

        raw_text argument is not used and is for code sharing with NX-API.
        """
        return self.device.send_command(command, cmd_verify=cmd_verify)

    def _send_command_list(self, commands, expect_string=None):
        """Wrapper for Netmiko's send_command method (for list of commands."""
        output = ""
        for command in commands:
            output += self.device.send_command(
                command,
                strip_prompt=False,
                strip_command=False,
                expect_string=expect_string,
            )
        return output

    def _send_config(self, commands):
        if isinstance(commands, str):
            commands = (command for command in commands.splitlines() if command)
        return self.device.send_config_set(commands)

    @staticmethod
    def parse_uptime(uptime_str):
        """
        Extract the uptime string from the given Cisco IOS Device.
        Return the uptime in seconds as an integer
        """
        # Initialize to zero
        (years, weeks, days, hours, minutes) = (0, 0, 0, 0, 0)

        uptime_str = uptime_str.strip()
        time_list = uptime_str.split(",")
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

        uptime_sec = (
            (years * YEAR_SECONDS)
            + (weeks * WEEK_SECONDS)
            + (days * DAY_SECONDS)
            + (hours * 3600)
            + (minutes * 60)
            + seconds
        )
        return uptime_sec

    def is_alive(self):
        """Returns a flag with the state of the SSH connection."""
        null = chr(0)
        try:
            if self.device is None:
                return {"is_alive": False}
            else:
                # Try sending ASCII null byte to maintain the connection alive
                self._send_command(null, cmd_verify=False)
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure that the connection is unusable,
            # hence return False.
            return {"is_alive": False}
        return {"is_alive": self.device.remote_conn.transport.is_active()}

    def _copy_run_start(self):

        output = self.device.save_config()
        if "complete" in output.lower():
            return True
        else:
            msg = "Unable to save running-config to startup-config!"
            raise CommandErrorException(msg)

    def _load_cfg_from_checkpoint(self):

        commands = [
            "terminal dont-ask",
            "rollback running-config file {}".format(self.candidate_cfg),
            "no terminal dont-ask",
        ]

        try:
            rollback_result = self._send_command_list(commands, expect_string=r"[#>]")
        finally:
            self.changed = True
        msg = rollback_result
        if "Rollback failed." in msg:
            raise ReplaceConfigException(msg)

    def rollback(self):
        if self.changed:
            commands = [
                "terminal dont-ask",
                "rollback running-config file {}".format(self.rollback_cfg),
                "no terminal dont-ask",
            ]
            result = self._send_command_list(commands, expect_string=r"[#>]")
            if "completed" not in result.lower():
                raise ReplaceConfigException(result)
            # If hostname changes ensure Netmiko state is updated properly
            self._netmiko_device.set_base_prompt()
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
        seconds = int(uptime_facts["up_days"]) * 24 * 60 * 60
        seconds += int(uptime_facts["up_hours"]) * 60 * 60
        seconds += int(uptime_facts["up_mins"]) * 60
        seconds += int(uptime_facts["up_secs"])
        return seconds

    def get_facts(self):
        """Return a set of facts from the devices."""
        # default values.
        vendor = "Cisco"
        uptime = -1
        serial_number, fqdn, os_version, hostname, domain_name, model = ("",) * 6

        # obtain output from device
        show_ver = self._send_command("show version")
        show_hosts = self._send_command("show hosts")
        show_int_status = self._send_command("show interface status")
        show_hostname = self._send_command("show hostname")

        try:
            show_inventory_table = self._get_command_table(
                "show inventory | json", "TABLE_inv", "ROW_inv"
            )
            if isinstance(show_inventory_table, dict):
                show_inventory_table = [show_inventory_table]

            for row in show_inventory_table:
                if row["name"] == '"Chassis"' or row["name"] == "Chassis":
                    serial_number = row.get("serialnum", "")
                    break
        except ValueError:
            show_inventory = self._send_command("show inventory")
            find_regexp = r"^NAME:\s+\"(.*)\",.*\n^PID:.*SN:\s+(\w*)"
            find = re.findall(find_regexp, show_inventory, re.MULTILINE)
            for row in find:
                if row[0] == "Chassis":
                    serial_number = row[1]
                    break

        # uptime/serial_number/IOS version
        for line in show_ver.splitlines():
            if " uptime is " in line:
                _, uptime_str = line.split(" uptime is ")
                uptime = self.parse_uptime(uptime_str)

            if "system: " in line or "NXOS: " in line:
                line = line.strip()
                os_version = line.split()[2]
                os_version = os_version.strip()

            if "cisco" in line and "hassis" in line:
                match = re.search(r".cisco (.*) \(", line)
                if match:
                    model = match.group(1).strip()
                match = re.search(r".cisco (.* [cC]hassis)", line)
                if match:
                    model = match.group(1).strip()

        hostname = show_hostname.strip()

        # Determine domain_name and fqdn
        for line in show_hosts.splitlines():
            if "Default domain" in line:
                _, domain_name = re.split(r".*Default domain.*is ", line)
                domain_name = domain_name.strip()
                break
        if hostname.count(".") >= 2:
            fqdn = hostname
            # Remove domain name from hostname
            if domain_name:
                hostname = re.sub(re.escape(domain_name) + "$", "", hostname)
                hostname = hostname.strip(".")
        elif domain_name:
            fqdn = "{}.{}".format(hostname, domain_name)

        # interface_list filter
        interface_list = []
        show_int_status = show_int_status.strip()
        # Remove the header information
        show_int_status = re.sub(
            r"(?:^---------+$|^Port .*$|^ .*$)", "", show_int_status, flags=re.M
        )
        for line in show_int_status.splitlines():
            if not line:
                continue
            interface = line.split()[0]
            # Return canonical interface name
            interface_list.append(helpers.canonical_interface_name(interface))

        return {
            "uptime": int(uptime),
            "vendor": vendor,
            "os_version": str(os_version),
            "serial_number": str(serial_number),
            "model": str(model),
            "hostname": str(hostname),
            "fqdn": fqdn,
            "interface_list": interface_list,
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
        interfaces = {}
        command = "show interface"
        output = self._send_command(command)
        if not output:
            return {}

        # Break output into per-interface sections (note, separator text is retained)
        separator1 = r"^\S+\s+is \S+.*\nadmin state is.*$"
        separator2 = r"^.* is .*, line protocol is .*$"
        separator3 = r"^.* is (?:down|up).*$"
        separators = r"({}|{}|{})".format(separator1, separator2, separator3)
        interface_lines = re.split(separators, output, flags=re.M)

        if len(interface_lines) == 1:
            msg = "Unexpected output data in '{}':\n\n{}".format(
                command, interface_lines
            )
            raise ValueError(msg)

        # Get rid of the blank data at the beginning
        interface_lines.pop(0)

        # Must be pairs of data (the separator and section corresponding to it)
        if len(interface_lines) % 2 != 0:
            msg = "Unexpected output data in '{}':\n\n{}".format(
                command, interface_lines
            )
            raise ValueError(msg)

        # Combine the separator and section into one string
        intf_iter = iter(interface_lines)
        try:
            new_interfaces = [line + next(intf_iter, "") for line in intf_iter]
        except TypeError:
            raise ValueError()

        for entry in new_interfaces:
            interfaces.update(parse_intf_section(entry))

        return interfaces

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
        cmd_bgp_all_sum = "show bgp all summary vrf all"
        bgp_summary_output = self._send_command(cmd_bgp_all_sum).strip()

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

    def cli(self, commands):
        cli_output = {}
        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            output = self._send_command(command)
            cli_output[str(command)] = output
        return cli_output

    def get_environment(self):
        """
        Get environment facts.

        power and fan are currently not implemented
        cpu is using 1-minute average
        """

        environment = {}
        # sys_resources contains cpu and mem output
        sys_resources = self._send_command("show system resources")
        temp_cmd = "show environment temperature"

        # cpu
        environment.setdefault("cpu", {})
        environment["cpu"]["0"] = {}
        environment["cpu"]["0"]["%usage"] = -1.0
        system_resources_cpu = helpers.textfsm_extractor(
            self, "system_resources", sys_resources
        )
        for cpu in system_resources_cpu:
            cpu_dict = {
                cpu.get("cpu_id"): {
                    "%usage": round(100 - float(cpu.get("cpu_idle")), 2)
                }
            }
            environment["cpu"].update(cpu_dict)

        # memory
        environment.setdefault("memory", {})
        for line in sys_resources.splitlines():
            # Memory usage:   16401224K total,   4798280K used,   11602944K free
            if "Memory usage:" in line:
                proc_total_mem, proc_used_mem, _ = line.split(",")
                proc_used_mem = re.search(r"\d+", proc_used_mem).group(0)
                proc_total_mem = re.search(r"\d+", proc_total_mem).group(0)
                break
        else:
            raise ValueError("Unexpected output from: {}".format(line))
        environment["memory"]["used_ram"] = int(proc_used_mem)
        environment["memory"]["available_ram"] = int(proc_total_mem)

        # temperature
        output = self._send_command(temp_cmd)
        environment.setdefault("temperature", {})
        for line in output.splitlines():
            # Module   Sensor        MajorThresh   MinorThres   CurTemp     Status
            # 1        Intake          70              42          28         Ok
            if re.match(r"^[0-9]", line):
                module, sensor, is_critical, is_alert, temp, _ = line.split()
                is_critical = float(is_critical)
                is_alert = float(is_alert)
                temp = float(temp)
                env_value = {
                    "is_alert": temp >= is_alert,
                    "is_critical": temp >= is_critical,
                    "temperature": temp,
                }
                location = "{0}-{1}".format(sensor, module)
                environment["temperature"][location] = env_value

        # Initialize 'power' and 'fan' to default values (not implemented)
        environment.setdefault("power", {})
        environment["power"]["invalid"] = {
            "status": True,
            "output": -1.0,
            "capacity": -1.0,
        }
        environment.setdefault("fans", {})
        environment["fans"]["invalid"] = {"status": True}

        return environment

    def get_arp_table(self, vrf=""):
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

        command = "show ip arp vrf {} | exc INCOMPLETE".format(vrf or "all")
        output = self._send_command(command)

        separator = r"^Address\s+Age.*Interface.*$"
        arp_list = re.split(separator, output, flags=re.M)
        if len(arp_list) != 2:
            raise ValueError("Error processing arp table output:\n\n{}".format(output))

        arp_entries = arp_list[1].strip()
        for line in arp_entries.splitlines():
            if len(line.split()) >= 4:
                # Search for extra characters to strip, currently strip '*', '+', '#', 'D'
                line = re.sub(r"\s+[\*\+\#D]{1,4}\s*$", "", line, flags=re.M)
                address, age, mac, interface = line.split()
            else:
                raise ValueError("Unexpected output from: {}".format(line.split()))

            if age == "-":
                age = -1.0
            elif ":" not in age:
                # Cisco sometimes returns a sub second arp time 0.411797
                try:
                    age = float(age)
                except ValueError:
                    age = -1.0
            else:
                age = convert_hhmmss(age)
                age = float(age)
            age = round(age, 1)

            # Validate we matched correctly
            if not re.search(RE_IPADDR, address):
                raise ValueError("Invalid IP Address detected: {}".format(address))
            if not re.search(RE_MAC, mac):
                raise ValueError("Invalid MAC Address detected: {}".format(mac))
            entry = {
                "interface": interface,
                "mac": helpers.mac(mac),
                "ip": address,
                "age": age,
            }
            arp_table.append(entry)
        return arp_table

    def _get_ntp_entity(self, peer_type):
        ntp_entities = {}
        command = "show ntp peers"
        output = self._send_command(command)

        for line in output.splitlines():
            # Skip first two lines and last line of command output
            if line == "" or "-----" in line or "Peer IP Address" in line:
                continue
            elif IPAddress(len(line.split()[0])).is_unicast:
                peer_addr = line.split()[0]
                ntp_entities[peer_addr] = {}
            else:
                raise ValueError("Did not correctly find a Peer IP Address")

        return ntp_entities

    def get_ntp_peers(self):
        return self._get_ntp_entity("Peer")

    def get_ntp_servers(self):
        return self._get_ntp_entity("Server")

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
        ipv4_command = "show ip interface vrf all"
        ipv6_command = "show ipv6 interface vrf all"
        output_v4 = self._send_command(ipv4_command)
        output_v6 = self._send_command(ipv6_command)

        v4_interfaces = {}
        for line in output_v4.splitlines():
            # Ethernet2/2, Interface status: protocol-up/link-up/admin-up, iod: 38,
            # IP address: 2.2.2.2, IP subnet: 2.2.2.0/27 route-preference: 0, tag: 0
            # IP address: 3.3.3.3, IP subnet: 3.3.3.0/25 secondary route-preference: 0, tag: 0
            if "Interface status" in line:
                interface = line.split(",")[0]
                continue
            if "IP address" in line:
                ip_address = line.split(",")[0].split()[2]
                try:
                    prefix_len = int(line.split()[5].split("/")[1])
                except (ValueError, IndexError):
                    prefix_len = "N/A"

                if ip_address == "none":
                    v4_interfaces.setdefault(interface, {})
                else:
                    val = {"prefix_length": prefix_len}
                    v4_interfaces.setdefault(interface, {})[ip_address] = val

        v6_interfaces = {}
        for line in output_v6.splitlines():
            # Ethernet2/4, Interface status: protocol-up/link-up/admin-up, iod: 40
            # IPv6 address:
            #   2001:11:2233::a1/24 [VALID]
            #   2001:cc11:22bb:0:2ec2:60ff:fe4f:feb2/64 [VALID]
            # IPv6 subnet:  2001::/24
            # IPv6 link-local address: fe80::2ec2:60ff:fe4f:feb2 (default) [VALID]
            # IPv6 address: fe80::a293:51ff:fe5f:5ce9 [VALID]
            if "Interface status" in line:
                interface = line.split(",")[0]
                continue
            if "VALID" in line:
                line = line.strip()
                if "link-local address" in line:
                    # match the following format:
                    # IPv6 link-local address: fe80::2ec2:60ff:fe4f:feb2 (default) [VALID]
                    ip_address = line.split()[3]
                    prefix_len = "64"
                elif "IPv6 address" in line:
                    # match the following format:
                    # IPv6 address: fe80::a293:51ff:fe5f:5ce9 [VALID]
                    ip_address = line.split()[2]
                    prefix_len = "64"
                else:
                    ip_address, prefix_len = line.split()[0].split("/")
                prefix_len = int(prefix_len)
                val = {"prefix_length": prefix_len}
                v6_interfaces.setdefault(interface, {})[ip_address] = val
            else:
                # match the following format:
                # IPv6 address: none
                v6_interfaces.setdefault(interface, {})

        # Join data from intermediate dictionaries.
        for interface, data in v4_interfaces.items():
            interfaces_ip.setdefault(interface, {"ipv4": {}})["ipv4"] = data

        for interface, data in v6_interfaces.items():
            interfaces_ip.setdefault(interface, {"ipv6": {}})["ipv6"] = data

        return interfaces_ip

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

        Legend:
        * - primary entry, G - Gateway MAC, (R) - Routed MAC, O - Overlay MAC
        age - seconds since last seen,+ - primary entry using vPC Peer-Link,
        (T) - True, (F) - False
           VLAN     MAC Address      Type      age     Secure NTFY Ports/SWID.SSID.LID
        ---------+-----------------+--------+---------+------+----+------------------
        * 27       0026.f064.0000    dynamic      -       F    F    po1
        * 27       001b.54c2.2644    dynamic      -       F    F    po1
        * 27       0000.0c9f.f2bc    dynamic      -       F    F    po1
        * 27       0026.980a.df44    dynamic      -       F    F    po1
        * 16       0050.56bb.0164    dynamic      -       F    F    po2
        * 13       90e2.ba5a.9f30    dynamic      -       F    F    eth1/2
        * 13       90e2.ba4b.fc78    dynamic      -       F    F    eth1/1
          39       0100.5e00.4b4b    igmp         0       F    F    Po1 Po2 Po22
          110      0100.5e00.0118    igmp         0       F    F    Po1 Po2
                                                                    Eth142/1/3 Eth112/1/5
                                                                    Eth112/1/6 Eth122/1/5

        """

        #  The '*' is stripped out later
        RE_MACTABLE_FORMAT1 = r"^\s+{}\s+{}\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+".format(
            VLAN_REGEX, MAC_REGEX
        )
        RE_MACTABLE_FORMAT2 = r"^\s+{}\s+{}\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+".format(
            "-", MAC_REGEX
        )
        # REGEX dedicated for lines with only interfaces (suite of the previous MAC address)
        RE_MACTABLE_FORMAT3 = r"^\s+\S+"

        mac_address_table = []
        command = "show mac address-table"
        output = self._send_command(command)

        def remove_prefix(s, prefix):
            return s[len(prefix) :] if s.startswith(prefix) else s

        def process_mac_fields(vlan, mac, mac_type, interface):
            """Return proper data for mac address fields."""
            if mac_type.lower() in ["self", "static", "system"]:
                static = True
                if vlan.lower() == "all":
                    vlan = 0
                elif vlan == "-":
                    vlan = 0
                if (
                    interface.lower() == "cpu"
                    or re.search(r"router", interface.lower())
                    or re.search(r"switch", interface.lower())
                ):
                    interface = ""
            else:
                static = False
            if mac_type.lower() in ["dynamic"]:
                active = True
            else:
                active = False
            return {
                "mac": helpers.mac(mac),
                "interface": helpers.canonical_interface_name(interface),
                "vlan": int(vlan),
                "static": static,
                "active": active,
                "moves": -1,
                "last_move": -1.0,
            }

        # Skip the header lines
        output = re.split(r"^----.*", output, flags=re.M)[1:]
        output = "\n".join(output).strip()
        # Strip any leading characters
        output = re.sub(r"^[\*\+GOCE]", "", output, flags=re.M)
        output = re.sub(r"^\(R\)", "", output, flags=re.M)
        output = re.sub(r"^\(T\)", "", output, flags=re.M)
        output = re.sub(r"^\(F\)", "", output, flags=re.M)
        output = re.sub(r"vPC Peer-Link", "vPC-Peer-Link", output, flags=re.M)

        for line in output.splitlines():

            # Every 500 Mac's Legend is reprinted, regardless of terminal length
            if re.search(r"^Legend", line):
                continue
            elif re.search(r"^\s+\* \- primary entry", line):
                continue
            elif re.search(r"^\s+age \-", line):
                continue
            elif re.search(r"^\s+VLAN", line):
                continue
            elif re.search(r"^------", line):
                continue
            elif re.search(r"^\s*$", line):
                continue

            for pattern in [
                RE_MACTABLE_FORMAT1,
                RE_MACTABLE_FORMAT2,
                RE_MACTABLE_FORMAT3,
            ]:
                if re.search(pattern, line):
                    fields = line.split()
                    if len(fields) >= 7:
                        vlan, mac, mac_type, _, _, _, interface = fields[:7]
                        mac_address_table.append(
                            process_mac_fields(vlan, mac, mac_type, interface)
                        )

                        # there can be multiples interfaces for the same MAC on the same line
                        for interface in fields[7:]:
                            mac_address_table.append(
                                process_mac_fields(vlan, mac, mac_type, interface)
                            )
                        break

                    # interfaces can overhang to the next line (line only contains interfaces)
                    elif len(fields) < 7:
                        for interface in fields:
                            mac_address_table.append(
                                process_mac_fields(vlan, mac, mac_type, interface)
                            )
                        break
            else:
                raise ValueError("Unexpected output from: {}".format(repr(line)))

        return mac_address_table

    def _get_bgp_route_attr(self, destination, vrf, next_hop, ip_version=4):
        """
        BGP protocol attributes for get_route_tp
        Only IPv4 supported
        """

        CMD_SHIBNV = 'show ip bgp neighbors vrf {vrf} | include "is {neigh}"'

        search_re_dict = {
            "aspath": {
                "re": r"AS-Path: ([\d\(\)]([\d\(\) ])*)",
                "group": 1,
                "default": "",
            },
            "bgpnh": {
                "re": r"[^|\\n][ ]{4}(" + IP_ADDR_REGEX + r")",
                "group": 1,
                "default": "",
            },
            "bgpfrom": {
                "re": r"from (" + IP_ADDR_REGEX + r")",
                "group": 1,
                "default": "",
            },
            "bgpcomm": {
                "re": r"  Community: ([\w\d\-\: ]+)",
                "group": 1,
                "default": "",
            },
            "bgplp": {"re": r"localpref (\d+)", "group": 1, "default": ""},
            # external, internal, redist
            "bgpie": {"re": r"^: (\w+),", "group": 1, "default": ""},
            "vrfimp": {
                "re": r"Imported from [\S]+ \(VRF (\S+)\)",
                "group": 1,
                "default": "",
            },
        }

        bgp_attr = {}
        # get BGP AS number
        outbgp = self._send_command('show bgp process | include "BGP Protocol Tag"')
        matchbgpattr = RE_BGP_PROTO_TAG.match(outbgp)
        if not matchbgpattr:
            return bgp_attr
        bgpas = matchbgpattr.group(1)
        if ip_version == 4:
            bgpcmd = "show ip bgp vrf {vrf} {destination}".format(
                vrf=vrf, destination=destination
            )
            outbgp = self._send_command(bgpcmd)
            outbgpsec = outbgp.split("Path type")

            # this should not happen (zero BGP paths)...
            if len(outbgpsec) == 1:
                return bgp_attr

            # process all bgp paths
            for bgppath in outbgpsec[1:]:
                if "is best path" not in bgppath:
                    # only best path is added to protocol attributes
                    continue
                # find BGP attributes
                for key in search_re_dict:
                    matchre = re.search(search_re_dict[key]["re"], bgppath)
                    if matchre:
                        groupnr = int(search_re_dict[key]["group"])
                        search_re_dict[key]["result"] = matchre.group(groupnr)
                    else:
                        search_re_dict[key]["result"] = search_re_dict[key]["default"]
                bgpnh = search_re_dict["bgpnh"]["result"]

                # if route is not leaked next hops have to match
                if (
                    not (search_re_dict["bgpie"]["result"] in ["redist", "local"])
                ) and (bgpnh != next_hop):
                    # this is not the right route
                    continue
                # find remote AS nr. of this neighbor
                bgpcmd = CMD_SHIBNV.format(vrf=vrf, neigh=bgpnh)
                outbgpnei = self._send_command(bgpcmd)
                matchbgpras = RE_BGP_REMOTE_AS.search(outbgpnei)
                if matchbgpras:
                    bgpras = matchbgpras.group(1)
                else:
                    # next-hop is not known in this vrf, route leaked from
                    #  other vrf or from vpnv4 table?
                    # get remote AS nr. from as-path if it is ebgp neighbor
                    # if locally sourced remote AS if undefined
                    bgpie = search_re_dict["bgpie"]["result"]
                    if bgpie == "external":
                        bgpras = bgpie.split(" ")[0].replace("(", "")
                    elif bgpie == "internal":
                        bgpras = bgpas
                    else:  # redist, local
                        bgpras = ""
                # community
                bothcomm = []
                extcomm = []
                stdcomm = search_re_dict["bgpcomm"]["result"].split()
                commsplit = bgppath.split("Extcommunity:")
                if len(commsplit) == 2:
                    for line in commsplit[1].split("\n")[1:]:
                        #          RT:65004:22
                        matchcommun = RE_BGP_COMMUN.match(line)
                        if matchcommun:
                            extcomm.append(matchcommun.group(1))
                        else:
                            # we've reached end of the extended community section
                            break
                bothcomm = stdcomm + extcomm
                bgp_attr = {
                    "as_path": search_re_dict["aspath"]["result"].strip(),
                    "remote_address": search_re_dict["bgpfrom"]["result"],
                    "local_preference": int(search_re_dict["bgplp"]["result"]),
                    "communities": bothcomm,
                    "local_as": helpers.as_number(bgpas),
                }
                if bgpras:
                    bgp_attr["remote_as"] = helpers.as_number(bgpras)
                else:
                    bgp_attr["remote_as"] = 0  # 0? , locally sourced
        return bgp_attr

    def get_route_to(self, destination="", protocol="", longer=False):
        """
        Only IPv4 supported, vrf aware, longer_prefixes parameter ready
        """
        if longer:
            raise NotImplementedError("Longer prefixes not yet supported for NXOS")
        longer_pref = ""  # longer_prefixes support, for future use
        vrf = ""

        ip_version = None
        try:
            ip_version = IPNetwork(destination).version
        except AddrFormatError:
            return "Please specify a valid destination!"
        if ip_version == 4:  # process IPv4 routing table
            routes = {}
            if vrf:
                send_cmd = "show ip route vrf {vrf} {destination} {longer}".format(
                    vrf=vrf, destination=destination, longer=longer_pref
                ).rstrip()
            else:
                send_cmd = "show ip route vrf all {destination} {longer}".format(
                    destination=destination, longer=longer_pref
                ).rstrip()
            out_sh_ip_rou = self._send_command(send_cmd)
            # IP Route Table for VRF "TEST"
            for vrfsec in out_sh_ip_rou.split("IP Route Table for ")[1:]:
                if "Route not found" in vrfsec:
                    continue
                vrffound = False
                preffound = False
                nh_list = []
                cur_prefix = ""
                for line in vrfsec.split("\n"):
                    if not vrffound:
                        vrfstr = RE_RT_VRF_NAME.match(line)
                        if vrfstr:
                            curvrf = vrfstr.group(1)
                            vrffound = True
                    else:
                        # 10.10.56.0/24, ubest/mbest: 2/0
                        prefstr = RE_RT_IPV4_ROUTE_PREF.match(line)
                        if prefstr:
                            if preffound:  # precess previous prefix
                                if cur_prefix not in routes:
                                    routes[cur_prefix] = []
                                for nh in nh_list:
                                    routes[cur_prefix].append(nh)
                                nh_list = []
                            else:
                                preffound = True
                            cur_prefix = prefstr.group(1)
                            continue
                        #     *via 10.2.49.60, Vlan3013, [0/0], 1y18w, direct
                        #      via 10.17.205.132, Po77.3602, [110/20], 1y18w, ospf-1000,
                        #            type-2, tag 2112
                        #     *via 10.17.207.42, Eth3/7.212, [110/20], 02:19:36, ospf-1000, type-2,
                        #            tag 2121
                        #     *via 10.17.207.73, [1/0], 1y18w, static
                        #     *via 10.17.209.132%vrf2, Po87.3606, [20/20], 1y25w, bgp-65000,
                        #            external, tag 65000
                        #     *via Vlan596, [1/0], 1y18w, static
                        viastr = RE_IP_ROUTE_VIA_REGEX.match(line)
                        if viastr:
                            nh_used = viastr.group("used") == "*"
                            nh_ip = viastr.group("ip") or ""
                            # when next hop is leaked from other vrf, for future use
                            # nh_vrf = viastr.group('vrf')
                            nh_int = viastr.group("int")
                            nh_metric = viastr.group("metric")
                            nh_age = bgp_time_conversion(viastr.group("age"))
                            nh_source = viastr.group("source")
                            # for future use
                            # rest_of_line = viastr.group('rest')
                            # use only routes from specified protocol
                            if protocol and protocol != nh_source:
                                continue
                            # routing protocol process number, for future use
                            # nh_source_proc_nr = viastr.group('procnr)
                            if nh_int:
                                nh_int_canon = helpers.canonical_interface_name(nh_int)
                            else:
                                nh_int_canon = ""
                            route_entry = {
                                "protocol": nh_source,
                                "outgoing_interface": nh_int_canon,
                                "age": nh_age,
                                "current_active": nh_used,
                                "routing_table": curvrf,
                                "last_active": nh_used,
                                "next_hop": nh_ip,
                                "selected_next_hop": nh_used,
                                "inactive_reason": "",
                                "preference": int(nh_metric),
                            }
                            if nh_source == "bgp":
                                route_entry[
                                    "protocol_attributes"
                                ] = self._get_bgp_route_attr(cur_prefix, curvrf, nh_ip)
                            else:
                                route_entry["protocol_attributes"] = {}
                            nh_list.append(route_entry)
                # process last next hop entries
                if preffound:
                    if cur_prefix not in routes:
                        routes[cur_prefix] = []
                    for nh in nh_list:
                        routes[cur_prefix].append(nh)
        return routes

    def get_snmp_information(self):
        snmp_information = {}
        command = "show running-config"
        output = self._send_command(command)
        snmp_config = helpers.textfsm_extractor(self, "snmp_config", output)

        if not snmp_config:
            return snmp_information

        snmp_information = {
            "contact": str(""),
            "location": str(""),
            "community": {},
            "chassis_id": str(""),
        }

        for snmp_entry in snmp_config:
            contact = str(snmp_entry.get("contact", ""))
            if contact:
                snmp_information["contact"] = contact
            location = str(snmp_entry.get("location", ""))
            if location:
                snmp_information["location"] = location

            community_name = str(snmp_entry.get("community", ""))
            if not community_name:
                continue

            if community_name not in snmp_information["community"].keys():
                snmp_information["community"][community_name] = {
                    "acl": str(snmp_entry.get("acl", "")),
                    "mode": str(snmp_entry.get("mode", "").lower()),
                }
            else:
                acl = str(snmp_entry.get("acl", ""))
                if acl:
                    snmp_information["community"][community_name]["acl"] = acl
                mode = str(snmp_entry.get("mode", "").lower())
                if mode:
                    snmp_information["community"][community_name]["mode"] = mode
        return snmp_information

    def get_users(self):
        _CISCO_TO_CISCO_MAP = {"network-admin": 15, "network-operator": 5}

        _DEFAULT_USER_DICT = {"password": "", "level": 0, "sshkeys": []}

        users = {}
        command = "show running-config"
        output = self._send_command(command)
        section_username_tabled_output = helpers.textfsm_extractor(
            self, "users", output
        )

        for user in section_username_tabled_output:
            username = user.get("username", "")
            if not username:
                continue
            if username not in users:
                users[username] = _DEFAULT_USER_DICT.copy()

            password = user.get("password", "")
            if password:
                users[username]["password"] = str(password.strip())

            level = 0
            role = user.get("role", "")
            if role.startswith("priv"):
                level = int(role.split("-")[-1])
            else:
                level = _CISCO_TO_CISCO_MAP.get(role, 0)
            if level > users.get(username).get("level"):
                # unfortunately on Cisco you can set different priv levels for the same user
                # Good news though: the device will consider the highest level
                users[username]["level"] = level

            sshkeytype = user.get("sshkeytype", "")
            sshkeyvalue = user.get("sshkeyvalue", "")
            if sshkeytype and sshkeyvalue:
                if sshkeytype not in ["ssh-rsa", "ssh-dsa"]:
                    continue
                users[username]["sshkeys"].append(str(sshkeyvalue))
        return users

    def get_vlans(self):
        vlans = {}
        command = "show vlan brief | json"
        vlan_table_raw = self._get_command_table(
            command, "TABLE_vlanbriefxbrief", "ROW_vlanbriefxbrief"
        )
        if isinstance(vlan_table_raw, dict):
            vlan_table_raw = [vlan_table_raw]

        for vlan in vlan_table_raw:
            if "vlanshowplist-ifidx" not in vlan.keys():
                vlan["vlanshowplist-ifidx"] = []
            vlans[vlan["vlanshowbr-vlanid"]] = {
                "name": vlan["vlanshowbr-vlanname"],
                "interfaces": self._parse_vlan_ports(vlan["vlanshowplist-ifidx"]),
            }
        return vlans
