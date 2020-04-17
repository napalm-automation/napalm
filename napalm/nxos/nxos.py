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
import os
import re
import time
import tempfile
import uuid
from collections import defaultdict

# import third party lib
from requests.exceptions import ConnectionError
from netaddr import IPAddress
from netaddr.core import AddrFormatError
from netmiko import file_transfer
from napalm.nxapi_plumbing import Device as NXOSDevice
from napalm.nxapi_plumbing import (
    NXAPIAuthError,
    NXAPIConnectionError,
    NXAPICommandError,
)
import json

# import NAPALM Base
import napalm.base.helpers
from napalm.base import NetworkDriver
from napalm.base.exceptions import ConnectionException
from napalm.base.exceptions import MergeConfigException
from napalm.base.exceptions import CommandErrorException
from napalm.base.exceptions import ReplaceConfigException
from napalm.base.netmiko_helpers import netmiko_args
import napalm.base.constants as c


def ensure_netmiko_conn(func):
    """Decorator that ensures Netmiko connection exists."""

    def wrap_function(self, filename=None, config=None):
        try:
            netmiko_object = self._netmiko_device
            if netmiko_object is None:
                raise AttributeError()
        except AttributeError:
            device_type = c.NETMIKO_MAP[self.platform]
            netmiko_optional_args = self.netmiko_optional_args
            if "port" in netmiko_optional_args:
                netmiko_optional_args["port"] = 22
            self._netmiko_open(
                device_type=device_type, netmiko_optional_args=netmiko_optional_args
            )
        func(self, filename=filename, config=config)

    return wrap_function


class NXOSDriverBase(NetworkDriver):
    """Common code shared between nx-api and nxos_ssh."""

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
        self.merge_candidate = ""
        self.candidate_cfg = "candidate_config.txt"
        self.rollback_cfg = "rollback_config.txt"
        self._dest_file_system = optional_args.pop("dest_file_system", "bootflash:")
        self.force_no_enable = optional_args.get("force_no_enable", False)
        self.netmiko_optional_args = netmiko_args(optional_args)
        self.device = None

    @ensure_netmiko_conn
    def load_replace_candidate(self, filename=None, config=None):

        if not filename and not config:
            raise ReplaceConfigException(
                "filename or config parameter must be provided."
            )

        if not filename:
            tmp_file = self._create_tmp_file(config)
            filename = tmp_file
        else:
            if not os.path.isfile(filename):
                raise ReplaceConfigException("File {} not found".format(filename))

        try:
            transfer_result = file_transfer(
                self._netmiko_device,
                source_file=filename,
                dest_file=self.candidate_cfg,
                file_system=self._dest_file_system,
                direction="put",
                overwrite_file=True,
            )
            if not transfer_result["file_exists"]:
                raise ValueError()
        except Exception:
            msg = (
                "Could not transfer file. There was an error "
                "during transfer. Please make sure remote "
                "permissions are set."
            )
            raise ReplaceConfigException(msg)

        self.replace = True
        self.loaded = True
        if config and os.path.isfile(tmp_file):
            os.remove(tmp_file)

    def load_merge_candidate(self, filename=None, config=None):
        if not filename and not config:
            raise MergeConfigException("filename or config param must be provided.")

        self.merge_candidate += "\n"  # insert one extra line
        if filename is not None:
            with open(filename, "r") as f:
                self.merge_candidate += f.read()
        else:
            self.merge_candidate += config
        self.replace = False
        self.loaded = True

    def _send_command(self, command, raw_text=False):
        raise NotImplementedError

    def _commit_merge(self):
        try:
            output = self._send_config(self.merge_candidate)
            if output and "Invalid command" in output:
                raise MergeConfigException("Error while applying config!")
        except Exception as e:
            self.changed = True
            self.rollback()
            err_header = "Configuration merge failed; automatic rollback attempted"
            merge_error = "{0}:\n{1}".format(err_header, repr(str(e)))
            raise MergeConfigException(merge_error)

        self.changed = True
        # clear the merge buffer
        self.merge_candidate = ""

    def _get_merge_diff(self):
        """
        The merge diff is not necessarily what needs to be loaded
        for example under NTP, even though the 'ntp commit' command might be
        alread configured, it is mandatory to be sent
        otherwise it won't take the new configuration - see:
        https://github.com/napalm-automation/napalm-nxos/issues/59
        therefore this method will return the real diff (but not necessarily what is
        being sent by the merge_load_config()
        """
        diff = []
        running_config = self.get_config(retrieve="running")["running"]
        running_lines = running_config.splitlines()
        for line in self.merge_candidate.splitlines():
            if line not in running_lines and line:
                if line[0].strip() != "!":
                    diff.append(line)
        return "\n".join(diff)

    def _get_diff(self):
        """Get a diff between running config and a proposed file."""
        diff = []
        self._create_sot_file()
        diff_out = self._send_command(
            "show diff rollback-patch file {} file {}".format(
                "sot_file", self.candidate_cfg
            ),
            raw_text=True,
        )
        try:
            diff_out = (
                diff_out.split("Generating Rollback Patch")[1]
                .replace("Rollback Patch is Empty", "")
                .strip()
            )
            for line in diff_out.splitlines():
                if line:
                    if line[0].strip() != "!" and line[0].strip() != ".":
                        diff.append(line.rstrip(" "))
        except (AttributeError, KeyError):
            raise ReplaceConfigException(
                "Could not calculate diff. It's possible the given file doesn't exist."
            )
        return "\n".join(diff)

    def compare_config(self):
        if self.loaded:
            if not self.replace:
                return self._get_merge_diff()
            diff = self._get_diff()
            return diff
        return ""

    def commit_config(self, message=""):
        if message:
            raise NotImplementedError(
                "Commit message not implemented for this platform"
            )
        if self.loaded:
            # Create checkpoint from current running-config
            self._save_to_checkpoint(self.rollback_cfg)

            if self.replace:
                self._load_cfg_from_checkpoint()
            else:
                self._commit_merge()

            try:
                # If hostname changes ensure Netmiko state is updated properly
                self._netmiko_device.set_base_prompt()
            except AttributeError:
                pass

            self._copy_run_start()
            self.loaded = False
        else:
            raise ReplaceConfigException("No config loaded.")

    def discard_config(self):
        if self.loaded:
            # clear the buffer
            self.merge_candidate = ""
        if self.loaded and self.replace:
            self._delete_file(self.candidate_cfg)
        self.loaded = False

    def _create_sot_file(self):
        """Create Source of Truth file to compare."""

        # Bug on on NX-OS 6.2.16 where overwriting sot_file would take exceptionally long time
        # (over 12 minutes); so just delete the sot_file
        try:
            self._delete_file(filename="sot_file")
        except Exception:
            pass
        commands = [
            "terminal dont-ask",
            "checkpoint file sot_file",
            "no terminal dont-ask",
        ]
        self._send_command_list(commands)

    def ping(
        self,
        destination,
        source=c.PING_SOURCE,
        ttl=c.PING_TTL,
        timeout=c.PING_TIMEOUT,
        size=c.PING_SIZE,
        count=c.PING_COUNT,
        vrf=c.PING_VRF,
    ):
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

        version = ""
        try:
            version = "6" if IPAddress(destination).version == 6 else ""
        except AddrFormatError:
            # Allow use of DNS names
            pass

        command = "ping{version} {destination}".format(
            version=version, destination=destination
        )
        command += " timeout {}".format(timeout)
        command += " packet-size {}".format(size)
        command += " count {}".format(count)
        if source != "":
            command += " source {}".format(source)

        if vrf != "":
            command += " vrf {}".format(vrf)
        output = self._send_command(command, raw_text=True)

        if "connect:" in output:
            ping_dict["error"] = output
        elif "PING" in output:
            ping_dict["success"] = {
                "probes_sent": 0,
                "packet_loss": 0,
                "rtt_min": 0.0,
                "rtt_max": 0.0,
                "rtt_avg": 0.0,
                "rtt_stddev": 0.0,
                "results": [],
            }
            results_array = []
            for line in output.splitlines():
                fields = line.split()
                if "icmp" in line:
                    if "Unreachable" in line:
                        if "(" in fields[2]:
                            results_array.append(
                                {"ip_address": str(fields[2][1:-1]), "rtt": 0.0}
                            )
                        else:
                            results_array.append(
                                {"ip_address": str(fields[1]), "rtt": 0.0}
                            )
                    elif "truncated" in line:
                        if "(" in fields[4]:
                            results_array.append(
                                {"ip_address": str(fields[4][1:-2]), "rtt": 0.0}
                            )
                        else:
                            results_array.append(
                                {"ip_address": str(fields[3][:-1]), "rtt": 0.0}
                            )
                    elif fields[1] == "bytes":
                        if version == "6":
                            m = fields[5][5:]
                        else:
                            m = fields[6][5:]
                        results_array.append(
                            {"ip_address": str(fields[3][:-1]), "rtt": float(m)}
                        )
                elif "packets transmitted" in line:
                    ping_dict["success"]["probes_sent"] = int(fields[0])
                    ping_dict["success"]["packet_loss"] = int(fields[0]) - int(
                        fields[3]
                    )
                elif "min/avg/max" in line:
                    m = fields[3].split("/")
                    ping_dict["success"].update(
                        {
                            "rtt_min": float(m[0]),
                            "rtt_avg": float(m[1]),
                            "rtt_max": float(m[2]),
                        }
                    )
            ping_dict["success"].update({"results": results_array})
        return ping_dict

    def traceroute(
        self,
        destination,
        source=c.TRACEROUTE_SOURCE,
        ttl=c.TRACEROUTE_TTL,
        timeout=c.TRACEROUTE_TIMEOUT,
        vrf=c.TRACEROUTE_VRF,
    ):

        _HOP_ENTRY_PROBE = [
            r"\s+",
            r"(",  # beginning of host_name (ip_address) RTT group
            r"(",  # beginning of host_name (ip_address) group only
            r"([a-zA-Z0-9\.:-]*)",  # hostname
            r"\s+",
            r"\(?([a-fA-F0-9\.:][^\)]*)\)?",  # IP Address between brackets
            r"(?:\s+\(AS\s+[0-9]+\))?",  # AS number -- may or may not be present
            r")?",  # end of host_name (ip_address) group only
            # also hostname/ip are optional -- they can or cannot be specified
            # if not specified, means the current probe followed the same path as the previous
            r"\s+",
            r"(\d+\.\d+)\s+ms",  # RTT
            r"|\*",  # OR *, when non responsive hop
            r")",  # end of host_name (ip_address) RTT group
        ]

        _HOP_ENTRY = [r"\s?", r"(\d+)"]  # space before hop index?  # hop index

        traceroute_result = {}
        timeout = 5  # seconds
        probes = 3  # 3 probes/jop and this cannot be changed on NXOS!

        version = ""
        try:
            version = "6" if IPAddress(destination).version == 6 else ""
        except AddrFormatError:
            # Allow use of DNS names
            pass

        if source:
            source_opt = "source {source}".format(source=source)
            command = "traceroute{version} {destination} {source_opt}".format(
                version=version, destination=destination, source_opt=source_opt
            )
        else:
            command = "traceroute{version} {destination}".format(
                version=version, destination=destination
            )

        if vrf != "":
            command += " vrf {vrf}".format(vrf=vrf)

        try:
            traceroute_raw_output = self._send_command(command, raw_text=True)
        except CommandErrorException:
            return {
                "error": "Cannot execute traceroute on the device: {}".format(command)
            }

        hop_regex = "".join(_HOP_ENTRY + _HOP_ENTRY_PROBE * probes)
        traceroute_result["success"] = {}
        if traceroute_raw_output:
            for line in traceroute_raw_output.splitlines():
                hop_search = re.search(hop_regex, line)
                if not hop_search:
                    continue
                hop_details = hop_search.groups()
                hop_index = int(hop_details[0])
                previous_probe_host_name = "*"
                previous_probe_ip_address = "*"
                traceroute_result["success"][hop_index] = {"probes": {}}
                for probe_index in range(probes):
                    host_name = hop_details[3 + probe_index * 5]
                    ip_address_raw = hop_details[4 + probe_index * 5]
                    ip_address = napalm.base.helpers.convert(
                        napalm.base.helpers.ip, ip_address_raw, ip_address_raw
                    )
                    rtt = hop_details[5 + probe_index * 5]
                    if rtt:
                        rtt = float(rtt)
                    else:
                        rtt = timeout * 1000.0
                    if not host_name:
                        host_name = previous_probe_host_name
                    if not ip_address:
                        ip_address = previous_probe_ip_address
                    if hop_details[1 + probe_index * 5] == "*":
                        host_name = "*"
                        ip_address = "*"
                    traceroute_result["success"][hop_index]["probes"][
                        probe_index + 1
                    ] = {
                        "host_name": str(host_name),
                        "ip_address": str(ip_address),
                        "rtt": rtt,
                    }
                    previous_probe_host_name = host_name
                    previous_probe_ip_address = ip_address
        return traceroute_result

    def _get_checkpoint_file(self):
        filename = "temp_cp_file_from_napalm"
        self._set_checkpoint(filename)
        command = "show file {}".format(filename)
        output = self._send_command(command, raw_text=True)
        self._delete_file(filename)
        return output

    def _set_checkpoint(self, filename):
        commands = [
            "terminal dont-ask",
            "checkpoint file {}".format(filename),
            "no terminal dont-ask",
        ]
        self._send_command_list(commands)

    def _save_to_checkpoint(self, filename):
        """Save the current running config to the given file."""
        commands = [
            "terminal dont-ask",
            "checkpoint file {}".format(filename),
            "no terminal dont-ask",
        ]
        self._send_command_list(commands)

    def _delete_file(self, filename):
        commands = [
            "terminal dont-ask",
            "delete {}".format(filename),
            "no terminal dont-ask",
        ]
        self._send_command_list(commands)

    @staticmethod
    def _create_tmp_file(config):
        tmp_dir = tempfile.gettempdir()
        rand_fname = str(uuid.uuid4())
        filename = os.path.join(tmp_dir, rand_fname)
        with open(filename, "wt") as fobj:
            fobj.write(config)
        return filename

    def _disable_confirmation(self):
        self._send_command_list(["terminal dont-ask"])

    def get_config(self, retrieve="all", full=False):
        config = {"startup": "", "running": "", "candidate": ""}  # default values
        # NX-OS only supports "all" on "show run"
        run_full = " all" if full else ""

        if retrieve.lower() in ("running", "all"):
            command = f"show running-config{run_full}"
            config["running"] = str(self._send_command(command, raw_text=True))
        if retrieve.lower() in ("startup", "all"):
            command = "show startup-config"
            config["startup"] = str(self._send_command(command, raw_text=True))
        return config

    def get_lldp_neighbors(self):
        """IOS implementation of get_lldp_neighbors."""
        lldp = {}
        neighbors_detail = self.get_lldp_neighbors_detail()
        for intf_name, entries in neighbors_detail.items():
            lldp[intf_name] = []
            for lldp_entry in entries:
                hostname = lldp_entry["remote_system_name"]
                # Match IOS behaviour of taking remote chassis ID
                # When lacking a system name (in show lldp neighbors)
                if hostname == "N/A":
                    hostname = lldp_entry["remote_chassis_id"]
                lldp_dict = {"port": lldp_entry["remote_port"], "hostname": hostname}
                lldp[intf_name].append(lldp_dict)

        return lldp

    def get_lldp_neighbors_detail(self, interface=""):
        lldp = {}
        lldp_interfaces = []

        if interface:
            command = "show lldp neighbors interface {} detail".format(interface)
        else:
            command = "show lldp neighbors detail"
        lldp_entries = self._send_command(command, raw_text=True)
        lldp_entries = str(lldp_entries)
        lldp_entries = napalm.base.helpers.textfsm_extractor(
            self, "show_lldp_neighbors_detail", lldp_entries
        )

        if len(lldp_entries) == 0:
            return {}

        for idx, lldp_entry in enumerate(lldp_entries):
            local_intf = lldp_entry.pop("local_interface") or lldp_interfaces[idx]
            # Convert any 'not advertised' to an empty string
            for field in lldp_entry:
                if "not advertised" in lldp_entry[field]:
                    lldp_entry[field] = ""
            # Add field missing on IOS
            lldp_entry["parent_interface"] = ""
            # Translate the capability fields
            lldp_entry[
                "remote_system_capab"
            ] = napalm.base.helpers.transform_lldp_capab(
                lldp_entry["remote_system_capab"]
            )
            lldp_entry[
                "remote_system_enable_capab"
            ] = napalm.base.helpers.transform_lldp_capab(
                lldp_entry["remote_system_enable_capab"]
            )
            # Turn the interfaces into their long version
            local_intf = napalm.base.helpers.canonical_interface_name(local_intf)
            lldp.setdefault(local_intf, [])
            lldp[local_intf].append(lldp_entry)

        return lldp

    @staticmethod
    def _get_table_rows(parent_table, table_name, row_name):
        """
        Inconsistent behavior:
        {'TABLE_intf': [{'ROW_intf': {
        vs
        {'TABLE_mac_address': {'ROW_mac_address': [{
        vs
        {'TABLE_vrf': {'ROW_vrf': {'TABLE_adj': {'ROW_adj': {
        """
        if parent_table is None:
            return []
        _table = parent_table.get(table_name)
        _table_rows = []
        if isinstance(_table, list):
            _table_rows = [_table_row.get(row_name) for _table_row in _table]
        elif isinstance(_table, dict):
            _table_rows = _table.get(row_name)
        if not isinstance(_table_rows, list):
            _table_rows = [_table_rows]
        return _table_rows

    def _get_reply_table(self, result, table_name, row_name):
        return self._get_table_rows(result, table_name, row_name)

    def _get_command_table(self, command, table_name, row_name):
        json_output = self._send_command(command)
        if type(json_output) is not dict and json_output:
            json_output = json.loads(json_output)
        return self._get_reply_table(json_output, table_name, row_name)

    def _parse_vlan_ports(self, vlan_s):
        vlans = []
        find_regexp = r"^([A-Za-z\/-]+|.*\/)(\d+)-(\d+)$"
        vlan_str = ""

        if isinstance(vlan_s, list):
            vlan_str = ",".join(vlan_s)
        else:
            vlan_str = vlan_s

        for vls in vlan_str.split(","):
            find = re.findall(find_regexp, vls.strip())
            if find:
                for i in range(int(find[0][1]), int(find[0][2]) + 1):
                    vlans.append(find[0][0] + str(i))
            else:
                vlans.append(vls.strip())
        return vlans


class NXOSDriver(NXOSDriverBase):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(
            hostname, username, password, timeout=timeout, optional_args=optional_args
        )
        if optional_args is None:
            optional_args = {}

        # nxos_protocol is there for backwards compatibility, transport is the preferred method
        self.transport = optional_args.get(
            "transport", optional_args.get("nxos_protocol", "https")
        )
        if self.transport == "https":
            self.port = optional_args.get("port", 443)
        elif self.transport == "http":
            self.port = optional_args.get("port", 80)

        self.ssl_verify = optional_args.get("ssl_verify", False)
        self.platform = "nxos"

    def open(self):
        try:
            self.device = NXOSDevice(
                host=self.hostname,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=self.port,
                transport=self.transport,
                verify=self.ssl_verify,
                api_format="jsonrpc",
            )
            self._send_command("show hostname")
        except (NXAPIConnectionError, NXAPIAuthError):
            # unable to open connection
            raise ConnectionException("Cannot connect to {}".format(self.hostname))

    def close(self):
        self.device = None

    def _send_command(self, command, raw_text=False):
        """
        Wrapper for NX-API show method.

        Allows more code sharing between NX-API and SSH.
        """
        return self.device.show(command, raw_text=raw_text)

    def _send_command_list(self, commands):
        return self.device.config_list(commands)

    def _send_config(self, commands):
        if isinstance(commands, str):
            # Has to be a list generator and not generator expression (not JSON serializable)
            commands = [command for command in commands.splitlines() if command]
        return self.device.config_list(commands)

    @staticmethod
    def _compute_timestamp(stupid_cisco_output):
        """
        Some fields such `uptime` are returned as: 23week(s) 3day(s)
        This method will determine the epoch of the event.
        e.g.: 23week(s) 3day(s) -> 1462248287
        """
        if not stupid_cisco_output or stupid_cisco_output == "never":
            return -1.0

        if "(s)" in stupid_cisco_output:
            pass
        elif ":" in stupid_cisco_output:
            stupid_cisco_output = stupid_cisco_output.replace(":", "hour(s) ", 1)
            stupid_cisco_output = stupid_cisco_output.replace(":", "minute(s) ", 1)
            stupid_cisco_output += "second(s)"
        else:
            stupid_cisco_output = stupid_cisco_output.replace("d", "day(s) ")
            stupid_cisco_output = stupid_cisco_output.replace("h", "hour(s)")

        things = {
            "second(s)": {"weight": 1},
            "minute(s)": {"weight": 60},
            "hour(s)": {"weight": 3600},
            "day(s)": {"weight": 24 * 3600},
            "week(s)": {"weight": 7 * 24 * 3600},
            "year(s)": {"weight": 365.25 * 24 * 3600},
        }

        things_keys = things.keys()
        for part in stupid_cisco_output.split():
            for key in things_keys:
                if key in part:
                    things[key]["count"] = napalm.base.helpers.convert(
                        int, part.replace(key, ""), 0
                    )

        delta = sum(
            [det.get("count", 0) * det.get("weight") for det in things.values()]
        )
        return time.time() - delta

    def is_alive(self):
        if self.device:
            return {"is_alive": True}
        else:
            return {"is_alive": False}

    def _copy_run_start(self):
        results = self.device.save(filename="startup-config")
        if not results:
            msg = "Unable to save running-config to startup-config!"
            raise CommandErrorException(msg)

    def _load_cfg_from_checkpoint(self):
        commands = [
            "terminal dont-ask",
            "rollback running-config file {}".format(self.candidate_cfg),
            "no terminal dont-ask",
        ]
        try:
            rollback_result = self._send_command_list(commands)
        except ConnectionError:
            # requests will raise an error with verbose warning output (don't fail on this).
            return
        finally:
            self.changed = True

        # For nx-api a list is returned so extract the result associated with the
        # 'rollback' command.
        rollback_result = rollback_result[1]
        msg = (
            rollback_result.get("msg")
            if rollback_result.get("msg")
            else rollback_result
        )
        error_msg = True if rollback_result.get("error") else False

        if "Rollback failed." in msg or error_msg:
            raise ReplaceConfigException(msg)
        elif rollback_result == []:
            raise ReplaceConfigException

    def rollback(self):
        if self.changed:
            self.device.rollback(self.rollback_cfg)
            self._copy_run_start()
            self.changed = False

    def get_facts(self):
        facts = {}
        facts["vendor"] = "Cisco"

        show_inventory_table = self._get_command_table(
            "show inventory", "TABLE_inv", "ROW_inv"
        )
        if isinstance(show_inventory_table, dict):
            show_inventory_table = [show_inventory_table]

        facts["serial_number"] = None

        for row in show_inventory_table:
            if row["name"] == '"Chassis"' or row["name"] == "Chassis":
                facts["serial_number"] = row.get("serialnum", "")
                break

        show_version = self._send_command("show version")
        facts["model"] = show_version.get("chassis_id", "")
        facts["hostname"] = show_version.get("host_name", "")
        facts["os_version"] = show_version.get(
            "sys_ver_str", show_version.get("kickstart_ver_str", "")
        )

        uptime_days = show_version.get("kern_uptm_days", 0)
        uptime_hours = show_version.get("kern_uptm_hrs", 0)
        uptime_mins = show_version.get("kern_uptm_mins", 0)
        uptime_secs = show_version.get("kern_uptm_secs", 0)

        uptime = 0
        uptime += uptime_days * 24 * 60 * 60
        uptime += uptime_hours * 60 * 60
        uptime += uptime_mins * 60
        uptime += uptime_secs

        facts["uptime"] = uptime

        iface_cmd = "show interface"
        interfaces_out = self._send_command(iface_cmd)
        interfaces_body = interfaces_out["TABLE_interface"]["ROW_interface"]
        interface_list = [intf_data["interface"] for intf_data in interfaces_body]
        facts["interface_list"] = interface_list

        hostname_cmd = "show hostname"
        hostname = self._send_command(hostname_cmd).get("hostname")
        if hostname:
            facts["fqdn"] = hostname

        return facts

    def get_interfaces(self):
        interfaces = {}
        iface_cmd = "show interface"
        interfaces_out = self._send_command(iface_cmd)
        interfaces_body = interfaces_out["TABLE_interface"]["ROW_interface"]

        for interface_details in interfaces_body:
            interface_name = interface_details.get("interface")

            if interface_details.get("eth_mtu"):
                interface_mtu = int(interface_details["eth_mtu"])
            elif interface_details.get("svi_mtu"):
                interface_mtu = int(interface_details["svi_mtu"])
            else:
                interface_mtu = 0

            # Earlier version of Nexus returned a list for 'eth_bw' (observed on 7.1(0)N1(1a))
            if interface_details.get("eth_bw"):
                interface_speed = interface_details["eth_bw"]
            elif interface_details.get("svi_bw"):
                interface_speed = interface_details["svi_bw"]
            else:
                interface_speed = 0
            if isinstance(interface_speed, list):
                interface_speed = interface_speed[0]
            interface_speed = int(int(interface_speed) / 1000)

            if "admin_state" in interface_details:
                is_up = interface_details.get("admin_state", "") == "up"
            elif "svi_admin_state" in interface_details:
                is_up = interface_details.get("svi_admin_state", "") == "up"
            else:
                is_up = interface_details.get("state", "") == "up"
            if interface_details.get("eth_hw_addr"):
                mac_address = interface_details["eth_hw_addr"]
            elif interface_details.get("svi_mac"):
                mac_address = interface_details["svi_mac"].strip()
            else:
                mac_address = None
            interfaces[interface_name] = {
                "is_up": is_up,
                "is_enabled": (
                    interface_details.get("state") == "up"
                    or interface_details.get("svi_admin_state") == "up"
                ),
                "description": str(interface_details.get("desc", "").strip('"')),
                "last_flapped": self._compute_timestamp(
                    interface_details.get("eth_link_flapped", "")
                ),
                "speed": interface_speed,
                "mtu": interface_mtu,
                "mac_address": napalm.base.helpers.convert(
                    napalm.base.helpers.mac, mac_address
                ),
            }
        return interfaces

    def get_bgp_neighbors(self):
        results = {}
        bgp_state_dict = {
            "Idle": {"is_up": False, "is_enabled": True},
            "Active": {"is_up": False, "is_enabled": True},
            "Open": {"is_up": False, "is_enabled": True},
            "Established": {"is_up": True, "is_enabled": True},
            "Closing": {"is_up": True, "is_enabled": True},
            "Shutdown": {"is_up": False, "is_enabled": False},
        }
        """
        af_name_dict = {
            'af-id': {'safi': "af-name"},
            'af-id': {'safi': "af-name"},
            'af-id': {'safi': "af-name"}
        }
        """
        af_name_dict = {
            1: {1: "ipv4", 128: "vpnv4"},
            2: {1: "ipv6", 128: "vpnv6"},
            25: {70: "l2vpn"},
        }

        try:
            cmd = "show bgp all summary vrf all"
            vrf_list = self._get_command_table(cmd, "TABLE_vrf", "ROW_vrf")
        except NXAPICommandError:
            vrf_list = []

        for vrf_dict in vrf_list:
            result_vrf_dict = {"router_id": str(vrf_dict["vrf-router-id"]), "peers": {}}

            af_list = vrf_dict.get("TABLE_af", {}).get("ROW_af", [])
            if isinstance(af_list, dict):
                af_list = [af_list]

            for af_dict in af_list:
                saf_dict = af_dict.get("TABLE_saf", {}).get("ROW_saf", {})
                neighbors_list = saf_dict.get("TABLE_neighbor", {}).get(
                    "ROW_neighbor", []
                )

                if isinstance(neighbors_list, dict):
                    neighbors_list = [neighbors_list]

                for neighbor_dict in neighbors_list:
                    neighborid = napalm.base.helpers.ip(neighbor_dict["neighborid"])
                    remoteas = napalm.base.helpers.as_number(
                        neighbor_dict["neighboras"]
                    )
                    state = str(neighbor_dict["state"])

                    bgp_state = bgp_state_dict[state]
                    afid_dict = af_name_dict[int(af_dict["af-id"])]
                    safi_name = afid_dict[int(saf_dict["safi"])]

                    result_peer_dict = {
                        "local_as": int(vrf_dict["vrf-local-as"]),
                        "remote_as": remoteas,
                        "remote_id": neighborid,
                        "is_enabled": bgp_state["is_enabled"],
                        "uptime": -1,
                        "description": "",
                        "is_up": bgp_state["is_up"],
                        "address_family": {
                            safi_name: {
                                "sent_prefixes": -1,
                                "accepted_prefixes": -1,
                                "received_prefixes": int(
                                    neighbor_dict["prefixreceived"]
                                ),
                            }
                        },
                    }
                    result_vrf_dict["peers"][neighborid] = result_peer_dict

            vrf_name = vrf_dict["vrf-name-out"]
            if vrf_name == "default":
                vrf_name = "global"
            results[vrf_name] = result_vrf_dict
        return results

    def cli(self, commands):
        cli_output = {}
        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            command_output = self._send_command(command, raw_text=True)
            cli_output[str(command)] = command_output
        return cli_output

    def get_arp_table(self, vrf=""):
        if vrf:
            msg = "VRF support has not been added for this getter on this platform."
            raise NotImplementedError(msg)

        arp_table = []
        command = "show ip arp"
        arp_table_vrf = self._get_command_table(command, "TABLE_vrf", "ROW_vrf")
        arp_table_raw = self._get_table_rows(arp_table_vrf[0], "TABLE_adj", "ROW_adj")

        for arp_table_entry in arp_table_raw:
            raw_ip = arp_table_entry.get("ip-addr-out")
            raw_mac = arp_table_entry.get("mac")
            age = arp_table_entry.get("time-stamp")
            if age == "-":
                age_sec = -1.0
            elif ":" not in age:
                # Cisco sometimes returns a sub second arp time 0.411797
                try:
                    age_sec = float(age)
                except ValueError:
                    age_sec = -1.0
            else:
                fields = age.split(":")
                if len(fields) == 3:
                    try:
                        fields = [float(x) for x in fields]
                        hours, minutes, seconds = fields
                        age_sec = 3600 * hours + 60 * minutes + seconds
                    except ValueError:
                        age_sec = -1.0
            age_sec = round(age_sec, 1)

            interface = str(arp_table_entry.get("intf-out"))
            arp_table.append(
                {
                    "interface": interface,
                    "mac": napalm.base.helpers.convert(
                        napalm.base.helpers.mac, raw_mac, raw_mac
                    ),
                    "ip": napalm.base.helpers.ip(raw_ip),
                    "age": age_sec,
                }
            )
        return arp_table

    def _get_ntp_entity(self, peer_type):
        ntp_entities = {}
        command = "show ntp peers"
        ntp_peers_table = self._get_command_table(command, "TABLE_peers", "ROW_peers")

        for ntp_peer in ntp_peers_table:
            if ntp_peer.get("serv_peer", "").strip() != peer_type:
                continue
            peer_addr = napalm.base.helpers.ip(ntp_peer.get("PeerIPAddress").strip())
            ntp_entities[peer_addr] = {}

        return ntp_entities

    def get_ntp_peers(self):
        return self._get_ntp_entity("Peer")

    def get_ntp_servers(self):
        return self._get_ntp_entity("Server")

    def get_ntp_stats(self):
        ntp_stats = []
        command = "show ntp peer-status"
        ntp_stats_table = self._get_command_table(
            command, "TABLE_peersstatus", "ROW_peersstatus"
        )

        for ntp_peer in ntp_stats_table:
            peer_address = napalm.base.helpers.ip(ntp_peer.get("remote").strip())
            syncmode = ntp_peer.get("syncmode")
            stratum = int(ntp_peer.get("st"))
            hostpoll = int(ntp_peer.get("poll"))
            reachability = int(ntp_peer.get("reach"))
            delay = float(ntp_peer.get("delay"))
            ntp_stats.append(
                {
                    "remote": peer_address,
                    "synchronized": (syncmode == "*"),
                    "referenceid": peer_address,
                    "stratum": stratum,
                    "type": "",
                    "when": "",
                    "hostpoll": hostpoll,
                    "reachability": reachability,
                    "delay": delay,
                    "offset": 0.0,
                    "jitter": 0.0,
                }
            )
        return ntp_stats

    def get_interfaces_ip(self):
        interfaces_ip = {}
        ipv4_command = "show ip interface"
        ipv4_interf_table_vrf = self._get_command_table(
            ipv4_command, "TABLE_intf", "ROW_intf"
        )

        for interface in ipv4_interf_table_vrf:
            interface_name = str(interface.get("intf-name", ""))
            addr_str = interface.get("prefix")
            unnumbered = str(interface.get("unnum-intf", ""))
            if addr_str:
                address = napalm.base.helpers.ip(addr_str)
                prefix = int(interface.get("masklen", ""))
                if interface_name not in interfaces_ip.keys():
                    interfaces_ip[interface_name] = {}
                if "ipv4" not in interfaces_ip[interface_name].keys():
                    interfaces_ip[interface_name]["ipv4"] = {}
                if address not in interfaces_ip[interface_name].get("ipv4"):
                    interfaces_ip[interface_name]["ipv4"][address] = {}
                interfaces_ip[interface_name]["ipv4"][address].update(
                    {"prefix_length": prefix}
                )
            elif unnumbered:
                for interf in ipv4_interf_table_vrf:
                    interf_name = str(interf.get("intf-name", ""))
                    if interf_name == unnumbered:
                        address = napalm.base.helpers.ip(interf.get("prefix"))
                        prefix = int(interf.get("masklen", ""))
                        if interface_name not in interfaces_ip.keys():
                            interfaces_ip[interface_name] = {}
                        if "ipv4" not in interfaces_ip[interface_name].keys():
                            interfaces_ip[interface_name]["ipv4"] = {}
                        if address not in interfaces_ip[interface_name].get("ipv4"):
                            interfaces_ip[interface_name]["ipv4"][address] = {}
                        interfaces_ip[interface_name]["ipv4"][address].update(
                            {"prefix_length": prefix}
                        )

            secondary_addresses = interface.get("TABLE_secondary_address", {}).get(
                "ROW_secondary_address", []
            )
            if type(secondary_addresses) is dict:
                secondary_addresses = [secondary_addresses]
            for secondary_address in secondary_addresses:
                secondary_address_ip = napalm.base.helpers.ip(
                    secondary_address.get("prefix1")
                )
                secondary_address_prefix = int(secondary_address.get("masklen1", ""))
                if "ipv4" not in interfaces_ip[interface_name].keys():
                    interfaces_ip[interface_name]["ipv4"] = {}
                if secondary_address_ip not in interfaces_ip[interface_name].get(
                    "ipv4"
                ):
                    interfaces_ip[interface_name]["ipv4"][secondary_address_ip] = {}
                interfaces_ip[interface_name]["ipv4"][secondary_address_ip].update(
                    {"prefix_length": secondary_address_prefix}
                )

        ipv6_command = "show ipv6 interface"
        # If the switch doesn't run IPv6 or support it the show ipv6 interface
        # command will throw an error so catch it and return the ipv4 addresses
        try:
            ipv6_interf_table_vrf = self._get_command_table(
                ipv6_command, "TABLE_intf", "ROW_intf"
            )
        except napalm.nxapi_plumbing.errors.NXAPIPostError:
            return interfaces_ip

        for interface in ipv6_interf_table_vrf:
            interface_name = str(interface.get("intf-name", ""))

            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = {}
            if "ipv6" not in interfaces_ip[interface_name].keys():
                interfaces_ip[interface_name]["ipv6"] = {}
            if "addr" not in interface.keys():
                # Handle nexus 9000 ipv6 interface output
                if isinstance(interface["TABLE_addr"]["ROW_addr"], list):
                    addrs = [
                        addr["addr"] for addr in interface["TABLE_addr"]["ROW_addr"]
                    ]
                elif isinstance(interface["TABLE_addr"]["ROW_addr"], dict):
                    addrs = interface["TABLE_addr"]["ROW_addr"]["addr"]
                interface["addr"] = addrs

            if type(interface.get("addr", "")) is list:
                for ipv6_address in interface.get("addr", ""):
                    address = napalm.base.helpers.ip(ipv6_address.split("/")[0])
                    prefix = int(ipv6_address.split("/")[-1])
                    if address not in interfaces_ip[interface_name].get("ipv6"):
                        interfaces_ip[interface_name]["ipv6"][address] = {}
                    interfaces_ip[interface_name]["ipv6"][address].update(
                        {"prefix_length": prefix}
                    )
            else:
                address = napalm.base.helpers.ip(
                    interface.get("addr", "").split("/")[0]
                )
                prefix = interface.get("prefix", "").split("/")[-1]
                if prefix:
                    prefix = int(interface.get("prefix", "").split("/")[-1])
                else:
                    prefix = 128

                if address not in interfaces_ip[interface_name].get("ipv6"):
                    interfaces_ip[interface_name]["ipv6"][address] = {}
                interfaces_ip[interface_name]["ipv6"][address].update(
                    {"prefix_length": prefix}
                )
        return interfaces_ip

    def get_mac_address_table(self):
        mac_table = []
        command = "show mac address-table"
        mac_table_raw = self._get_command_table(
            command, "TABLE_mac_address", "ROW_mac_address"
        )

        for mac_entry in mac_table_raw:
            raw_mac = mac_entry.get("disp_mac_addr")
            interface = str(mac_entry.get("disp_port"))
            try:
                vlan = int(mac_entry.get("disp_vlan"))
            except ValueError:
                vlan = 0
            active = True
            static = mac_entry.get("disp_is_static") != "0"
            moves = 0
            last_move = 0.0
            mac_table.append(
                {
                    "mac": napalm.base.helpers.mac(raw_mac),
                    "interface": interface,
                    "vlan": vlan,
                    "active": active,
                    "static": static,
                    "moves": moves,
                    "last_move": last_move,
                }
            )
        return mac_table

    def get_snmp_information(self):
        snmp_information = {}
        snmp_command = "show running-config"
        snmp_raw_output = self.cli([snmp_command]).get(snmp_command, "")
        snmp_config = napalm.base.helpers.textfsm_extractor(
            self, "snmp_config", snmp_raw_output
        )

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
        section_username_raw_output = self.cli([command]).get(command, "")
        section_username_tabled_output = napalm.base.helpers.textfsm_extractor(
            self, "users", section_username_raw_output
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

    def get_network_instances(self, name=""):
        """ get_network_instances implementation for NX-OS """

        # command 'show vrf detail' returns all VRFs with detailed information
        # format: list of dictionaries with keys such as 'vrf_name' and 'rd'
        command = "show vrf detail"
        vrf_table_raw = self._get_command_table(command, "TABLE_vrf", "ROW_vrf")

        # command 'show vrf interface' returns all interfaces including their assigned VRF
        # format: list of dictionaries with keys 'if_name', 'vrf_name', 'vrf_id' and 'soo'
        command = "show vrf interface"
        intf_table_raw = self._get_command_table(command, "TABLE_if", "ROW_if")

        # create a dictionary with key = 'vrf_name' and value = list of interfaces
        vrf_intfs = defaultdict(list)
        for intf in intf_table_raw:
            vrf_intfs[intf["vrf_name"]].append(str(intf["if_name"]))

        vrfs = {}
        for vrf in vrf_table_raw:
            vrf_name = str(vrf.get("vrf_name"))
            vrfs[vrf_name] = {}
            vrfs[vrf_name]["name"] = vrf_name

            # differentiate between VRF type 'DEFAULT_INSTANCE' and 'L3VRF'
            if vrf_name == "default":
                vrfs[vrf_name]["type"] = "DEFAULT_INSTANCE"
            else:
                vrfs[vrf_name]["type"] = "L3VRF"

            vrfs[vrf_name]["state"] = {"route_distinguisher": str(vrf.get("rd"))}

            # convert list of interfaces (vrf_intfs[vrf_name]) to expected format
            # format = dict with key = interface name and empty values
            vrfs[vrf_name]["interfaces"] = {}
            vrfs[vrf_name]["interfaces"]["interface"] = dict.fromkeys(
                vrf_intfs[vrf_name], {}
            )

        # if name of a specific VRF was passed as an argument
        # only return results for this particular VRF
        if name:
            if name in vrfs.keys():
                return {str(name): vrfs[name]}
            else:
                return {}
        # else return results for all VRFs
        else:
            return vrfs

    def get_environment(self):
        def _process_pdus(power_data):
            normalized = defaultdict(dict)
            # some nexus devices have keys postfixed with the shorthand device series name (ie n3k)
            # ex. on a 9k, the key is TABLE_psinfo, but on a 3k it is TABLE_psinfo_n3k
            ps_info_key = [
                i for i in power_data.keys() if i.startswith("TABLE_psinfo")
            ][0]
            ps_info_table = power_data[ps_info_key]
            # Later version of nxos will have a list under TABLE_psinfo like
            # TABLE_psinfo : [{'ROW_psinfo': {...
            # and not have the psnum under the row
            if isinstance(ps_info_table, list):
                # if this is one of those later versions, make the data look like
                # the older way
                count = 1
                tmp_table = []
                for entry in ps_info_table:
                    tmp = entry.get("ROW_psinfo")
                    tmp["psnum"] = count
                    # to access the power supply status, the key looks like it is device dependent
                    # on a 3k device it is ps_status_3k
                    status_key = [
                        i
                        for i in entry["ROW_psinfo"].keys()
                        if i.startswith("ps_status")
                    ][0]
                    tmp["ps_status"] = entry["ROW_psinfo"][status_key]
                    count += 1
                    tmp_table.append(tmp)
                ps_info_table = {"ROW_psinfo": tmp_table}
            # some nexus devices have keys postfixed with the shorthand device series name (ie n3k)
            # ex. on a 9k the key is ROW_psinfo, but on a 3k it is ROW_psinfo_n3k
            ps_info_row_key = [
                i for i in ps_info_table.keys() if i.startswith("ROW_psinfo")
            ][0]
            for psinfo in ps_info_table[ps_info_row_key]:
                normalized[psinfo["psnum"]]["status"] = (
                    psinfo.get("ps_status", "ok") == "ok"
                )
                normalized[psinfo["psnum"]]["output"] = float(psinfo.get("watts", -1.0))
                # Newer nxos versions provide the total capacity in the `tot_capa` key
                if "tot_capa" in psinfo:
                    normalized[psinfo["psnum"]]["capacity"] = float(
                        psinfo["tot_capa"].split()[0]
                    )
                # The capacity of the power supply can be determined by the model
                # ie N2200-PAC-400W = 400 watts
                else:
                    ps_model = psinfo.get("psmodel", "-1")
                    normalized[psinfo["psnum"]]["capacity"] = float(
                        ps_model.split("-")[-1][:-1]
                    )
            return json.loads(json.dumps(normalized))

        def _process_fans(fan_data):
            normalized = {}
            for entry in fan_data["TABLE_faninfo"]["ROW_faninfo"]:
                if "PS" in entry["fanname"]:
                    # Skip fans in power supplies
                    continue
                normalized[entry["fanname"]] = {
                    # Copying the behavior of eos.py where if the fanstatus key is not found
                    # we default the status to True
                    "status": entry.get("fanstatus", "Ok")
                    == "Ok"
                }
            return normalized

        def _process_temperature(temperature_data):
            normalized = {}
            # The modname and sensor type are not unique enough keys, so adding a count
            count = 1
            past_tempmod = "1"
            for entry in temperature_data["ROW_tempinfo"]:
                mod_name = entry.get("tempmod").rstrip()
                # if the mod name has change reset the count to 1
                if past_tempmod != mod_name:
                    count = 1
                name = "{}-{} {}".format(mod_name, count, entry.get("sensor").rstrip())
                normalized[name] = {
                    "temperature": float(entry.get("curtemp", -1)),
                    "is_alert": entry.get("alarmstatus", "Ok").rstrip() != "Ok",
                    "is_critical": float(entry.get("curtemp"))
                    > float(entry.get("majthres")),
                }
                count += 1
            return normalized

        def _process_cpu(cpu_data):
            idle = (
                cpu_data.get("idle_percent")
                if cpu_data.get("idle_percent")
                else cpu_data["TABLE_cpu_util"]["ROW_cpu_util"]["idle_percent"]
            )
            return {0: {"%usage": round(100 - float(idle), 2)}}

        def _process_memory(memory_data):
            avail = memory_data["TABLE_process_tag"]["ROW_process_tag"][
                "process-memory-share-total-shm-avail"
            ]
            used = memory_data["TABLE_process_tag"]["ROW_process_tag"][
                "process-memory-share-total-shm-used"
            ]
            return {"available_ram": int(avail) * 1000, "used_ram": int(used) * 1000}

        environment_raw = self._send_command("show environment")
        cpu_raw = self._send_command("show processes cpu")
        memory_raw = self._send_command("show processes memory shared")
        fan_key = [i for i in environment_raw.keys() if i.startswith("fandetails")][0]
        return {
            "power": _process_pdus(environment_raw["powersup"]),
            "fans": _process_fans(environment_raw[fan_key]),
            "temperature": _process_temperature(environment_raw["TABLE_tempinfo"]),
            "cpu": _process_cpu(cpu_raw),
            "memory": _process_memory(memory_raw),
        }

    def get_vlans(self):
        vlans = {}
        command = "show vlan brief"
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
