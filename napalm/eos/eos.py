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

"""
Napalm driver for Arista EOS.

Read napalm.readthedocs.org for more information.
"""

# std libs
import re
import time
import inspect

from datetime import datetime
from collections import defaultdict
from netaddr import IPAddress
from netaddr import IPNetwork

from netaddr.core import AddrFormatError

# third party libs
import pyeapi
from pyeapi.eapilib import ConnectionError, CommandError

# NAPALM base
import napalm.base.helpers
from napalm.base.base import NetworkDriver
from napalm.base.utils import string_parsers
from napalm.base.exceptions import (
    ConnectionException,
    MergeConfigException,
    ReplaceConfigException,
    SessionLockedException,
    CommandErrorException,
)
from napalm.eos.constants import LLDP_CAPAB_TRANFORM_TABLE
from napalm.eos.pyeapi_syntax_wrapper import Node
from napalm.eos.utils.versions import EOSVersion
import napalm.base.constants as c

# local modules
# here add local imports
# e.g. import napalm.eos.helpers etc.


class EOSDriver(NetworkDriver):
    """Napalm driver for Arista EOS."""

    SUPPORTED_OC_MODELS = []

    HEREDOC_COMMANDS = [
        ("banner login", 1),
        ("banner motd", 1),
        ("comment", 1),
        ("protocol https certificate", 2),
    ]

    _RE_BGP_INFO = re.compile(
        r"BGP neighbor is (?P<neighbor>.*?), remote AS (?P<as>.*?), .*"
    )  # noqa
    _RE_BGP_RID_INFO = re.compile(
        r".*BGP version 4, remote router ID (?P<rid>.*?), VRF (?P<vrf>.*?)$"
    )  # noqa
    _RE_BGP_DESC = re.compile(r"\s+Description: (?P<description>.*?)$")
    _RE_BGP_LOCAL = re.compile(r"Local AS is (?P<as>.*?),.*")
    _RE_BGP_PREFIX = re.compile(
        r"(\s*?)(?P<af>IPv[46]) (Unicast|6PE):\s*(?P<sent>\d+)\s*(?P<received>\d+)"
    )  # noqa
    _RE_SNMP_COMM = re.compile(
        r"""^snmp-server\s+community\s+(?P<community>\S+)
                                (\s+view\s+(?P<view>\S+))?(\s+(?P<access>ro|rw)?)
                                (\s+ipv6\s+(?P<v6_acl>\S+))?(\s+(?P<v4_acl>\S+))?$""",
        re.VERBOSE,
    )

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialize EOS Driver.

        Optional args:
            * lock_disable (True/False): force configuration lock to be disabled (for external lock
                management).
            * enable_password (True/False): Enable password for privilege elevation
            * eos_autoComplete (True/False): Allow for shortening of cli commands
            * transport (string): pyeapi transport, defaults to eos_transport if set
                - socket
                - http_local
                - http
                - https
                - https_certs
                (from: https://github.com/arista-eosplus/pyeapi/blob/develop/pyeapi/client.py#L115)
                transport is the preferred method
            * eos_transport (string): pyeapi transport, defaults to https
                eos_transport for backwards compatibility

        """
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.config_session = None
        self.locked = False

        self.platform = "eos"
        self.profile = [self.platform]

        self._process_optional_args(optional_args or {})

    def _process_optional_args(self, optional_args):
        # Define locking method
        self.lock_disable = optional_args.get("lock_disable", False)

        self.enablepwd = optional_args.pop("enable_password", "")
        self.eos_autoComplete = optional_args.pop("eos_autoComplete", None)
        # eos_transport is there for backwards compatibility, transport is the preferred method
        transport = optional_args.get(
            "transport", optional_args.get("eos_transport", "https")
        )
        self.fn0039_config = optional_args.pop("eos_fn0039_config", False)
        try:
            self.transport_class = pyeapi.client.TRANSPORTS[transport]
        except KeyError:
            raise ConnectionException("Unknown transport: {}".format(self.transport))
        init_args = inspect.getfullargspec(self.transport_class.__init__)[0]

        init_args.pop(0)  # Remove "self"
        init_args.append("enforce_verification")  # Not an arg for unknown reason

        filter_args = ["host", "username", "password", "timeout", "lock_disable"]

        self.eapi_kwargs = {
            k: v
            for k, v in optional_args.items()
            if k in init_args and k not in filter_args
        }

    def open(self):
        """Implementation of NAPALM method open."""
        try:
            connection = self.transport_class(
                host=self.hostname,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                **self.eapi_kwargs
            )

            if self.device is None:
                self.device = Node(connection, enablepwd=self.enablepwd)
            # does not raise an Exception if unusable

            # let's try to determine if we need to use new EOS cli syntax
            sh_ver = self.device.run_commands(["show version"])
            cli_version = (
                2 if EOSVersion(sh_ver[0]["version"]) >= EOSVersion("4.23.0") else 1
            )

            self.device.update_cli_version(cli_version)
        except ConnectionError as ce:
            # and this is raised either if device not avaiable
            # either if HTTP(S) agent is not enabled
            # show management api http-commands
            raise ConnectionException(str(ce))

    def close(self):
        """Implementation of NAPALM method close."""
        self.discard_config()

    def is_alive(self):
        return {"is_alive": True}  # always true as eAPI is HTTP-based

    def _lock(self):
        sess = self.device.run_commands(["show configuration sessions"])[0]["sessions"]
        if [
            k
            for k, v in sess.items()
            if v["state"] == "pending" and k != self.config_session
        ]:
            raise SessionLockedException("Session is already in use")

    @staticmethod
    def _multiline_convert(config, start="banner login", end="EOF", depth=1):
        """Converts running-config HEREDOC into EAPI JSON dict"""
        ret = list(config)  # Don't modify list in-place
        try:
            s = ret.index(start)
            e = s
            while depth:
                e = ret.index(end, e + 1)
                depth = depth - 1
        except ValueError:  # Couldn't find end, abort
            return ret
        ret[s] = {"cmd": ret[s], "input": "\n".join(ret[s + 1 : e])}
        del ret[s + 1 : e + 1]

        return ret

    @staticmethod
    def _mode_comment_convert(commands):
        """
        EOS has the concept of multi-line mode comments, shown in the running-config
        as being inside a config stanza (router bgp, ACL definition, etc) and beginning
        with the normal level of spaces and '!!', followed by comments.

        Unfortunately, pyeapi does not accept mode comments in this format, and have to be
        converted to a specific type of pyeapi call that accepts multi-line input

        Copy the config list into a new return list, converting consecutive lines starting with
        "!!" into a single multiline comment command

        :param commands: List of commands to be sent to pyeapi
        :return: Converted list of commands to be sent to pyeapi
        """

        ret = []
        comment_count = 0
        for idx, element in enumerate(commands):
            # Check first for stringiness, as we may have dicts in the command list already
            if isinstance(element, str) and element.startswith("!!"):
                comment_count += 1
                continue
            else:
                if comment_count > 0:
                    # append the previous comment
                    ret.append(
                        {
                            "cmd": "comment",
                            "input": "\n".join(
                                map(
                                    lambda s: s.lstrip("! "),
                                    commands[idx - comment_count : idx],
                                )
                            ),
                        }
                    )
                    comment_count = 0
                ret.append(element)

        return ret

    def _load_config(self, filename=None, config=None, replace=True):
        if self.config_session is None:
            self.config_session = "napalm_{}".format(datetime.now().microsecond)

        commands = []
        commands.append("configure session {}".format(self.config_session))
        if replace:
            commands.append("rollback clean-config")

        if filename is not None:
            with open(filename, "r") as f:
                lines = f.readlines()
        else:
            if isinstance(config, list):
                lines = config
            else:
                lines = config.splitlines()

        for line in lines:
            line = line.strip()
            if line == "":
                continue
            if line.startswith("!") and not line.startswith("!!"):
                continue
            commands.append(line)

        for start, depth in [
            (s, d) for (s, d) in self.HEREDOC_COMMANDS if s in commands
        ]:
            commands = self._multiline_convert(commands, start=start, depth=depth)

        commands = self._mode_comment_convert(commands)

        try:
            if self.eos_autoComplete is not None:
                self.device.run_commands(
                    commands,
                    autoComplete=self.eos_autoComplete,
                    fn0039_transform=self.fn0039_config,
                )
            else:
                self.device.run_commands(commands, fn0039_transform=self.fn0039_config)
        except pyeapi.eapilib.CommandError as e:
            self.discard_config()
            msg = str(e)
            if replace:
                raise ReplaceConfigException(msg)
            else:
                raise MergeConfigException(msg)

    def load_replace_candidate(self, filename=None, config=None):
        """Implementation of NAPALM method load_replace_candidate."""
        self._load_config(filename, config, True)

    def load_merge_candidate(self, filename=None, config=None):
        """Implementation of NAPALM method load_merge_candidate."""
        self._load_config(filename, config, False)

    def compare_config(self):
        """Implementation of NAPALM method compare_config."""
        if self.config_session is None:
            return ""
        else:
            commands = ["show session-config named %s diffs" % self.config_session]
            result = self.device.run_commands(commands, encoding="text")[0]["output"]

            result = "\n".join(result.splitlines()[2:])

            return result.strip()

    def commit_config(self, message=""):
        """Implementation of NAPALM method commit_config."""

        if not self.lock_disable:
            self._lock()
        if message:
            raise NotImplementedError(
                "Commit message not implemented for this platform"
            )
        commands = [
            "copy startup-config flash:rollback-0",
            "configure session {}".format(self.config_session),
            "commit",
            "write memory",
        ]

        self.device.run_commands(commands)
        self.config_session = None

    def discard_config(self):
        """Implementation of NAPALM method discard_config."""
        if self.config_session is not None:
            commands = ["configure session {}".format(self.config_session), "abort"]
            self.device.run_commands(commands)
            self.config_session = None

    def rollback(self):
        """Implementation of NAPALM method rollback."""
        commands = ["configure replace flash:rollback-0", "write memory"]
        self.device.run_commands(commands)

    def get_facts(self):
        """Implementation of NAPALM method get_facts."""
        commands = ["show version", "show hostname", "show interfaces"]

        result = self.device.run_commands(commands)

        version = result[0]
        hostname = result[1]
        interfaces_dict = result[2]["interfaces"]

        uptime = time.time() - version["bootupTimestamp"]

        interfaces = [i for i in interfaces_dict.keys() if "." not in i]
        interfaces = string_parsers.sorted_nicely(interfaces)

        return {
            "hostname": hostname["hostname"],
            "fqdn": hostname["fqdn"],
            "vendor": "Arista",
            "model": version["modelName"],
            "serial_number": version["serialNumber"],
            "os_version": version["internalVersion"],
            "uptime": int(uptime),
            "interface_list": interfaces,
        }

    def get_interfaces(self):
        commands = ["show interfaces"]
        output = self.device.run_commands(commands)[0]

        interfaces = {}

        for interface, values in output["interfaces"].items():
            interfaces[interface] = {}

            if values["lineProtocolStatus"] == "up":
                interfaces[interface]["is_up"] = True
                interfaces[interface]["is_enabled"] = True
            else:
                interfaces[interface]["is_up"] = False
                if values["interfaceStatus"] == "disabled":
                    interfaces[interface]["is_enabled"] = False
                else:
                    interfaces[interface]["is_enabled"] = True

            interfaces[interface]["description"] = values["description"]

            interfaces[interface]["last_flapped"] = values.pop(
                "lastStatusChangeTimestamp", -1.0
            )

            interfaces[interface]["mtu"] = int(values["mtu"])
            interfaces[interface]["speed"] = int(values["bandwidth"] * 1e-6)
            interfaces[interface]["mac_address"] = napalm.base.helpers.convert(
                napalm.base.helpers.mac, values.pop("physicalAddress", "")
            )

        return interfaces

    def get_lldp_neighbors(self):
        commands = ["show lldp neighbors"]
        output = self.device.run_commands(commands)[0]["lldpNeighbors"]

        lldp = {}

        for n in output:
            if n["port"] not in lldp.keys():
                lldp[n["port"]] = []

            lldp[n["port"]].append(
                {"hostname": n["neighborDevice"], "port": n["neighborPort"]}
            )

        return lldp

    def get_interfaces_counters(self):
        commands = ["show interfaces"]
        output = self.device.run_commands(commands)
        interface_counters = defaultdict(dict)
        for interface, data in output[0]["interfaces"].items():
            if data["hardware"] == "subinterface":
                # Subinterfaces will never have counters so no point in parsing them at all
                continue
            counters = data.get("interfaceCounters", {})
            interface_counters[interface].update(
                tx_octets=counters.get("outOctets", -1),
                rx_octets=counters.get("inOctets", -1),
                tx_unicast_packets=counters.get("outUcastPkts", -1),
                rx_unicast_packets=counters.get("inUcastPkts", -1),
                tx_multicast_packets=counters.get("outMulticastPkts", -1),
                rx_multicast_packets=counters.get("inMulticastPkts", -1),
                tx_broadcast_packets=counters.get("outBroadcastPkts", -1),
                rx_broadcast_packets=counters.get("inBroadcastPkts", -1),
                tx_discards=counters.get("outDiscards", -1),
                rx_discards=counters.get("inDiscards", -1),
                tx_errors=counters.get("totalOutErrors", -1),
                rx_errors=counters.get("totalInErrors", -1),
            )
        return interface_counters

    def get_bgp_neighbors(self):
        def get_re_group(res, key, default=None):
            """ Small helper to retrive data from re match groups"""
            try:
                return res.group(key)
            except KeyError:
                return default

        NEIGHBOR_FILTER = "bgp neighbors vrf all | include remote AS | remote router ID |IPv[46] (Unicast|6PE):.*[0-9]+|^Local AS|Desc|BGP state"  # noqa
        output_summary_cmds = self.device.run_commands(
            ["show ipv6 bgp summary vrf all", "show ip bgp summary vrf all"],
            encoding="json",
        )
        output_neighbor_cmds = self.device.run_commands(
            ["show ip " + NEIGHBOR_FILTER, "show ipv6 " + NEIGHBOR_FILTER],
            encoding="text",
        )

        bgp_counters = defaultdict(lambda: dict(peers={}))
        for summary in output_summary_cmds:
            """
            Json output looks as follows
            "vrfs": {
                "default": {
                    "routerId": 1,
                    "asn": 1,
                    "peers": {
                        "1.1.1.1": {
                            "msgSent": 1,
                            "inMsgQueue": 0,
                            "prefixReceived": 3926,
                            "upDownTime": 1449501378.418644,
                            "version": 4,
                            "msgReceived": 59616,
                            "prefixAccepted": 3926,
                            "peerState": "Established",
                            "outMsgQueue": 0,
                            "underMaintenance": false,
                            "asn": 1
                        }
                    }
                }
            }
            """
            for vrf, vrf_data in summary["vrfs"].items():
                bgp_counters[vrf]["router_id"] = vrf_data["routerId"]
                for peer, peer_data in vrf_data["peers"].items():
                    if peer_data["peerState"] == "Idle":
                        is_enabled = (
                            True
                            if peer_data["peerStateIdleReason"] != "Admin"
                            else False
                        )
                    else:
                        is_enabled = True
                    peer_info = {
                        "is_up": peer_data["peerState"] == "Established",
                        "is_enabled": is_enabled,
                        "uptime": int(time.time() - float(peer_data["upDownTime"])),
                    }
                    bgp_counters[vrf]["peers"][napalm.base.helpers.ip(peer)] = peer_info
        lines = []
        [lines.extend(x["output"].splitlines()) for x in output_neighbor_cmds]
        while lines:
            """
            Raw output from the command looks like the following:

              BGP neighbor is 1.1.1.1, remote AS 1, external link
                Description: Very info such descriptive
                BGP version 4, remote router ID 1.1.1.1, VRF my_vrf
                BGP state is Idle, Administratively shut down
                 IPv4 Unicast:         683        78
                 IPv6 Unicast:           0         0
              Local AS is 2, local router ID 2.2.2.2
            """
            neighbor_info = re.match(self._RE_BGP_INFO, lines.pop(0))
            # this line can be either description or rid info
            next_line = lines.pop(0)
            desc = re.match(self._RE_BGP_DESC, next_line)
            if desc is None:
                rid_info = re.match(self._RE_BGP_RID_INFO, next_line)
                desc = ""
            else:
                rid_info = re.match(self._RE_BGP_RID_INFO, lines.pop(0))
                desc = desc.group("description")
            lines.pop(0)
            v4_stats = re.match(self._RE_BGP_PREFIX, lines.pop(0))
            v6_stats = re.match(self._RE_BGP_PREFIX, lines.pop(0))
            local_as = re.match(self._RE_BGP_LOCAL, lines.pop(0))
            data = {
                "remote_as": napalm.base.helpers.as_number(neighbor_info.group("as")),
                "remote_id": napalm.base.helpers.ip(
                    get_re_group(rid_info, "rid", "0.0.0.0")
                ),
                "local_as": napalm.base.helpers.as_number(local_as.group("as")),
                "description": str(desc),
                "address_family": {
                    "ipv4": {
                        "sent_prefixes": int(get_re_group(v4_stats, "sent", -1)),
                        "received_prefixes": int(
                            get_re_group(v4_stats, "received", -1)
                        ),
                        "accepted_prefixes": -1,
                    },
                    "ipv6": {
                        "sent_prefixes": int(get_re_group(v6_stats, "sent", -1)),
                        "received_prefixes": int(
                            get_re_group(v6_stats, "received", -1)
                        ),
                        "accepted_prefixes": -1,
                    },
                },
            }
            peer_addr = napalm.base.helpers.ip(neighbor_info.group("neighbor"))
            vrf = rid_info.group("vrf")
            if peer_addr not in bgp_counters[vrf]["peers"]:
                bgp_counters[vrf]["peers"][peer_addr] = {
                    "is_up": False,  # if not found, means it was not found in the oper stats
                    # i.e. neighbor down,
                    "uptime": 0,
                    "is_enabled": True,
                }
            bgp_counters[vrf]["peers"][peer_addr].update(data)
        if "default" in bgp_counters:
            bgp_counters["global"] = bgp_counters.pop("default")
        return dict(bgp_counters)

    def get_environment(self):
        def extract_temperature_data(data):
            for s in data:
                temp = s["currentTemperature"] if "currentTemperature" in s else 0.0
                name = s["name"]
                values = {
                    "temperature": temp,
                    "is_alert": temp > s["overheatThreshold"],
                    "is_critical": temp > s["criticalThreshold"],
                }
                yield name, values

        sh_version_out = self.device.run_commands(["show version"])
        is_veos = sh_version_out[0]["modelName"].lower() == "veos"
        commands = ["show environment cooling", "show environment temperature"]
        if not is_veos:
            commands.append("show environment power")
            fans_output, temp_output, power_output = self.device.run_commands(commands)
        else:
            fans_output, temp_output = self.device.run_commands(commands)
        environment_counters = {"fans": {}, "temperature": {}, "power": {}, "cpu": {}}
        cpu_output = self.device.run_commands(
            ["show processes top once"], encoding="text"
        )[0]["output"]
        for slot in fans_output["fanTraySlots"]:
            environment_counters["fans"][slot["label"]] = {
                "status": slot["status"] == "ok"
            }
        # First check FRU's
        for fru_type in ["cardSlots", "powerSupplySlots"]:
            for fru in temp_output[fru_type]:
                t = {
                    name: value
                    for name, value in extract_temperature_data(fru["tempSensors"])
                }
                environment_counters["temperature"].update(t)
        # On board sensors
        parsed = {n: v for n, v in extract_temperature_data(temp_output["tempSensors"])}
        environment_counters["temperature"].update(parsed)
        if not is_veos:
            for psu, data in power_output["powerSupplies"].items():
                environment_counters["power"][psu] = {
                    "status": data.get("state", "ok") == "ok",
                    "capacity": data.get("capacity", -1.0),
                    "output": data.get("outputPower", -1.0),
                }
        cpu_lines = cpu_output.splitlines()
        # Matches either of
        # Cpu(s):  5.2%us,  1.4%sy,  0.0%ni, 92.2%id,  0.6%wa,  0.3%hi,  0.4%si,  0.0%st ( 4.16 > )
        # %Cpu(s):  4.2 us,  0.9 sy,  0.0 ni, 94.6 id,  0.0 wa,  0.1 hi,  0.2 si,  0.0 st ( 4.16 < )
        m = re.match(".*ni, (?P<idle>.*).id.*", cpu_lines[2])
        environment_counters["cpu"][0] = {
            "%usage": round(100 - float(m.group("idle")), 1)
        }
        # Matches either of
        # Mem:   3844356k total,  3763184k used,    81172k free,    16732k buffers ( 4.16 > )
        # KiB Mem:  32472080 total,  5697604 used, 26774476 free,   372052 buffers ( 4.16 < )
        mem_regex = (
            r"[^\d]*(?P<total>\d+)[k\s]+total,"
            r"\s+(?P<used>\d+)[k\s]+used,"
            r"\s+(?P<free>\d+)[k\s]+free,.*"
        )
        m = re.match(mem_regex, cpu_lines[3])
        environment_counters["memory"] = {
            "available_ram": int(m.group("total")),
            "used_ram": int(m.group("used")),
        }
        return environment_counters

    def _transform_lldp_capab(self, capabilities):
        return sorted([LLDP_CAPAB_TRANFORM_TABLE[c.lower()] for c in capabilities])

    def get_lldp_neighbors_detail(self, interface=""):

        lldp_neighbors_out = {}

        filters = []
        if interface:
            filters.append(interface)

        commands = [
            "show lldp neighbors {filters} detail".format(filters=" ".join(filters))
        ]

        lldp_neighbors_in = self.device.run_commands(commands)[0].get(
            "lldpNeighbors", {}
        )

        for interface in lldp_neighbors_in:
            interface_neighbors = lldp_neighbors_in.get(interface).get(
                "lldpNeighborInfo", {}
            )
            if not interface_neighbors:
                # in case of empty infos
                continue

            # it is provided a list of neighbors per interface
            for neighbor in interface_neighbors:
                if interface not in lldp_neighbors_out.keys():
                    lldp_neighbors_out[interface] = []
                capabilities = neighbor.get("systemCapabilities", {})
                available_capabilities = self._transform_lldp_capab(capabilities.keys())
                enabled_capabilities = self._transform_lldp_capab(
                    [capab for capab, enabled in capabilities.items() if enabled]
                )
                remote_chassis_id = neighbor.get("chassisId", "")
                if neighbor.get("chassisIdType", "") == "macAddress":
                    remote_chassis_id = napalm.base.helpers.mac(remote_chassis_id)
                neighbor_interface_info = neighbor.get("neighborInterfaceInfo", {})
                lldp_neighbors_out[interface].append(
                    {
                        "parent_interface": interface,  # no parent interfaces
                        "remote_port": neighbor_interface_info.get(
                            "interfaceId", ""
                        ).replace('"', ""),
                        "remote_port_description": neighbor_interface_info.get(
                            "interfaceDescription", ""
                        ),
                        "remote_system_name": neighbor.get("systemName", ""),
                        "remote_system_description": neighbor.get(
                            "systemDescription", ""
                        ),
                        "remote_chassis_id": remote_chassis_id,
                        "remote_system_capab": available_capabilities,
                        "remote_system_enable_capab": enabled_capabilities,
                    }
                )
        return lldp_neighbors_out

    def cli(self, commands):
        cli_output = {}

        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            try:
                cli_output[str(command)] = self.device.run_commands(
                    [command], encoding="text"
                )[0].get("output")
                # not quite fair to not exploit rum_commands
                # but at least can have better control to point to wrong command in case of failure
            except pyeapi.eapilib.CommandError:
                # for sure this command failed
                cli_output[str(command)] = 'Invalid command: "{cmd}"'.format(
                    cmd=command
                )
                raise CommandErrorException(str(cli_output))
            except Exception as e:
                # something bad happened
                msg = 'Unable to execute command "{cmd}": {err}'.format(
                    cmd=command, err=e
                )
                cli_output[str(command)] = msg
                raise CommandErrorException(str(cli_output))

        return cli_output

    def get_bgp_config(self, group="", neighbor=""):
        """Implementation of NAPALM method get_bgp_config."""
        _GROUP_FIELD_MAP_ = {
            "type": "type",
            "multipath": "multipath",
            "apply-groups": "apply_groups",
            "remove-private-as": "remove_private_as",
            "ebgp-multihop": "multihop_ttl",
            "remote-as": "remote_as",
            "local-v4-addr": "local_address",
            "local-v6-addr": "local_address",
            "local-as": "local_as",
            "description": "description",
            "import-policy": "import_policy",
            "export-policy": "export_policy",
        }

        _PEER_FIELD_MAP_ = {
            "description": "description",
            "remote-as": "remote_as",
            "local-v4-addr": "local_address",
            "local-v6-addr": "local_address",
            "local-as": "local_as",
            "next-hop-self": "nhs",
            "route-reflector-client": "route_reflector_client",
            "import-policy": "import_policy",
            "export-policy": "export_policy",
            "passwd": "authentication_key",
        }

        _PROPERTY_FIELD_MAP_ = _GROUP_FIELD_MAP_.copy()
        _PROPERTY_FIELD_MAP_.update(_PEER_FIELD_MAP_)

        _PROPERTY_TYPE_MAP_ = {
            # used to determine the default value
            # and cast the values
            "remote-as": int,
            "ebgp-multihop": int,
            "local-v4-addr": str,
            "local-v6-addr": str,
            "local-as": int,
            "remove-private-as": bool,
            "next-hop-self": bool,
            "description": str,
            "route-reflector-client": bool,
            "password": str,
            "route-map": str,
            "apply-groups": list,
            "type": str,
            "import-policy": str,
            "export-policy": str,
            "multipath": bool,
        }

        _DATATYPE_DEFAULT_ = {str: "", int: 0, bool: False, list: []}

        def default_group_dict(local_as):
            group_dict = {}
            group_dict.update(
                {
                    key: _DATATYPE_DEFAULT_.get(_PROPERTY_TYPE_MAP_.get(prop))
                    for prop, key in _GROUP_FIELD_MAP_.items()
                }
            )
            group_dict.update(
                {"prefix_limit": {}, "neighbors": {}, "local_as": local_as}
            )  # few more default values
            return group_dict

        def default_neighbor_dict(local_as):
            neighbor_dict = {}
            neighbor_dict.update(
                {
                    key: _DATATYPE_DEFAULT_.get(_PROPERTY_TYPE_MAP_.get(prop))
                    for prop, key in _PEER_FIELD_MAP_.items()
                }
            )  # populating with default values
            neighbor_dict.update(
                {"prefix_limit": {}, "local_as": local_as, "authentication_key": ""}
            )  # few more default values
            return neighbor_dict

        def parse_options(options, default_value=False):

            if not options:
                return {}

            config_property = options[0]
            field_name = _PROPERTY_FIELD_MAP_.get(config_property)
            field_type = _PROPERTY_TYPE_MAP_.get(config_property)
            field_value = _DATATYPE_DEFAULT_.get(field_type)  # to get the default value

            if not field_type:
                # no type specified at all => return empty dictionary
                return {}

            if not default_value:
                if len(options) > 1:
                    field_value = napalm.base.helpers.convert(
                        field_type, options[1], _DATATYPE_DEFAULT_.get(field_type)
                    )
                else:
                    if field_type is bool:
                        field_value = True
            if field_name is not None:
                return {field_name: field_value}
            elif config_property in ["route-map", "password"]:
                # do not respect the pattern neighbor [IP_ADDRESS] [PROPERTY] [VALUE]
                # or need special output (e.g.: maximum-routes)
                if config_property == "password":
                    return {"authentication_key": str(options[2])}
                    # returns the MD5 password
                if config_property == "route-map":
                    direction = None
                    if len(options) == 3:
                        direction = options[2]
                        field_value = field_type(options[1])  # the name of the policy
                    elif len(options) == 2:
                        direction = options[1]
                    if direction == "in":
                        field_name = "import_policy"
                    else:
                        field_name = "export_policy"
                    return {field_name: field_value}

            return {}

        bgp_config = {}

        commands = ["show running-config | section router bgp"]
        bgp_conf = self.device.run_commands(commands, encoding="text")[0].get(
            "output", "\n\n"
        )
        bgp_conf_lines = bgp_conf.splitlines()

        bgp_neighbors = {}

        if not group:
            neighbor = ""  # noqa

        local_as = 0
        bgp_neighbors = {}
        for bgp_conf_line in bgp_conf_lines:
            default_value = False
            bgp_conf_line = bgp_conf_line.strip()
            if bgp_conf_line.startswith("router bgp"):
                local_as = napalm.base.helpers.as_number(
                    (bgp_conf_line.replace("router bgp", "").strip())
                )
                continue
            if not (
                bgp_conf_line.startswith("neighbor")
                or bgp_conf_line.startswith("no neighbor")
            ):
                continue
            if bgp_conf_line.startswith("no"):
                default_value = True
            bgp_conf_line = bgp_conf_line.replace("no neighbor ", "").replace(
                "neighbor ", ""
            )
            bgp_conf_line_details = bgp_conf_line.split()
            group_or_neighbor = str(bgp_conf_line_details[0])
            options = bgp_conf_line_details[1:]
            try:
                # will try to parse the neighbor name
                # which sometimes is the IP Address of the neigbor
                # or the name of the BGP group
                IPAddress(group_or_neighbor)
                # if passes the test => it is an IP Address, thus a Neighbor!
                peer_address = group_or_neighbor
                if peer_address not in bgp_neighbors:
                    bgp_neighbors[peer_address] = default_neighbor_dict(local_as)
                if options[0] == "peer-group":
                    bgp_neighbors[peer_address]["__group"] = options[1]

                # in the config, neighbor details are lister after
                # the group is specified for the neighbor:
                #
                # neighbor 192.168.172.36 peer-group 4-public-anycast-peers
                # neighbor 192.168.172.36 remote-as 12392
                # neighbor 192.168.172.36 maximum-routes 200
                #
                # because the lines are parsed sequentially
                # can use the last group detected
                # that way we avoid one more loop to
                # match the neighbors with the group they belong to
                # directly will apend the neighbor in the neighbor list of the group at the end

                bgp_neighbors[peer_address].update(
                    parse_options(options, default_value)
                )
            except AddrFormatError:
                # exception trying to parse group name
                # group_or_neighbor represents the name of the group
                group_name = group_or_neighbor
                if group and group_name != group:
                    continue
                if group_name not in bgp_config.keys():
                    bgp_config[group_name] = default_group_dict(local_as)
                bgp_config[group_name].update(parse_options(options, default_value))

        for peer, peer_details in bgp_neighbors.items():
            peer_group = peer_details.pop("__group", None)
            if not peer_group:
                peer_group = "_"
            if peer_group not in bgp_config:
                bgp_config[peer_group] = default_group_dict(local_as)
            bgp_config[peer_group]["neighbors"][peer] = peer_details

        return bgp_config

    def get_arp_table(self, vrf=""):
        arp_table = []

        try:
            commands = ["show arp vrf all"]
            ipv4_neighbors = [
                neighbor
                for k, v in self.device.run_commands(commands)[0].get("vrfs").items()
                if not vrf or k == vrf
                for neighbor in v.get("ipV4Neighbors", [])
            ]
        except pyeapi.eapilib.CommandError:
            return []

        for neighbor in ipv4_neighbors:
            interface = str(neighbor.get("interface"))
            mac_raw = neighbor.get("hwAddress")
            ip = str(neighbor.get("address"))
            age = float(neighbor.get("age"))
            arp_table.append(
                {
                    "interface": interface,
                    "mac": napalm.base.helpers.mac(mac_raw),
                    "ip": napalm.base.helpers.ip(ip),
                    "age": age,
                }
            )

        return arp_table

    def get_ntp_servers(self):
        commands = ["show running-config | section ntp"]

        raw_ntp_config = self.device.run_commands(commands, encoding="text")[0].get(
            "output", ""
        )

        ntp_config = napalm.base.helpers.textfsm_extractor(
            self, "ntp_peers", raw_ntp_config
        )

        return {
            str(ntp_peer.get("ntppeer")): {}
            for ntp_peer in ntp_config
            if ntp_peer.get("ntppeer", "")
        }

    def get_ntp_stats(self):
        ntp_stats = []

        REGEX = (
            r"^\s?(\+|\*|x|-)?([a-zA-Z0-9\.+-:]+)"
            r"\s+([a-zA-Z0-9\.]+)\s+([0-9]{1,2})"
            r"\s+(-|u)\s+([0-9h-]+)\s+([0-9]+)"
            r"\s+([0-9]+)\s+([0-9\.]+)\s+([0-9\.-]+)"
            r"\s+([0-9\.]+)\s?$"
        )

        commands = ["show ntp associations"]

        # output = self.device.run_commands(commands)
        # pyeapi.eapilib.CommandError: CLI command 2 of 2 'show ntp associations'
        # failed: unconverted command
        # JSON output not yet implemented...

        ntp_assoc = self.device.run_commands(commands, encoding="text")[0].get(
            "output", "\n\n"
        )
        ntp_assoc_lines = ntp_assoc.splitlines()[2:]

        for ntp_assoc in ntp_assoc_lines:
            line_search = re.search(REGEX, ntp_assoc, re.I)
            if not line_search:
                continue  # pattern not found
            line_groups = line_search.groups()
            try:
                ntp_stats.append(
                    {
                        "remote": str(line_groups[1]),
                        "synchronized": (line_groups[0] == "*"),
                        "referenceid": str(line_groups[2]),
                        "stratum": int(line_groups[3]),
                        "type": str(line_groups[4]),
                        "when": str(line_groups[5]),
                        "hostpoll": int(line_groups[6]),
                        "reachability": int(line_groups[7]),
                        "delay": float(line_groups[8]),
                        "offset": float(line_groups[9]),
                        "jitter": float(line_groups[10]),
                    }
                )
            except Exception:
                continue  # jump to next line

        return ntp_stats

    def get_interfaces_ip(self):

        interfaces_ip = {}

        interfaces_ipv4_out = self.device.run_commands(["show ip interface"])[0][
            "interfaces"
        ]
        try:
            interfaces_ipv6_out = self.device.run_commands(["show ipv6 interface"])[0][
                "interfaces"
            ]
        except pyeapi.eapilib.CommandError as e:
            msg = str(e)
            if "No IPv6 configured interfaces" in msg:
                interfaces_ipv6_out = {}
            else:
                raise

        for interface_name, interface_details in interfaces_ipv4_out.items():
            ipv4_list = []
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = {}

            if "ipv4" not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name]["ipv4"] = {}
            if "ipv6" not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name]["ipv6"] = {}

            iface_details = interface_details.get("interfaceAddress", {})
            if iface_details.get("primaryIp", {}).get("address") != "0.0.0.0":
                ipv4_list.append(
                    {
                        "address": napalm.base.helpers.ip(
                            iface_details.get("primaryIp", {}).get("address")
                        ),
                        "masklen": iface_details.get("primaryIp", {}).get("maskLen"),
                    }
                )
            for secondary_ip in iface_details.get("secondaryIpsOrderedList", []):
                ipv4_list.append(
                    {
                        "address": napalm.base.helpers.ip(secondary_ip.get("address")),
                        "masklen": secondary_ip.get("maskLen"),
                    }
                )

            for ip in ipv4_list:
                if not ip.get("address"):
                    continue
                if ip.get("address") not in interfaces_ip.get(interface_name).get(
                    "ipv4"
                ):
                    interfaces_ip[interface_name]["ipv4"][ip.get("address")] = {
                        "prefix_length": ip.get("masklen")
                    }

        for interface_name, interface_details in interfaces_ipv6_out.items():
            ipv6_list = []
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = {}

            if "ipv4" not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name]["ipv4"] = {}
            if "ipv6" not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name]["ipv6"] = {}

            ipv6_list.append(
                {
                    "address": napalm.base.helpers.convert(
                        napalm.base.helpers.ip,
                        interface_details.get("linkLocal", {}).get("address"),
                    ),
                    "masklen": int(
                        interface_details.get("linkLocal", {})
                        .get("subnet", "::/0")
                        .split("/")[-1]
                    )
                    # when no link-local set, address will be None and maslken 0
                }
            )
            for address in interface_details.get("addresses"):
                ipv6_list.append(
                    {
                        "address": napalm.base.helpers.ip(address.get("address")),
                        "masklen": int(address.get("subnet").split("/")[-1]),
                    }
                )
            for ip in ipv6_list:
                if not ip.get("address"):
                    continue
                if ip.get("address") not in interfaces_ip.get(interface_name).get(
                    "ipv6"
                ):
                    interfaces_ip[interface_name]["ipv6"][ip.get("address")] = {
                        "prefix_length": ip.get("masklen")
                    }

        return interfaces_ip

    def get_mac_address_table(self):

        mac_table = []

        commands = ["show mac address-table"]

        mac_entries = (
            self.device.run_commands(commands)[0]
            .get("unicastTable", {})
            .get("tableEntries", [])
        )

        for mac_entry in mac_entries:
            vlan = mac_entry.get("vlanId")
            interface = mac_entry.get("interface")
            mac_raw = mac_entry.get("macAddress")
            static = mac_entry.get("entryType") == "static"
            last_move = mac_entry.get("lastMove", 0.0)
            moves = mac_entry.get("moves", 0)
            mac_table.append(
                {
                    "mac": napalm.base.helpers.mac(mac_raw),
                    "interface": interface,
                    "vlan": vlan,
                    "active": True,
                    "static": static,
                    "moves": moves,
                    "last_move": last_move,
                }
            )

        return mac_table

    def get_route_to(self, destination="", protocol="", longer=False):
        routes = {}

        # Placeholder for vrf arg
        vrf = ""

        # Right not iterating through vrfs is necessary
        # show ipv6 route doesn't support vrf 'all'
        if vrf == "":
            vrfs = sorted(self._get_vrfs())
        else:
            vrfs = [vrf]

        if protocol.lower() == "direct":
            protocol = "connected"

        ipv = ""
        if IPNetwork(destination).version == 6:
            ipv = "v6"

        commands = []
        for _vrf in vrfs:
            commands.append(
                "show ip{ipv} route vrf {_vrf} {destination} {longer} {protocol} detail".format(
                    ipv=ipv,
                    _vrf=_vrf,
                    destination=destination,
                    longer="longer-prefixes" if longer else "",
                    protocol=protocol,
                )
            )

        commands_output = self.device.run_commands(commands)
        vrf_cache = {}

        for _vrf, command_output in zip(vrfs, commands_output):
            if ipv == "v6":
                routes_out = command_output.get("routes", {})
            else:
                routes_out = (
                    command_output.get("vrfs", {}).get(_vrf, {}).get("routes", {})
                )

            for prefix, route_details in routes_out.items():
                if prefix not in routes.keys():
                    routes[prefix] = []
                route_protocol = route_details.get("routeType")
                preference = route_details.get("preference", 0)

                route = {
                    "current_active": True,
                    "last_active": True,
                    "age": 0,
                    "next_hop": "",
                    "protocol": route_protocol,
                    "outgoing_interface": "",
                    "preference": preference,
                    "inactive_reason": "",
                    "routing_table": _vrf,
                    "selected_next_hop": True,
                    "protocol_attributes": {},
                }
                if protocol == "bgp" or route_protocol.lower() in ("ebgp", "ibgp"):
                    nexthop_interface_map = {}
                    for next_hop in route_details.get("vias"):
                        nexthop_ip = napalm.base.helpers.ip(next_hop.get("nexthopAddr"))
                        nexthop_interface_map[nexthop_ip] = next_hop.get("interface")
                    metric = route_details.get("metric")
                    if _vrf not in vrf_cache.keys():
                        try:
                            command = "show ip{ipv} bgp {dest} {longer} detail vrf {_vrf}".format(
                                ipv=ipv,
                                dest=destination,
                                longer="longer-prefixes" if longer else "",
                                _vrf=_vrf,
                            )
                            vrf_cache.update(
                                {
                                    _vrf: self.device.run_commands([command])[0]
                                    .get("vrfs", {})
                                    .get(_vrf, {})
                                }
                            )
                        except CommandError:
                            # Newer EOS can't mix longer-prefix and detail
                            command = "show ip{ipv} bgp {dest} {longer} vrf {_vrf}".format(
                                ipv=ipv,
                                dest=destination,
                                longer="longer-prefixes" if longer else "",
                                _vrf=_vrf,
                            )
                            vrf_cache.update(
                                {
                                    _vrf: self.device.run_commands([command])[0]
                                    .get("vrfs", {})
                                    .get(_vrf, {})
                                }
                            )

                    vrf_details = vrf_cache.get(_vrf)
                    local_as = napalm.base.helpers.as_number(vrf_details.get("asn"))
                    bgp_routes = (
                        vrf_details.get("bgpRouteEntries", {})
                        .get(prefix, {})
                        .get("bgpRoutePaths", [])
                    )
                    for bgp_route_details in bgp_routes:
                        bgp_route = route.copy()
                        as_path = bgp_route_details.get("asPathEntry", {}).get(
                            "asPath", ""
                        )
                        as_path_type = bgp_route_details.get("asPathEntry", {}).get(
                            "asPathType", ""
                        )
                        if as_path_type in ["Internal", "Local"]:
                            remote_as = local_as
                        else:
                            remote_as = napalm.base.helpers.as_number(
                                as_path.strip("()").split()[-1]
                            )
                        remote_address = napalm.base.helpers.ip(
                            bgp_route_details.get("routeDetail", {})
                            .get("peerEntry", {})
                            .get("peerAddr", "")
                        )
                        local_preference = bgp_route_details.get("localPreference")
                        next_hop = napalm.base.helpers.ip(
                            bgp_route_details.get("nextHop")
                        )
                        active_route = bgp_route_details.get("routeType", {}).get(
                            "active", False
                        )
                        last_active = active_route  # should find smth better
                        communities = bgp_route_details.get("routeDetail", {}).get(
                            "communityList", []
                        )
                        preference2 = bgp_route_details.get("weight")
                        inactive_reason = bgp_route_details.get("reasonNotBestpath", "")
                        bgp_route.update(
                            {
                                "current_active": active_route,
                                "inactive_reason": inactive_reason,
                                "last_active": last_active,
                                "next_hop": next_hop,
                                "outgoing_interface": nexthop_interface_map.get(
                                    next_hop
                                ),
                                "selected_next_hop": active_route,
                                "protocol_attributes": {
                                    "metric": metric,
                                    "as_path": as_path,
                                    "local_preference": local_preference,
                                    "local_as": local_as,
                                    "remote_as": remote_as,
                                    "remote_address": remote_address,
                                    "preference2": preference2,
                                    "communities": communities,
                                },
                            }
                        )
                        routes[prefix].append(bgp_route)
                else:
                    if route_details.get("routeAction") in ("drop",):
                        route["next_hop"] = "NULL"
                    if route_details.get("routingDisabled") is True:
                        route["last_active"] = False
                        route["current_active"] = False
                    for next_hop in route_details.get("vias"):
                        route_next_hop = route.copy()
                        if next_hop.get("nexthopAddr") is None:
                            route_next_hop.update(
                                {
                                    "next_hop": "",
                                    "outgoing_interface": next_hop.get("interface"),
                                }
                            )
                        else:
                            route_next_hop.update(
                                {
                                    "next_hop": napalm.base.helpers.ip(
                                        next_hop.get("nexthopAddr")
                                    ),
                                    "outgoing_interface": next_hop.get("interface"),
                                }
                            )
                        routes[prefix].append(route_next_hop)
                    if route_details.get("vias") == []:  # empty list
                        routes[prefix].append(route)
        return routes

    def get_snmp_information(self):
        """get_snmp_information() for EOS.  Re-written to not use TextFSM"""

        # Default values
        snmp_dict = {"chassis_id": "", "location": "", "contact": "", "community": {}}

        commands = ["show snmp chassis", "show snmp location", "show snmp contact"]
        snmp_config = self.device.run_commands(commands, encoding="json")
        for line in snmp_config:
            for k, v in line.items():
                if k == "chassisId":
                    snmp_dict["chassis_id"] = v
                else:
                    # Some EOS versions add extra quotes
                    snmp_dict[k] = v.strip('"')

        commands = ["show running-config | section snmp-server community"]
        raw_snmp_config = self.device.run_commands(commands, encoding="text")[0].get(
            "output", ""
        )
        for line in raw_snmp_config.splitlines():
            match = self._RE_SNMP_COMM.search(line)
            if match:
                matches = match.groupdict("")
                snmp_dict["community"][match.group("community")] = {
                    "acl": str(matches["v4_acl"]),
                    "mode": str(matches["access"]),
                }

        return snmp_dict

    def get_users(self):
        def _sshkey_type(sshkey):
            if sshkey.startswith("ssh-rsa"):
                return "ssh_rsa", str(sshkey)
            elif sshkey.startswith("ssh-dss"):
                return "ssh_dsa", str(sshkey)
            return "ssh_rsa", ""

        users = {}

        commands = ["show user-account"]
        user_items = self.device.run_commands(commands)[0].get("users", {})

        for user, user_details in user_items.items():
            user_details.pop("username", "")
            sshkey_value = user_details.pop("sshAuthorizedKey", "")
            sshkey_type, sshkey_value = _sshkey_type(sshkey_value)
            if sshkey_value != "":
                sshkey_list = [sshkey_value]
            else:
                sshkey_list = []
            user_details.update(
                {
                    "level": user_details.pop("privLevel", 0),
                    "password": str(user_details.pop("secret", "")),
                    "sshkeys": sshkey_list,
                }
            )
            users[user] = user_details

        return users

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
            r"\(?([a-fA-F0-9\.:][^\)]*)\)?"  # IP Address between brackets
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

        source_opt = ""
        ttl_opt = ""
        timeout_opt = ""

        # if not ttl:
        #     ttl = 20

        probes = 3
        # in case will be added one further param to adjust the number of probes/hop

        commands = []

        if vrf:
            commands.append("routing-context vrf {vrf}".format(vrf=vrf))

        if source:
            source_opt = "-s {source}".format(source=source)
        if ttl:
            ttl_opt = "-m {ttl}".format(ttl=ttl)
        if timeout:
            timeout_opt = "-w {timeout}".format(timeout=timeout)
        total_timeout = timeout * ttl
        # `ttl`, `source` and `timeout` are not supported by default CLI
        # so we need to go through the bash and set a specific timeout
        commands.append(
            (
                "bash timeout {total_timeout} traceroute {destination} "
                "{source_opt} {ttl_opt} {timeout_opt}"
            ).format(
                total_timeout=total_timeout,
                destination=destination,
                source_opt=source_opt,
                ttl_opt=ttl_opt,
                timeout_opt=timeout_opt,
            )
        )

        try:
            traceroute_raw_output = self.device.run_commands(commands, encoding="text")[
                -1
            ].get("output")
        except CommandErrorException:
            return {
                "error": "Cannot execute traceroute on the device: {}".format(
                    commands[0]
                )
            }

        hop_regex = "".join(_HOP_ENTRY + _HOP_ENTRY_PROBE * probes)

        traceroute_result["success"] = {}
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
                hop_addr = hop_details[4 + probe_index * 5]
                ip_address = napalm.base.helpers.convert(
                    napalm.base.helpers.ip, hop_addr, hop_addr
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
                traceroute_result["success"][hop_index]["probes"][probe_index + 1] = {
                    "host_name": str(host_name),
                    "ip_address": str(ip_address),
                    "rtt": rtt,
                }
                previous_probe_host_name = host_name
                previous_probe_ip_address = ip_address

        return traceroute_result

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        """Implementation of get_bgp_neighbors_detail"""

        def _parse_per_peer_bgp_detail(peer_output):
            """This function parses the raw data per peer and returns a
            json structure per peer.
            """

            int_fields = [
                "local_as",
                "remote_as",
                "local_port",
                "remote_port",
                "local_port",
                "input_messages",
                "output_messages",
                "input_updates",
                "output_updates",
                "messages_queued_out",
                "holdtime",
                "configured_holdtime",
                "keepalive",
                "configured_keepalive",
                "advertised_prefix_count",
                "received_prefix_count",
            ]

            peer_details = []

            # Using preset template to extract peer info
            peer_info = napalm.base.helpers.textfsm_extractor(
                self, "bgp_detail", peer_output
            )

            for item in peer_info:

                # Determining a few other fields in the final peer_info
                item["up"] = True if item["up"] == "up" else False
                item["local_address_configured"] = (
                    True if item["local_address"] else False
                )
                item["multihop"] = (
                    False if item["multihop"] == 0 or item["multihop"] == "" else True
                )

                # TODO: The below fields need to be retrieved
                # Currently defaulting their values to False or 0
                item["multipath"] = False
                item["remove_private_as"] = False
                item["suppress_4byte_as"] = False
                item["local_as_prepend"] = False
                item["flap_count"] = 0
                item["active_prefix_count"] = 0
                item["suppressed_prefix_count"] = 0

                # Converting certain fields into int
                for key in int_fields:
                    item[key] = napalm.base.helpers.convert(int, item[key], 0)

                # Conforming with the datatypes defined by the base class
                item["export_policy"] = napalm.base.helpers.convert(
                    str, item["export_policy"]
                )
                item["last_event"] = napalm.base.helpers.convert(
                    str, item["last_event"]
                )
                item["remote_address"] = napalm.base.helpers.ip(item["remote_address"])
                item["previous_connection_state"] = napalm.base.helpers.convert(
                    str, item["previous_connection_state"]
                )
                item["import_policy"] = napalm.base.helpers.convert(
                    str, item["import_policy"]
                )
                item["connection_state"] = napalm.base.helpers.convert(
                    str, item["connection_state"]
                )
                item["routing_table"] = napalm.base.helpers.convert(
                    str, item["routing_table"]
                )
                item["router_id"] = napalm.base.helpers.ip(item["router_id"])
                item["local_address"] = napalm.base.helpers.convert(
                    napalm.base.helpers.ip, item["local_address"]
                )

                peer_details.append(item)

            return peer_details

        def _append(bgp_dict, peer_info):

            remote_as = peer_info["remote_as"]
            vrf_name = peer_info["routing_table"]

            if vrf_name not in bgp_dict.keys():
                bgp_dict[vrf_name] = {}
            if remote_as not in bgp_dict[vrf_name].keys():
                bgp_dict[vrf_name][remote_as] = []

            bgp_dict[vrf_name][remote_as].append(peer_info)

        commands = []
        summary_commands = []
        if not neighbor_address:
            commands.append("show ip bgp neighbors vrf all")
            commands.append("show ipv6 bgp neighbors vrf all")
            summary_commands.append("show ip bgp summary vrf all")
            summary_commands.append("show ipv6 bgp summary vrf all")
        else:
            try:
                peer_ver = IPAddress(neighbor_address).version
            except Exception as e:
                raise e

            if peer_ver == 4:
                commands.append("show ip bgp neighbors %s vrf all" % neighbor_address)
                summary_commands.append("show ip bgp summary vrf all")
            elif peer_ver == 6:
                commands.append("show ipv6 bgp neighbors %s vrf all" % neighbor_address)
                summary_commands.append("show ipv6 bgp summary vrf all")

        raw_output = self.device.run_commands(commands, encoding="text")
        bgp_summary = self.device.run_commands(summary_commands, encoding="json")

        bgp_detail_info = {}

        v4_peer_info = []
        v6_peer_info = []

        if neighbor_address:
            peer_info = _parse_per_peer_bgp_detail(raw_output[0]["output"])

            if peer_ver == 4:
                v4_peer_info.append(peer_info[0])
            else:
                v6_peer_info.append(peer_info[0])

        else:
            # Using preset template to extract peer info
            v4_peer_info = _parse_per_peer_bgp_detail(raw_output[0]["output"])
            v6_peer_info = _parse_per_peer_bgp_detail(raw_output[1]["output"])

        for peer_info in v4_peer_info:

            vrf_name = peer_info["routing_table"]
            peer_remote_addr = peer_info["remote_address"]
            peer_info["accepted_prefix_count"] = (
                bgp_summary[0]["vrfs"][vrf_name]["peers"][peer_remote_addr][
                    "prefixAccepted"
                ]
                if peer_remote_addr in bgp_summary[0]["vrfs"][vrf_name]["peers"].keys()
                else 0
            )

            _append(bgp_detail_info, peer_info)

        for peer_info in v6_peer_info:

            vrf_name = peer_info["routing_table"]
            peer_remote_addr = peer_info["remote_address"]
            peer_info["accepted_prefix_count"] = (
                bgp_summary[1]["vrfs"][vrf_name]["peers"][peer_remote_addr][
                    "prefixAccepted"
                ]
                if peer_remote_addr in bgp_summary[1]["vrfs"][vrf_name]["peers"].keys()
                else 0
            )

            _append(bgp_detail_info, peer_info)

        return bgp_detail_info

    def get_optics(self):

        command = ["show interfaces transceiver"]

        output = self.device.run_commands(command, encoding="json")[0]["interfaces"]

        # Formatting data into return data structure
        optics_detail = {}

        for port, port_values in output.items():
            port_detail = {"physical_channels": {"channel": []}}

            # Defaulting avg, min, max values to 0.0 since device does not
            # return these values
            optic_states = {
                "index": 0,
                "state": {
                    "input_power": {
                        "instant": (
                            port_values["rxPower"] if "rxPower" in port_values else 0.0
                        ),
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0,
                    },
                    "output_power": {
                        "instant": (
                            port_values["txPower"] if "txPower" in port_values else 0.0
                        ),
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0,
                    },
                    "laser_bias_current": {
                        "instant": (
                            port_values["txBias"] if "txBias" in port_values else 0.0
                        ),
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0,
                    },
                },
            }

            port_detail["physical_channels"]["channel"].append(optic_states)
            optics_detail[port] = port_detail

        return optics_detail

    def get_config(self, retrieve="all", full=False, sanitized=False):
        """get_config implementation for EOS."""
        get_startup = retrieve == "all" or retrieve == "startup"
        get_running = retrieve == "all" or retrieve == "running"
        get_candidate = (
            retrieve == "all" or retrieve == "candidate"
        ) and self.config_session

        # EOS only supports "all" on "show run"
        run_full = " all" if full else ""
        run_sanitized = " sanitized" if sanitized else ""

        if retrieve == "all":
            commands = [
                "show startup-config",
                "show running-config{0}{1}".format(run_full, run_sanitized),
            ]

            if self.config_session:
                commands.append(
                    "show session-config named {0}{1}".format(
                        self.config_session, run_sanitized
                    )
                )

            output = self.device.run_commands(commands, encoding="text")
            startup_cfg = str(output[0]["output"]) if get_startup else ""
            if sanitized and startup_cfg:
                startup_cfg = napalm.base.helpers.sanitize_config(
                    startup_cfg, c.CISCO_SANITIZE_FILTERS
                )
            return {
                "startup": startup_cfg,
                "running": str(output[1]["output"]) if get_running else "",
                "candidate": str(output[2]["output"]) if get_candidate else "",
            }
        elif get_startup or get_running:
            if retrieve == "running":
                commands = ["show {}-config{}".format(retrieve, run_full)]
            elif retrieve == "startup":
                commands = ["show {}-config".format(retrieve)]
            output = self.device.run_commands(commands, encoding="text")
            return {
                "startup": str(output[0]["output"]) if get_startup else "",
                "running": str(output[0]["output"]) if get_running else "",
                "candidate": "",
            }
        elif get_candidate:
            commands = ["show session-config named {}".format(self.config_session)]
            output = self.device.run_commands(commands, encoding="text")
            return {"startup": "", "running": "", "candidate": str(output[0]["output"])}
        elif retrieve == "candidate":
            # If we get here it means that we want the candidate but there is none.
            return {"startup": "", "running": "", "candidate": ""}
        else:
            raise Exception("Wrong retrieve filter: {}".format(retrieve))

    def _show_vrf(self):
        commands = ["show vrf"]

        # This command has no JSON yet
        raw_output = self.device.run_commands(commands, encoding="text")[0].get(
            "output", ""
        )

        output = napalm.base.helpers.textfsm_extractor(self, "vrf", raw_output)

        return output

    def _get_vrfs(self):
        output = self._show_vrf()

        vrfs = [str(vrf["name"]) for vrf in output]

        vrfs.append("default")

        return vrfs

    def get_network_instances(self, name=""):
        """get_network_instances implementation for EOS."""

        output = self._show_vrf()
        vrfs = {}
        all_vrf_interfaces = {}
        for vrf in output:
            if (
                vrf.get("route_distinguisher", "") == "<not set>"
                or vrf.get("route_distinguisher", "") == "None"
            ):
                vrf["route_distinguisher"] = ""
            else:
                vrf["route_distinguisher"] = str(vrf["route_distinguisher"])
            interfaces = {}
            for interface_raw in vrf.get("interfaces", []):
                interface = interface_raw.split(",")
                for line in interface:
                    if line.strip() != "":
                        interfaces[str(line.strip())] = {}
                        all_vrf_interfaces[str(line.strip())] = {}

            vrfs[str(vrf["name"])] = {
                "name": str(vrf["name"]),
                "type": "L3VRF",
                "state": {"route_distinguisher": vrf["route_distinguisher"]},
                "interfaces": {"interface": interfaces},
            }
        all_interfaces = self.get_interfaces_ip().keys()
        vrfs["default"] = {
            "name": "default",
            "type": "DEFAULT_INSTANCE",
            "state": {"route_distinguisher": ""},
            "interfaces": {
                "interface": {
                    k: {} for k in all_interfaces if k not in all_vrf_interfaces.keys()
                }
            },
        }

        if name:
            if name in vrfs:
                return {str(name): vrfs[name]}
            return {}
        else:
            return vrfs

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
        commands = []

        if vrf:
            commands.append("routing-context vrf {vrf}".format(vrf=vrf))

        command = "ping {}".format(destination)
        command += " timeout {}".format(timeout)
        command += " size {}".format(size)
        command += " repeat {}".format(count)
        if source != "":
            command += " source {}".format(source)

        commands.append(command)
        output = self.device.run_commands(commands, encoding="text")[-1]["output"]

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
                            "rtt_stddev": float(m[3]),
                        }
                    )
            ping_dict["success"].update({"results": results_array})
        return ping_dict
