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

"""Parsing functions for Arista EOS driver responses."""

import time
from typing import Any, Dict, List

import napalm.base.helpers
from napalm.base.utils import string_parsers


def parse_facts_response(
    version: Dict[str, Any],
    hostname: Dict[str, Any],
    interfaces: Dict[str, Any],
) -> Dict[str, Any]:
    interfaces_dict = interfaces["interfaces"]

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
        "uptime": float(uptime),
        "interface_list": interfaces,
    }


def parse_arp_table_response(
    show_arp: Dict[str, Any], vrf: str = ""
) -> List[Dict[str, Any]]:
    arp_table = []

    ipv4_neighbors = [
        neighbor
        for k, v in show_arp.get("vrfs").items()
        if not vrf or k == vrf
        for neighbor in v.get("ipV4Neighbors", [])
    ]

    for neighbor in ipv4_neighbors:
        interface = str(neighbor.get("interface"))
        mac_raw = neighbor.get("hwAddress")
        ip = str(neighbor.get("address"))
        age = float(neighbor.get("age", -1.0))
        arp_table.append(
            {
                "interface": interface,
                "mac": napalm.base.helpers.mac(mac_raw),
                "ip": napalm.base.helpers.ip(ip),
                "age": age,
            }
        )

    return arp_table


def parse_mac_address_table_response(
    show_mac_address_table: Dict[str, Any],
) -> List[Dict[str, Any]]:
    mac_table = []

    mac_entries = show_mac_address_table.get("unicastTable", {}).get("tableEntries", [])

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


def parse_interfaces_response(show_interfaces: Dict[str, Any]) -> Dict[str, Any]:
    interfaces = {}

    for interface, values in show_interfaces["interfaces"].items():
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
        interfaces[interface]["speed"] = float(values["bandwidth"] / 1000000.0)
        interfaces[interface]["mac_address"] = napalm.base.helpers.convert(
            napalm.base.helpers.mac, values.pop("physicalAddress", "")
        )

    return interfaces


def parse_lldp_neighbors_response(
    lldp_neighbors: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, str]]]:
    lldp_neighbors = lldp_neighbors["lldpNeighbors"]
    lldp = {}

    for n in lldp_neighbors:
        if n["port"] not in lldp.keys():
            lldp[n["port"]] = []

        lldp[n["port"]].append(
            {"hostname": n["neighborDevice"], "port": n["neighborPort"]}
        )

    return lldp


def parse_interfaces_counters_response(
    show_interfaces: Dict[str, Any],
) -> Dict[str, Dict[str, int]]:
    interface_counters: Dict[str, Dict[str, int]] = {}

    for interface, data in show_interfaces["interfaces"].items():
        if data["hardware"] == "subinterface":
            continue
        counters = data.get("interfaceCounters", {})
        interface_counters[interface] = {
            "tx_octets": counters.get("outOctets", -1),
            "rx_octets": counters.get("inOctets", -1),
            "tx_unicast_packets": counters.get("outUcastPkts", -1),
            "rx_unicast_packets": counters.get("inUcastPkts", -1),
            "tx_multicast_packets": counters.get("outMulticastPkts", -1),
            "rx_multicast_packets": counters.get("inMulticastPkts", -1),
            "tx_broadcast_packets": counters.get("outBroadcastPkts", -1),
            "rx_broadcast_packets": counters.get("inBroadcastPkts", -1),
            "tx_discards": counters.get("outDiscards", -1),
            "rx_discards": counters.get("inDiscards", -1),
            "tx_errors": counters.get("totalOutErrors", -1),
            "rx_errors": counters.get("totalInErrors", -1),
        }

    return interface_counters


def parse_users_response(show_users_accounts: Dict[str, Any]) -> Dict[str, Any]:
    def _sshkey_type(sshkey: str) -> tuple[str, str]:
        if sshkey.startswith("ssh-rsa"):
            return "ssh_rsa", str(sshkey)
        elif sshkey.startswith("ssh-dss"):
            return "ssh_dsa", str(sshkey)
        return "ssh_rsa", ""

    users: Dict[str, Any] = {}

    user_items = show_users_accounts.get("users", {})

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


def parse_lldp_neighbors_detail_response(
    lldp_neighbors_in: Dict[str, Any],
    transform_lldp_capab: Any,
) -> Dict[str, List[Dict[str, Any]]]:
    lldp_neighbors_out: Dict[str, List[Dict[str, Any]]] = {}

    for interface in lldp_neighbors_in:
        interface_neighbors = lldp_neighbors_in.get(interface).get(
            "lldpNeighborInfo", {}
        )
        if not interface_neighbors:
            continue

        for neighbor in interface_neighbors:
            if interface not in lldp_neighbors_out.keys():
                lldp_neighbors_out[interface] = []
            capabilities = neighbor.get("systemCapabilities", {})
            available_capabilities = transform_lldp_capab(capabilities.keys())
            enabled_capabilities = transform_lldp_capab(
                [capab for capab, enabled in capabilities.items() if enabled]
            )
            remote_chassis_id = neighbor.get("chassisId", "")
            if neighbor.get("chassisIdType", "") == "macAddress":
                remote_chassis_id = napalm.base.helpers.mac(remote_chassis_id)
            neighbor_interface_info = neighbor.get("neighborInterfaceInfo", {})
            lldp_neighbors_out[interface].append(
                {
                    "parent_interface": interface,
                    "remote_port": neighbor_interface_info.get(
                        "interfaceId", ""
                    ).replace('"', ""),
                    "remote_port_description": neighbor_interface_info.get(
                        "interfaceDescription", ""
                    ),
                    "remote_system_name": neighbor.get("systemName", ""),
                    "remote_system_description": neighbor.get("systemDescription", ""),
                    "remote_chassis_id": remote_chassis_id,
                    "remote_system_capab": available_capabilities,
                    "remote_system_enable_capab": enabled_capabilities,
                }
            )
    return lldp_neighbors_out


def parse_config_response(
    output: List[Dict[str, Any]],
    retrieve: str,
    get_startup: bool,
    get_running: bool,
    get_candidate: bool,
    sanitized: bool,
    cisco_sanitize_filters: List[str],
) -> Dict[str, str]:
    if retrieve == "all":
        startup_cfg = str(output[0]["output"]) if get_startup else ""
        if sanitized and startup_cfg:
            startup_cfg = napalm.base.helpers.sanitize_config(
                startup_cfg, cisco_sanitize_filters
            )
        return {
            "startup": startup_cfg,
            "running": str(output[1]["output"]) if get_running else "",
            "candidate": str(output[2]["output"]) if get_candidate else "",
        }
    elif get_startup or get_running:
        return {
            "startup": str(output[0]["output"]) if get_startup else "",
            "running": str(output[0]["output"]) if get_running else "",
            "candidate": "",
        }
    elif get_candidate:
        return {"startup": "", "running": "", "candidate": str(output[0]["output"])}
    elif retrieve == "candidate":
        return {"startup": "", "running": "", "candidate": ""}
    else:
        raise Exception("Wrong retrieve filter: {}".format(retrieve))


def parse_snmp_information_response(
    snmp_config: List[Dict[str, Any]],
    raw_snmp_config: str,
    snmp_comm_regex: Any,
) -> Dict[str, Any]:
    snmp_dict: Dict[str, Any] = {
        "chassis_id": "",
        "location": "",
        "contact": "",
        "community": {},
    }

    for line in snmp_config:
        for k, v in line.items():
            if k == "chassisId":
                snmp_dict["chassis_id"] = v
            else:
                snmp_dict[k] = v.strip('"')

    for line in raw_snmp_config.splitlines():
        match = snmp_comm_regex.search(line)
        if match:
            matches = match.groupdict("")
            snmp_dict["community"][match.group("community")] = {
                "acl": str(matches["v4_acl"]),
                "mode": str(matches["access"]),
            }

    return snmp_dict
