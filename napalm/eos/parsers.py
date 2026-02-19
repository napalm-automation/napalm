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
