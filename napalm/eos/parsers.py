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


def parse_vlans_response(output: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    vlans: Dict[str, Dict[str, Any]] = {}
    for vlan, vlan_config in output.items():
        vlans[vlan] = {
            "name": vlan_config["name"],
            "interfaces": list(vlan_config["interfaces"].keys()),
        }

    return vlans


def parse_optics_response(output: Dict[str, Any]) -> Dict[str, Any]:
    optics_detail: Dict[str, Any] = {}

    for port, port_values in output.items():
        port_detail: Dict[str, Any] = {"physical_channels": {"channel": []}}

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


def parse_ntp_stats_response(ntp_assoc_output: str) -> List[Dict[str, Any]]:
    import re

    ntp_stats = []

    REGEX = (
        r"^\s?(\+|\*|x|-)?([a-zA-Z0-9\.+-:]+)"
        r"\s+([a-zA-Z0-9\.]+)\s+([0-9]{1,2})"
        r"\s+(-|u)\s+([0-9h-]+)\s+([0-9]+)"
        r"\s+([0-9]+)\s+([0-9\.]+)\s+([0-9\.-]+)"
        r"\s+([0-9\.]+)\s?$"
    )

    ntp_assoc_lines = ntp_assoc_output.splitlines()[2:]

    for ntp_assoc in ntp_assoc_lines:
        line_search = re.search(REGEX, ntp_assoc, re.I)
        if not line_search:
            continue
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
            continue

    return ntp_stats


def parse_ntp_servers_response(
    raw_ntp_config: List[str],
    interfaces: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}

    for server in raw_ntp_config:
        details: Dict[str, Any] = {
            "port": 123,
            "version": 4,
            "association_type": "SERVER",
            "iburst": False,
            "prefer": False,
            "network_instance": "default",
            "source_address": "",
            "key_id": -1,
        }
        tokens = server.split()
        if tokens[0] != "ntp":
            continue
        if tokens[2] == "vrf":
            details["network_instance"] = tokens[3]
            server_ip = details["address"] = tokens[4]
            idx = 5
        else:
            server_ip = details["address"] = tokens[2]
            idx = 3
        try:
            parsed_address = napalm.base.helpers.ipaddress.ip_address(server_ip)
            family = parsed_address.version
        except ValueError:
            family = 4
        while idx < len(tokens):
            if tokens[idx] == "iburst":
                details["iburst"] = True
                idx += 1

            elif tokens[idx] == "key":
                details["key_id"] = int(tokens[idx + 1])
                idx += 2

            elif tokens[idx] == "local-interface":
                intf = tokens[idx + 1]
                if family == 6 and interfaces[intf]["ipv6"]:
                    details["source_address"] = list(interfaces[intf]["ipv6"].keys())[0]
                elif interfaces[intf]["ipv4"]:
                    details["source_address"] = list(interfaces[intf]["ipv4"].keys())[0]
                elif interfaces[intf]["ipv6"]:
                    details["source_address"] = list(interfaces[intf]["ipv6"].keys())[0]
                idx += 2

            elif tokens[idx] == "version":
                details["version"] = int(tokens[idx + 1])
                idx += 2

            elif tokens[idx] == "prefer":
                details["prefer"] = True
                idx += 1
            else:
                idx += 1

        result[server_ip] = details

    return result


def parse_network_instances_response(
    show_vrf_output: List[Dict[str, Any]],
    get_interfaces_ip_func: Any,
    name: str = "",
) -> Dict[str, Dict[str, Any]]:
    vrfs: Dict[str, Dict[str, Any]] = {}
    all_vrf_interfaces: Dict[str, Any] = {}
    for vrf in show_vrf_output:
        if (
            vrf.get("route_distinguisher", "") == "<not set>"
            or vrf.get("route_distinguisher", "") == "None"
        ):
            vrf["route_distinguisher"] = ""
        else:
            vrf["route_distinguisher"] = str(vrf["route_distinguisher"])
        interfaces: Dict[str, Dict[str, Any]] = {}
        for interface_raw in vrf.get("interfaces", []):
            interface = interface_raw.split(",")
            for line in interface:
                if line.strip() != "":
                    interfaces[str(line.strip())] = {}
                    all_vrf_interfaces[str(line.strip())] = {}

        vrfs[vrf["name"]] = {
            "name": vrf["name"],
            "type": "DEFAULT_INSTANCE" if vrf["name"] == "default" else "L3VRF",
            "state": {"route_distinguisher": vrf["route_distinguisher"]},
            "interfaces": {"interface": interfaces},
        }
    if "default" not in vrfs:
        all_interfaces = get_interfaces_ip_func().keys()
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


def parse_environment_response(
    fans_output: Dict[str, Any],
    temp_output: Dict[str, Any],
    power_output: Dict[str, Any],
    cpu_output: str,
    is_veos: bool,
    cpu_idle_regex: str,
    mem_regex: str,
) -> Dict[str, Any]:
    import re

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

    def _parse_memory(unit, total, used):
        if unit == "MiB":
            return {
                "available_ram": int(float(total) * 1024),
                "used_ram": int(float(used) * 1024),
            }
        return {
            "available_ram": int(total),
            "used_ram": int(used),
        }

    environment_counters = {"fans": {}, "temperature": {}, "power": {}, "cpu": {}}

    for slot in fans_output["fanTraySlots"]:
        environment_counters["fans"][slot["label"]] = {"status": slot["status"] == "ok"}

    for fru_type in ["cardSlots", "powerSupplySlots"]:
        for fru in temp_output[fru_type]:
            t = {
                name: value
                for name, value in extract_temperature_data(fru["tempSensors"])
            }
            environment_counters["temperature"].update(t)

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
    m = re.match(cpu_idle_regex, cpu_lines[2])
    environment_counters["cpu"][0] = {"%usage": round(100 - float(m.group("idle")), 1)}

    m = re.match(mem_regex, cpu_lines[3])
    environment_counters["memory"] = _parse_memory(
        m.group("unit"), m.group("total"), m.group("used1") or m.group("used2")
    )

    return environment_counters


def parse_bgp_config_response(
    bgp_conf_output: str,
    group: str = "",
    neighbor: str = "",
) -> Dict[str, Dict[str, Any]]:
    import ipaddress

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
        "next-hop-self": "nhs",
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

    def default_group_dict(local_as: int) -> Dict[str, Any]:
        group_dict = {}
        group_dict.update(
            {
                key: _DATATYPE_DEFAULT_.get(_PROPERTY_TYPE_MAP_.get(prop))
                for prop, key in _GROUP_FIELD_MAP_.items()
            }
        )
        group_dict.update({"prefix_limit": {}, "neighbors": {}, "local_as": local_as})
        return group_dict

    def default_neighbor_dict(
        local_as: int, group_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        neighbor_dict = {}
        neighbor_dict.update(
            {
                key: _DATATYPE_DEFAULT_.get(_PROPERTY_TYPE_MAP_.get(prop))
                for prop, key in _PEER_FIELD_MAP_.items()
            }
        )
        neighbor_dict.update(
            {"prefix_limit": {}, "local_as": local_as, "authentication_key": ""}
        )
        neighbor_dict.update(
            {
                key: group_dict.get(key)
                for key in _GROUP_FIELD_MAP_.values()
                if key in group_dict and key in _PEER_FIELD_MAP_.values()
            }
        )
        return neighbor_dict

    def parse_options(
        options: List[str], default_value: bool = False
    ) -> Dict[str, Any]:
        if not options:
            return {}

        config_property = options[0]
        field_name = _PROPERTY_FIELD_MAP_.get(config_property)
        field_type = _PROPERTY_TYPE_MAP_.get(config_property)
        field_value = _DATATYPE_DEFAULT_.get(field_type)

        if not field_type:
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
            if config_property == "password":
                return {"authentication_key": str(options[2])}
            if config_property == "route-map":
                direction = None
                if len(options) == 3:
                    direction = options[2]
                    field_value = field_type(options[1])
                elif len(options) == 2:
                    direction = options[1]
                if direction == "in":
                    field_name = "import_policy"
                else:
                    field_name = "export_policy"
                return {field_name: field_value}

        return {}

    bgp_config = {}

    bgp_conf_lines = bgp_conf_output.splitlines()

    bgp_neighbors: Dict[str, Dict[str, Any]] = {}

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
            ipaddress.ip_address(group_or_neighbor)
            peer_address = group_or_neighbor
            group_name = None
            if options[0] == "peer-group":
                group_name = options[1]
            elif options[0] == "peer" and options[1] == "group":
                group_name = options[2]
            if peer_address not in bgp_neighbors:
                bgp_neighbors[peer_address] = default_neighbor_dict(
                    local_as, bgp_config.get(group_name, {})
                )

            if group_name:
                bgp_neighbors[peer_address]["__group"] = group_name

            bgp_neighbors[peer_address].update(parse_options(options, default_value))
        except ValueError:
            group_name = group_or_neighbor
            if group and group_name != group:
                continue
            if group_name not in bgp_config.keys():
                bgp_config[group_name] = default_group_dict(local_as)
            bgp_config[group_name].update(parse_options(options, default_value))

    bgp_config["_"] = default_group_dict(local_as)

    for peer, peer_details in bgp_neighbors.items():
        peer_group = peer_details.pop("__group", None)
        if not peer_group:
            peer_group = "_"
        if peer_group not in bgp_config:
            bgp_config[peer_group] = default_group_dict(local_as)
        bgp_config[peer_group]["neighbors"][peer] = peer_details

    [v.pop("nhs", None) for v in bgp_config.values()]

    if local_as == 0:
        return {}

    return bgp_config
