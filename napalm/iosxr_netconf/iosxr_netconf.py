# -*- coding: utf-8 -*-
# Copyright 2020 CISCO. All rights reserved.
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

"""NETCONF Driver for IOSXR devices."""

from __future__ import unicode_literals

# import stdlib
import copy

# import third party lib
from ncclient import manager
from lxml import etree as ETREE
from ncclient.xml_ import to_ele

# import NAPALM base
from napalm.iosxr_netconf import constants as C
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionException
import napalm.base.helpers
from napalm.base.utils import py23_compat
from napalm.base.utils.py23_compat import text_type


class IOSXRNETCONFDriver(NetworkDriver):
    """IOS-XR NETCONF driver class: inherits NetworkDriver from napalm.base."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialize IOSXR driver.

        optional_args:
            * config_lock (True/False): lock configuration DB after the
                connection is established.
            * port (int): custom port
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.pending_changes = False
        self.replace = False
        self.locked = False
        if optional_args is None:
            optional_args = {}

        self.port = optional_args.get("port", 830)
        self.lock_on_connect = optional_args.get("config_lock", False)

        self.platform = "iosxr"
        self.netconf_ssh = None

    def open(self):
        """Open the connection with the device."""
        try:
            self.netconf_ssh = manager.connect(
                           host=self.hostname,
                           port=self.port,
                           username=self.username,
                           password=self.password,
                           timeout=self.timeout,
                           device_params={'name': 'iosxr'})
            if not self.lock_on_connect:
                self._lock()
        except Exception as conn_err:
            raise ConnectionException(conn_err.args[0])

    def close(self):
        """Close the connection."""
        return NotImplementedError

    def _lock(self):
        """Lock the config DB."""
        if not self.locked:
            self.netconf_ssh.lock()
            self.locked = True

    def _unlock(self):
        """Unlock the config DB."""
        if self.locked:
            self.netconf_ssh.unlock()
            self.locked = False

    def _load_candidate_config(self, filename, config, default_operation):
        """Edit Configuration."""
        pass

    def is_alive(self):
        """Return flag with the state of the connection."""
        return NotImplementedError

    def load_replace_candidate(self, filename=None, config=None):
        """Open the candidate config and replace."""
        return NotImplementedError

    def load_merge_candidate(self, filename=None, config=None):
        """Open the candidate config and merge."""
        return NotImplementedError

    def compare_config(self):
        """Compare candidate config with running."""
        return NotImplementedError

    def commit_config(self, message=""):
        """Commit configuration."""
        return NotImplementedError

    def discard_config(self):
        """Discard changes."""
        return NotImplementedError

    def rollback(self):
        """Rollback to previous commit."""
        return NotImplementedError

    def _find_txt(self, xml_tree, path, default="", namespace=None):
        """
        Extract the text value from an XML tree, using XPath.

        In case of error, will return a default value.
        :param xml_tree:the XML Tree object. <type'lxml.etree._Element'>.
        :param path:XPath to be applied, in order to extract the desired data.
        :param default:  Value to be returned in case of error.
        :param ns: namespace dict
        :return: a str value.
        """
        value = ""
        try:
            xpath_applied = xml_tree.xpath(path, namespaces=namespace)
            if len(xpath_applied) and xpath_applied[0] is not None:
                xpath_result = xpath_applied[0]
                value = xpath_result.text.strip()
        except Exception:  # in case of any exception, returns default
            value = default
        return py23_compat.text_type(value)

    def get_facts(self):
        """Return facts of the device."""
        facts = {
            "vendor": "Cisco",
            "os_version": "",
            "hostname": "",
            "uptime": -1,
            "serial_number": "",
            "fqdn": "",
            "model": "",
            "interface_list": [],
        }

        interface_list = []

        facts_rpc_reply = self.netconf_ssh.dispatch(to_ele(C.FACTS_RPC_REQ)).xml

        # Converts string to etree
        facts_rpc_reply_etree = ETREE.fromstring(facts_rpc_reply)

        # Retrieves hostname
        hostname = napalm.base.helpers.convert(
            text_type, self._find_txt(facts_rpc_reply_etree, ".//suo:system-time/\
            suo:uptime/suo:host-name", namespace=C.NS)
        )

        # Retrieves uptime
        uptime = napalm.base.helpers.convert(
            int, self._find_txt(facts_rpc_reply_etree, ".//suo:system-time/\
            suo:uptime/suo:uptime", namespace=C.NS), -1
        )

        # Retrieves interfaces name
        interface_tree = facts_rpc_reply_etree.xpath(
                        ".//int:interfaces/int:interfaces/int:interface",
                        namespaces=C.NS)
        for interface in interface_tree:
            name = self._find_txt(interface, "./int:interface-name", namespace=C.NS)
            interface_list.append(name)

        # Retrieves os version, model, serial number
        basic_info_tree = facts_rpc_reply_etree.xpath(
                        ".//imo:inventory/imo:racks/imo:rack/imo:attributes/\
                        imo:inv-basic-bag", namespaces=C.NS)[0]
        os_version = napalm.base.helpers.convert(
            text_type,
            self._find_txt(
                basic_info_tree, "./imo:software-revision", namespace=C.NS)
        )
        model = napalm.base.helpers.convert(
            text_type,
            self._find_txt(basic_info_tree, "./imo:model-name", namespace=C.NS)
        )
        serial = napalm.base.helpers.convert(
            text_type, self._find_txt(
                basic_info_tree, "./imo:serial-number", namespace=C.NS)
        )

        facts.update(
            {
                "os_version": os_version,
                "hostname": hostname,
                "model": model,
                "uptime": uptime,
                "serial_number": serial,
                "fqdn": hostname,
                "interface_list": interface_list,
            }
        )

        return facts

    def get_interfaces(self):
        """Return interfaces details."""
        interfaces = {}

        INTERFACE_DEFAULTS = {
            "is_enabled": False,
            "is_up": False,
            "mac_address": "",
            "description": "",
            "speed": -1,
            "last_flapped": -1.0,
        }

        interfaces_rpc_reply = self.netconf_ssh.get(filter=(
                                    'subtree', C.INT_RPC_REQ_FILTER)).xml
        # Converts string to etree
        interfaces_rpc_reply_etree = ETREE.fromstring(interfaces_rpc_reply)

        # Retrieves interfaces details
        for (interface_tree, description_tree) in zip(
                interfaces_rpc_reply_etree.xpath(
                ".//int:interfaces/int:interface-xr/int:interface",
                namespaces=C.NS),
                interfaces_rpc_reply_etree.xpath(
                ".//int:interfaces/int:interfaces/int:interface",
                namespaces=C.NS)):

            interface_name = self._find_txt(
                    interface_tree, "./int:interface-name", namespace=C.NS)
            if not interface_name:
                continue
            is_up = (self._find_txt(
                interface_tree, "./int:line-state", namespace=C.NS) == "im-state-up")
            enabled = (self._find_txt(
                interface_tree, "./int:state", namespace=C.NS)
                != "im-state-admin-down")
            raw_mac = self._find_txt(
                interface_tree, "./int:mac-address/int:address", namespace=C.NS)
            mac_address = napalm.base.helpers.convert(
                napalm.base.helpers.mac, raw_mac, raw_mac
            )
            speed = napalm.base.helpers.convert(
                int, napalm.base.helpers.convert(int, self._find_txt(
                 interface_tree, "./int:bandwidth", namespace=C.NS), 0) * 1e-3,)
            mtu = int(self._find_txt(interface_tree, "./int:mtu", namespace=C.NS))
            description = self._find_txt(
                description_tree, "./int:description", namespace=C.NS)
            interfaces[interface_name] = copy.deepcopy(INTERFACE_DEFAULTS)
            interfaces[interface_name].update(
                {
                    "is_up": is_up,
                    "speed": speed,
                    "mtu": mtu,
                    "is_enabled": enabled,
                    "mac_address": mac_address,
                    "description": description,
                }
            )

        return interfaces

    def get_interfaces_counters(self):
        """Return interfaces counters."""
        rpc_reply = self.netconf_ssh.get(filter=(
                    'subtree', C.INT_COUNTERS_RPC_REQ_FILTER)).xml
        # Converts string to tree
        rpc_reply_etree = ETREE.fromstring(rpc_reply)

        interface_counters = {}

        # Retrieves interfaces counters details
        interface_xr_tree = rpc_reply_etree.xpath(
            ".//int:interfaces/int:interface-xr/int:interface", namespaces=C.NS)
        for interface in interface_xr_tree:
            interface_name = self._find_txt(
                interface, "./int:interface-name", namespace=C.NS)
            interface_stats = {}
            if not interface.xpath(
                    "./int:interface-statistics/int:full-interface-stats", namespaces=C.NS):
                continue
            else:
                interface_stats = {}
                int_stats_xpath = "./int:interface-statistics/int:full-interface-stats/"
                interface_stats["tx_multicast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:multicast-packets-sent", "0", namespace=C.NS
                    ),
                )
                interface_stats["tx_discards"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:output-drops", "0", namespace=C.NS
                    ),
                )
                interface_stats["tx_octets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:bytes-sent", "0", namespace=C.NS
                    ),
                )
                interface_stats["tx_errors"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:output-errors", "0", namespace=C.NS
                    ),
                )
                interface_stats["rx_octets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:bytes-received", "0", namespace=C.NS
                    ),
                )
                interface_stats["tx_unicast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:packets-sent", "0", namespace=C.NS
                    ),
                )
                interface_stats["rx_errors"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:input-errors", "0", namespace=C.NS
                    ),
                )
                interface_stats["tx_broadcast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:broadcast-packets-sent", "0", namespace=C.NS
                    ),
                )
                interface_stats["rx_multicast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:multicast-packets-received", "0", namespace=C.NS
                    ),
                )
                interface_stats["rx_broadcast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:broadcast-packets-received", "0", namespace=C.NS
                    ),
                )
                interface_stats["rx_discards"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:input-drops", "0", namespace=C.NS
                    ),
                )
                interface_stats["rx_unicast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface, int_stats_xpath+"int:packets-received", "0", namespace=C.NS
                    ),
                )
            interface_counters[interface_name] = interface_stats

        return interface_counters

    def get_bgp_neighbors(self):
        """Return BGP neighbors details."""
        return NotImplementedError

    def get_environment(self):
        """Return environment details."""
        return NotImplementedError

    def get_lldp_neighbors(self):
        """Return LLDP neighbors details."""
        return NotImplementedError

    def get_lldp_neighbors_detail(self, interface=""):
        """Detailed view of the LLDP neighbors."""
        return NotImplementedError

    def cli(self, commands):
        """Execute raw CLI commands and returns their output."""
        return NotImplementedError

    def get_bgp_config(self, group="", neighbor=""):
        """Return BGP configuration."""
        return NotImplementedError

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        """Detailed view of the BGP neighbors operational data."""
        return NotImplementedError

    def get_arp_table(self, vrf=""):
        """Return the ARP table."""
        return NotImplementedError

    def get_ntp_peers(self):
        """Return the NTP peers configured on the device."""
        ntp_peers = {}

        rpc_reply = self.netconf_ssh.get_config(source="running", filter=(
                        'subtree', C.NTP_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        for version in ["ipv4", "ipv6"]:
            ntp_xpath = ".//ntpc:ntp/ntpc:peer-vrfs/ntpc:peer-vrf/\
                        ntpc:peer-{version}s".format(version=version)
            for peer in result_tree.xpath(ntp_xpath+"/ntpc:peer-{version}".format(
                    version=version), namespaces=C.NS):
                peer_type = self._find_txt(peer, "./ntpc:peer-type-{version}/\
                    ntpc:peer-type".format(version=version), namespace=C.NS)
                if peer_type != "peer":
                    continue
                peer_address = self._find_txt(
                    peer, "./ntpc:address-{version}".format(
                            version=version), namespace=C.NS)
                if not peer_address:
                    continue
                ntp_peers[peer_address] = {}

        return ntp_peers

    def get_ntp_servers(self):
        """Return the NTP servers configured on the device."""
        ntp_servers = {}

        rpc_reply = self.netconf_ssh.get_config(source="running", filter=(
                            "subtree", C.NTP_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        for version in ["ipv4", "ipv6"]:
            ntp_xpath = ".//ntpc:ntp/ntpc:peer-vrfs/ntpc:peer-vrf/\
                        ntpc:peer-{version}s".format(version=version)
            for peer in result_tree.xpath(
                    ntp_xpath+"/ntpc:peer-{version}".format(
                    version=version), namespaces=C.NS):
                peer_type = self._find_txt(peer, "./ntpc:peer-type-{version}/\
                    ntpc:peer-type".format(version=version), namespace=C.NS)
                if peer_type != "server":
                    continue
                server_address = self._find_txt(
                        peer, "./ntpc:address-{version}".format(
                                version=version), namespace=C.NS)
                if not server_address:
                    continue
                ntp_servers[server_address] = {}

        return ntp_servers

    def get_ntp_stats(self):
        """Return NTP stats (associations)."""
        ntp_stats = []

        rpc_reply = self.netconf_ssh.get(filter=(
                            "subtree", C.NTP_STAT_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        xpath = ".//ntp:ntp/ntp:nodes/ntp:node/ntp:associations/\
                ntp:peer-summary-info/ntp:peer-info-common"
        for node in result_tree.xpath(xpath, namespaces=C.NS):
            synchronized = self._find_txt(
                        node, "./ntp:is-sys-peer", namespace=C.NS) == "true"
            address = self._find_txt(node, "./ntp:address", namespace=C.NS)
            if address == "DLRSC node":
                continue
            referenceid = self._find_txt(node, "./ntp:reference-id", namespace=C.NS)
            hostpoll = napalm.base.helpers.convert(
                int, self._find_txt(node, "./ntp:host-poll", "0", namespace=C.NS)
            )
            reachability = napalm.base.helpers.convert(
                int, self._find_txt(node, "./ntp:reachability", "0", namespace=C.NS)
            )
            stratum = napalm.base.helpers.convert(
                int, self._find_txt(node, "./ntp:stratum", "0", namespace=C.NS)
            )
            delay = napalm.base.helpers.convert(
                float, self._find_txt(node, "./ntp:delay", "0.0", namespace=C.NS)
            )
            offset = napalm.base.helpers.convert(
                float, self._find_txt(node, "./ntp:offset", "0.0", namespace=C.NS)
            )
            jitter = napalm.base.helpers.convert(
                float, self._find_txt(node, "./ntp:dispersion", "0.0", namespace=C.NS)
            )

            ntp_stats.append(
                {
                    "remote": address,
                    "synchronized": synchronized,
                    "referenceid": referenceid,
                    "stratum": stratum,
                    "type": "",
                    "when": "",
                    "hostpoll": hostpoll,
                    "reachability": reachability,
                    "delay": delay,
                    "offset": offset,
                    "jitter": jitter,
                }
            )

        return ntp_stats

    def get_interfaces_ip(self):
        """Return the configured IP addresses."""
        return NotImplementedError

    def get_mac_address_table(self):
        """Return the MAC address table."""
        return NotImplementedError

    def get_route_to(self, destination="", protocol=""):
        """Return route details to a specific destination."""
        return NotImplementedError

    def get_snmp_information(self):
        """Return the SNMP configuration."""
        return NotImplementedError

    def get_probes_config(self):
        """Return the configuration of the probes."""
        return NotImplementedError

    def get_probes_results(self):
        """Return the results of the probes."""
        return NotImplementedError

    def traceroute(
        self,
        destination,
        source=C.TRACEROUTE_SOURCE,
        ttl=C.TRACEROUTE_TTL,
        timeout=C.TRACEROUTE_TIMEOUT,
        vrf=C.TRACEROUTE_VRF,
    ):
        """Execute traceroute and return results."""
        return NotImplementedError

    def get_users(self):
        """Return user configuration."""
        return NotImplementedError

    def get_config(self, retrieve="all", full=False):
        """Return device configuration."""
        return NotImplementedError
