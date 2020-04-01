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
import difflib

# import third party lib
from ncclient import manager
from ncclient.xml_ import to_ele
from ncclient.operations.rpc import RPCError
from lxml import etree as ETREE
from lxml.etree import XMLSyntaxError
from netaddr import IPAddress  # needed for traceroute, to check IP version
from netaddr.core import AddrFormatError

# import NAPALM base
from napalm.iosxr_netconf import constants as C
from napalm.base.base import NetworkDriver
import napalm.base.helpers
from napalm.base.exceptions import ConnectionException
from napalm.base.exceptions import MergeConfigException
from napalm.base.exceptions import ReplaceConfigException


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
        self.device = None

    def open(self):
        """Open the connection with the device."""
        try:
            self.device = manager.connect(
                           host=self.hostname,
                           port=self.port,
                           username=self.username,
                           password=self.password,
                           timeout=self.timeout,
                           device_params={'name': 'iosxr'})
            if self.lock_on_connect:
                self._lock()
        except Exception as conn_err:
            raise ConnectionException(conn_err.args[0])

    def close(self):
        """Close the connection."""
        if self.locked:
            self._unlock()
        self.device.close_session()

    def _lock(self):
        """Lock the config DB."""
        if not self.locked:
            self.device.lock()
            self.locked = True

    def _unlock(self):
        """Unlock the config DB."""
        if self.locked:
            self.device.unlock()
            self.locked = False

    def _load_config(self, filename, config):
        """Edit Configuration."""
        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()
        self.pending_changes = True
        if not self.lock_on_connect:
            self._lock()
        return configuration

    def is_alive(self):
        """Return flag with the state of the connection."""
        if self.device is None:
            return {"is_alive": False}
        return {"is_alive": self.device._session.transport.is_active()}

    def load_replace_candidate(self, filename=None, config=None):
        """Open the candidate config and replace."""
        self.replace = True
        configuration = self._load_config(filename=filename, config=config)
        configuration = "<source>"+configuration+"</source>"
        try:
            self.device.copy_config(
                source=configuration, target="candidate")
        except (RPCError, XMLSyntaxError) as e:
            self.pending_changes = False
            self.replace = False
            raise ReplaceConfigException(e)

    def load_merge_candidate(self, filename=None, config=None):
        """Open the candidate config and merge."""
        self.replace = False
        configuration = self._load_config(filename=filename, config=config)
        try:
            self.device.edit_config(
                config=configuration, error_option="rollback-on-error")
        except (RPCError, XMLSyntaxError) as e:
            self.pending_changes = False
            raise MergeConfigException(e)

    def compare_config(self):
        """Compare candidate config with running."""
        if not self.pending_changes:
            return ""
        else:
            diff = ""
            run_conf = self.device.get_config("running").xml
            can_conf = self.device.get_config("candidate").xml
            # Remove rpc-reply and data tag then reformat XML before doing the diff
            parser = ETREE.XMLParser(remove_blank_text=True)
            run_conf = ETREE.tostring(ETREE.XML(
                    run_conf, parser=parser)[0], pretty_print=True).decode()
            can_conf = ETREE.tostring(ETREE.XML(
                    can_conf, parser=parser)[0], pretty_print=True).decode()
            for line in difflib.unified_diff(run_conf.splitlines(1), can_conf.splitlines(1)):
                diff += line
            return diff

    def commit_config(self, message=""):
        """Commit configuration."""
        self.device.commit()
        self.pending_changes = False
        if self.locked:
            self._unlock()

    def discard_config(self):
        """Discard changes."""
        self.device.discard_changes()
        self.pending_changes = False
        if not self.lock_on_connect:
            self._unlock()

    def rollback(self):
        """Rollback to previous commit."""
        self.device.dispatch(to_ele(C.ROLLBACK_RPC_REQ))

    def _find_txt(self, xml_tree, path, default=None, namespaces=None):
        """
        Extract the text value from a leaf in an XML tree using XPath.

        Will return a default value if leaf path not matched.
        :param xml_tree:the XML Tree object. <type'lxml.etree._Element'>.
        :param path: XPath to be applied in order to extract the desired data.
        :param default:  Value to be returned in case of a no match.
        :param namespaces: namespace dictionary.
        :return: a str value or None if leaf path not matched.
        """

        value = None
        xpath_applied = xml_tree.xpath(path, namespaces=namespaces)
        if xpath_applied:
            if not len(xpath_applied[0]):
                if xpath_applied[0].text is not None:
                    value = xpath_applied[0].text.strip()
                else:
                    value = ''
        else:
            value = default

        return value

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

        facts_rpc_reply = self.device.dispatch(to_ele(C.FACTS_RPC_REQ)).xml

        # Converts string to etree
        facts_rpc_reply_etree = ETREE.fromstring(facts_rpc_reply)

        # Retrieves hostname
        hostname = napalm.base.helpers.convert(
            str, self._find_txt(facts_rpc_reply_etree, ".//suo:system-time/\
            suo:uptime/suo:host-name", namespaces=C.NS)
        )

        # Retrieves uptime
        uptime = napalm.base.helpers.convert(
            int, self._find_txt(facts_rpc_reply_etree, ".//suo:system-time/\
            suo:uptime/suo:uptime", namespaces=C.NS), -1
        )

        # Retrieves interfaces name
        interface_tree = facts_rpc_reply_etree.xpath(
                        ".//int:interfaces/int:interfaces/int:interface",
                        namespaces=C.NS)
        for interface in interface_tree:
            name = self._find_txt(interface, "./int:interface-name", namespaces=C.NS)
            interface_list.append(name)

        # Retrieves os version, model, serial number
        basic_info_tree = facts_rpc_reply_etree.xpath(
                        ".//imo:inventory/imo:racks/imo:rack/imo:attributes/\
                        imo:inv-basic-bag", namespaces=C.NS)[0]
        os_version = napalm.base.helpers.convert(
            str,
            self._find_txt(
                basic_info_tree, "./imo:software-revision", namespaces=C.NS)
        )
        model = napalm.base.helpers.convert(
            str,
            self._find_txt(basic_info_tree, "./imo:model-name", namespaces=C.NS)
        )
        serial = napalm.base.helpers.convert(
            str, self._find_txt(
                basic_info_tree, "./imo:serial-number", namespaces=C.NS)
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

        interfaces_rpc_reply = self.device.get(filter=(
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
                    interface_tree, "./int:interface-name", namespaces=C.NS)
            if not interface_name:
                continue
            is_up = (self._find_txt(
                interface_tree, "./int:line-state", namespaces=C.NS) == "im-state-up")
            enabled = (self._find_txt(
                interface_tree, "./int:state", namespaces=C.NS)
                != "im-state-admin-down")
            raw_mac = self._find_txt(
                interface_tree, "./int:mac-address/int:address", default="", namespaces=C.NS)
            mac_address = napalm.base.helpers.convert(
                napalm.base.helpers.mac, raw_mac, raw_mac
            )
            speed = napalm.base.helpers.convert(
                int, napalm.base.helpers.convert(int, self._find_txt(
                 interface_tree, "./int:bandwidth", namespaces=C.NS), 0) * 1e-3,)
            mtu = int(self._find_txt(interface_tree, "./int:mtu", namespaces=C.NS))
            description = self._find_txt(
                description_tree, "./int:description", default="", namespaces=C.NS)
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
        rpc_reply = self.device.get(filter=(
                    'subtree', C.INT_COUNTERS_RPC_REQ_FILTER)).xml
        # Converts string to tree
        rpc_reply_etree = ETREE.fromstring(rpc_reply)

        interface_counters = {}

        # Retrieves interfaces counters details
        interface_xr_tree = rpc_reply_etree.xpath(
            ".//int:interfaces/int:interface-xr/int:interface", namespaces=C.NS)
        for interface in interface_xr_tree:
            interface_name = self._find_txt(
                interface, "./int:interface-name", namespaces=C.NS)
            if interface_name[:8] == "Loopback" and interface_name[8:].isdigit():
                continue
            interface_stats = {}
            if self._find_txt(interface,
                    "./int:interface-statistics/int:stats-type", namespaces=C.NS) == 'basic':
                interface_stats["tx_multicast_packets"] = ""
                interface_stats["tx_discards"] = ""
                interface_stats["tx_octets"] = ""
                interface_stats["tx_errors"] = ""
                interface_stats["rx_octets"] = ""
                interface_stats["tx_unicast_packets"] = ""
                interface_stats["rx_errors"] = ""
                interface_stats["tx_broadcast_packets"] = ""
                interface_stats["rx_multicast_packets"] = ""
                interface_stats["rx_broadcast_packets"] = ""
                interface_stats["rx_discards"] = ""
                interface_stats["rx_unicast_packets"] = ""
            else:
                int_stats_xpath = "./int:interface-statistics/int:full-interface-stats/"
                interface_stats["tx_multicast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:multicast-packets-sent", "0", namespaces=C.NS
                    ),
                )
                interface_stats["tx_discards"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:output-drops", "0", namespaces=C.NS
                    ),
                )
                interface_stats["tx_octets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:bytes-sent", "0", namespaces=C.NS
                    ),
                )
                interface_stats["tx_errors"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:output-errors", "0", namespaces=C.NS
                    ),
                )
                interface_stats["rx_octets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:bytes-received", "0", namespaces=C.NS
                    ),
                )
                interface_stats["tx_unicast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:packets-sent", "0", namespaces=C.NS
                    ),
                )
                interface_stats["rx_errors"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:input-errors", "0", namespaces=C.NS
                    ),
                )
                interface_stats["tx_broadcast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:broadcast-packets-sent", "0", namespaces=C.NS
                    ),
                )
                interface_stats["rx_multicast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:multicast-packets-received", "0", namespaces=C.NS
                    ),
                )
                interface_stats["rx_broadcast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:broadcast-packets-received", "0", namespaces=C.NS
                    ),
                )
                interface_stats["rx_discards"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath+"int:input-drops", "0", namespaces=C.NS
                    ),
                )
                interface_stats["rx_unicast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface, int_stats_xpath+"int:packets-received", "0", namespaces=C.NS
                    ),
                )

            interface_counters[interface_name] = interface_stats

        return interface_counters

    def get_bgp_neighbors(self):
        """Return BGP neighbors details."""
        def get_vrf_neighbors(rpc_reply_etree, xpath):
            """Return BGP neighbors details for a given VRF."""
            neighbors = {}

            for neighbor in rpc_reply_etree.xpath(xpath, namespaces=C.NS):

                this_neighbor = {}
                this_neighbor["local_as"] = napalm.base.helpers.convert(
                    int, self._find_txt(neighbor, "./bgp:local-as", namespaces=C.NS)
                )
                this_neighbor["remote_as"] = napalm.base.helpers.convert(
                    int, self._find_txt(neighbor, "./bgp:remote-as", namespaces=C.NS)
                )
                this_neighbor["remote_id"] = napalm.base.helpers.convert(
                    str, self._find_txt(
                        neighbor, "./bgp:router-id", namespaces=C.NS)
                )

                if (self._find_txt(
                     neighbor, "./bgp:connection-admin-status", namespaces=C.NS) == "1"):
                    this_neighbor["is_enabled"] = True

                try:
                    this_neighbor["description"] = napalm.base.helpers.convert(
                        str, self._find_txt(
                         neighbor, "./bgp:description", namespaces=C.NS)
                    )
                except AttributeError:
                    this_neighbor["description"] = ""

                this_neighbor["is_enabled"] = (
                    self._find_txt(
                     neighbor, "./bgp:connection-admin-status", namespaces=C.NS)
                    == "1"
                )

                if (
                    str(self._find_txt(
                        neighbor, "./bgp:connection-state", namespaces=C.NS))
                    == "bgp-st-estab"
                ):
                    this_neighbor["is_up"] = True
                    this_neighbor["uptime"] = napalm.base.helpers.convert(
                        int,
                        self._find_txt(
                         neighbor, "./bgp:connection-established-time", namespaces=C.NS
                        ),
                    )
                else:
                    this_neighbor["is_up"] = False
                    this_neighbor["uptime"] = -1

                this_neighbor["address_family"] = {}

                if (self._find_txt(neighbor, "./bgp:connection-remote-address/\
                     bgp:afi", namespaces=C.NS) == "ipv4"):
                    this_afi = "ipv4"
                elif (
                    self._find_txt(
                     neighbor, "./bgp:connection-remote-address/bgp:afi", namespaces=C.NS
                    )
                    == "ipv6"
                ):
                    this_afi = "ipv6"
                else:
                    this_afi = self._find_txt(
                     neighbor, "./bgp:connection-remote-address/bgp:afi", namespaces=C.NS
                    )

                this_neighbor["address_family"][this_afi] = {}

                try:
                    this_neighbor["address_family"][this_afi][
                        "received_prefixes"
                    ] = napalm.base.helpers.convert(
                        int,
                        self._find_txt(
                         neighbor, "./bgp:af-data/bgp:prefixes-accepted", namespaces=C.NS
                        ),
                        0,
                    ) + napalm.base.helpers.convert(
                        int,
                        self._find_txt(
                         neighbor, "./bgp:af-data/bgp:prefixes-denied", namespaces=C.NS
                        ),
                        0,
                    )
                    this_neighbor["address_family"][this_afi][
                        "accepted_prefixes"
                    ] = napalm.base.helpers.convert(
                        int,
                        self._find_txt(
                         neighbor, "./bgp:af-data/bgp:prefixes-accepted", namespaces=C.NS
                        ),
                        0,
                    )
                    this_neighbor["address_family"][this_afi][
                        "sent_prefixes"
                    ] = napalm.base.helpers.convert(
                        int, self._find_txt(neighbor, "./bgp:af-data/\
                            bgp:prefixes-advertised", namespaces=C.NS), 0,
                    )
                except AttributeError:
                    this_neighbor["address_family"][this_afi][
                                        "received_prefixes"] = -1
                    this_neighbor["address_family"][this_afi][
                                        "accepted_prefixes"] = -1
                    this_neighbor["address_family"][this_afi][
                                        "sent_prefixes"] = -1

                neighbor_ip = napalm.base.helpers.ip(
                    self._find_txt(
                        neighbor, "./bgp:neighbor-address", namespaces=C.NS
                    )
                )

                neighbors[neighbor_ip] = this_neighbor

            return neighbors

        rpc_reply = self.device.get(filter=(
                    'subtree', C.BGP_NEIGHBOR_REQ_FILTER)).xml
        # Converts string to tree
        rpc_reply_etree = ETREE.fromstring(rpc_reply)
        result = {}
        this_vrf = {}
        this_vrf["peers"] = {}

        # get neighbors and router id from default(global) VRF
        default_vrf_xpath = '''.//bgp:bgp/bgp:instances/bgp:instance/
          bgp:instance-active/bgp:default-vrf/'''
        this_vrf["router_id"] = napalm.base.helpers.convert(
            str,
            self._find_txt(
               rpc_reply_etree, default_vrf_xpath+"bgp:global-process-info/\
                    bgp:vrf/bgp:router-id", namespaces=C.NS)
        )
        this_vrf["peers"] = get_vrf_neighbors(rpc_reply_etree,
                    default_vrf_xpath+"bgp:neighbors/bgp:neighbor")
        result['global'] = this_vrf

        # get neighbors and router id from other VRFs
        vrf_xpath = '''.//bgp:bgp/bgp:instances/
                    bgp:instance/bgp:instance-active/bgp:vrfs'''
        for vrf in rpc_reply_etree.xpath(
                        vrf_xpath+"/bgp:vrf", namespaces=C.NS):
            this_vrf = {}
            this_vrf["peers"] = {}
            this_vrf["router_id"] = napalm.base.helpers.convert(
                str,
                self._find_txt(vrf, "./bgp:global-process-info/bgp:vrf/\
                                    bgp:router-id", namespaces=C.NS))
            vrf_name = self._find_txt(vrf, "./bgp:vrf-name", namespaces=C.NS)
            this_vrf["peers"] = get_vrf_neighbors(rpc_reply_etree,
                        vrf_xpath+"/bgp:vrf[bgp:vrf-name='"+vrf_name+"']\
                        /bgp:neighbors/bgp:neighbor")
            result[vrf_name] = this_vrf

        return result

    def get_environment(self):
        """Return environment details."""
        return NotImplementedError

    def get_lldp_neighbors(self):
        """Return LLDP neighbors details."""
        # init result dict
        lldp_neighbors = {}

        rpc_reply = self.device.get(
                filter=("subtree", C.LLDP_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        lldp_xpath = ".//lldp:lldp/lldp:nodes/lldp:node/lldp:neighbors\
                        /lldp:details/lldp:detail"
        for neighbor in result_tree.xpath(
                            lldp_xpath+"/lldp:lldp-neighbor", namespaces=C.NS):
            interface_name = self._find_txt(
                neighbor, "./lldp:receiving-interface-name", namespaces=C.NS)
            system_name = napalm.base.helpers.convert(
                str,
                self._find_txt(neighbor, "./lldp:detail/lldp:system-name", namespaces=C.NS)
            )
            port_id = napalm.base.helpers.convert(
                str,
                self._find_txt(neighbor, "./lldp:port-id-detail", namespaces=C.NS)
            )
            if interface_name not in lldp_neighbors.keys():
                lldp_neighbors[interface_name] = []
            lldp_neighbors[interface_name].append(
                {
                    "hostname": system_name,
                    "port": port_id,
                }
            )

        return lldp_neighbors

    def get_lldp_neighbors_detail(self, interface=""):
        """Detailed view of the LLDP neighbors."""
        lldp_neighbors_detail = {}

        rpc_reply = self.device.get(filter=(
                    "subtree", C.LLDP_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        lldp_neighbor_xpath = ".//lldp:lldp/lldp:nodes/lldp:node/lldp:neighbors\
                /lldp:details/lldp:detail/lldp:lldp-neighbor"
        for neighbor in result_tree.xpath(
                        lldp_neighbor_xpath, namespaces=C.NS):
            interface_name = napalm.base.helpers.convert(str, self._find_txt(
                neighbor, "./lldp:receiving-interface-name", default="", namespaces=C.NS))
            parent_interface = napalm.base.helpers.convert(str, self._find_txt(
                neighbor, "./lldp:receiving-parent-interface-name", default="None", namespaces=C.NS))
            chassis_id_raw = self._find_txt(
                neighbor, "./lldp:chassis-id", default="", namespaces=C.NS)
            chassis_id = napalm.base.helpers.convert(
                napalm.base.helpers.mac, chassis_id_raw, chassis_id_raw
            )
            port_id = napalm.base.helpers.convert(str, self._find_txt(
                neighbor, "./lldp:port-id-detail", default="", namespaces=C.NS))
            port_descr = napalm.base.helpers.convert(str, self._find_txt(
                neighbor, "./lldp:detail/lldp:port-description", default="", namespaces=C.NS))
            system_name = napalm.base.helpers.convert(str, self._find_txt(
                neighbor, "./lldp:detail/lldp:system-name", default="", namespaces=C.NS))
            system_descr = napalm.base.helpers.convert(str, self._find_txt(
                neighbor, "./lldp:detail/lldp:system-description", default="", namespaces=C.NS))
            system_capabilities = napalm.base.helpers.convert(str, self._find_txt(
                neighbor, "./lldp:detail/lldp:system-capabilities", default="", namespaces=C.NS))
            enabled_capabilities = napalm.base.helpers.convert(str, self._find_txt(
                neighbor, "./lldp:detail/lldp:enabled-capabilities", default="", namespaces=C.NS))

            if interface_name not in lldp_neighbors_detail.keys():
                lldp_neighbors_detail[interface_name] = []
            lldp_neighbors_detail[interface_name].append(
                {
                    "parent_interface": parent_interface,
                    "remote_chassis_id": chassis_id,
                    "remote_port": port_id,
                    "remote_port_description": port_descr,
                    "remote_system_name": system_name,
                    "remote_system_description": system_descr,
                    "remote_system_capab":
                        napalm.base.helpers.transform_lldp_capab(
                            system_capabilities),
                    "remote_system_enable_capab":
                        napalm.base.helpers.transform_lldp_capab(
                            enabled_capabilities),
                }
            )

        return lldp_neighbors_detail

    def cli(self, commands):
        """Execute raw CLI commands and returns their output."""
        return NotImplementedError

    def get_bgp_config(self, group="", neighbor=""):
        """Return BGP configuration."""
        bgp_config = {}

        # a helper
        def build_prefix_limit(
             af_table, limit, prefix_percent, prefix_timeout):
            prefix_limit = {}
            inet = False
            inet6 = False
            preifx_type = "inet"
            if "ipv4" in af_table.lower():
                inet = True
            if "ipv6" in af_table.lower():
                inet6 = True
                preifx_type = "inet6"
            if inet or inet6:
                prefix_limit = {
                    preifx_type: {
                        af_table[5:].lower(): {
                            "limit": limit,
                            "teardown": {
                                "threshold": prefix_percent,
                                "timeout": prefix_timeout,
                            },
                        }
                    }
                }
            return prefix_limit

        # here begins actual method...
        rpc_reply = self.device.get_config(source="running", filter=(
                            'subtree', C.BGP_CFG_RPC_REQ_FILTER)).xml

        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        if not group:
            neighbor = ""

        bgp_group_neighbors = {}
        bgp_neighbor_xpath = ".//bgpc:bgp/bgpc:instance/bgpc:instance-as/\
             bgpc:four-byte-as/bgpc:default-vrf/bgpc:bgp-entity/bgpc:neighbors/bgpc:neighbor"
        for bgp_neighbor in result_tree.xpath(bgp_neighbor_xpath, namespaces=C.NS):
            group_name = self._find_txt(
                bgp_neighbor,
                "./bgpc:neighbor-group-add-member", default="", namespaces=C.NS
            )
            peer = napalm.base.helpers.ip(
                self._find_txt(
                    bgp_neighbor,
                    "./bgpc:neighbor-address", namespaces=C.NS
                )
            )
            if neighbor and peer != neighbor:
                continue
            description = self._find_txt(
                bgp_neighbor,
                "./bgpc:description", default="", namespaces=C.NS)
            peer_as = napalm.base.helpers.convert(
                int, self._find_txt(
                    bgp_neighbor,
                    "./bgpc:remote-as/bgpc:as-yy", namespaces=C.NS), 0
            )
            local_as = napalm.base.helpers.convert(
                int, self._find_txt(
                    bgp_neighbor,
                    "./bgpc:local-as/bgpc:as-yy", namespaces=C.NS), 0
            )
            af_table = self._find_txt(
                bgp_neighbor,
                "./bgpc:neighbor-afs/bgpc:neighbor-af/bgpc:af-name", default="", namespaces=C.NS
            )
            prefix_limit = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_neighbor,
                    "./bgpc:neighbor-afs/bgpc:neighbor-af/\
                    bgpc:maximum-prefixes/bgpc:prefix-limit", namespaces=C.NS
                ),
                0,
            )
            prefix_percent = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_neighbor,
                    "./bgpc:neighbor-afs/bgpc:neighbor-af/\
                    bgpc:maximum-prefixes/bgpc:warning-percentage", namespaces=C.NS
                ),
                0,
            )
            prefix_timeout = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_neighbor,
                    "./bgpc:neighbor-afs/bgpc:neighbor-af/\
                    bgpc:maximum-prefixes/bgpc:restart-time", namespaces=C.NS
                ),
                0,
            )
            import_policy = self._find_txt(
                bgp_neighbor,
                "./bgpc:neighbor-afs/bgpc:neighbor-af/bgpc:route-policy-in", default="", namespaces=C.NS
            )
            export_policy = self._find_txt(
                bgp_neighbor,
                "./bgpc:neighbor-afs/bgpc:neighbor-af/bgpc:route-policy-out", default="", namespaces=C.NS
            )
            local_addr_raw = self._find_txt(
                bgp_neighbor,
                "./bgpc:local-address/bgpc:local-ip-address", default="", namespaces=C.NS
            )
            local_address = napalm.base.helpers.convert(
                napalm.base.helpers.ip, local_addr_raw, local_addr_raw
            )
            password = self._find_txt(
                bgp_neighbor,
                "./bgpc:password/bgpc:password", default="", namespaces=C.NS
            )
            nhs = False
            route_reflector = False
            if group_name not in bgp_group_neighbors.keys():
                bgp_group_neighbors[group_name] = {}
            bgp_group_neighbors[group_name][peer] = {
                "description": description,
                "remote_as": peer_as,
                "prefix_limit": build_prefix_limit(
                    af_table, prefix_limit, prefix_percent, prefix_timeout
                ),
                "export_policy": export_policy,
                "import_policy": import_policy,
                "local_address": local_address,
                "local_as": local_as,
                "authentication_key": password,
                "nhs": nhs,
                "route_reflector_client": route_reflector,
            }
            if neighbor and peer == neighbor:
                break

        bgp_neighbor_group_xpath = ".//bgpc:bgp/bgpc:instance/bgpc:instance-as/\
             bgpc:four-byte-as/bgpc:default-vrf/bgpc:bgp-entity/\
             bgpc:neighbor-groups/bgpc:neighbor-group"
        for bgp_group in result_tree.xpath(
                        bgp_neighbor_group_xpath, namespaces=C.NS):
            group_name = self._find_txt(
                bgp_group,
                "./bgpc:neighbor-group-name", namespaces=C.NS
            )
            if group and group != group_name:
                continue
            bgp_type = "external"  # by default external
            # must check
            description = self._find_txt(
                bgp_group,
                "./bgpc:description", default="", namespaces=C.NS)
            import_policy = self._find_txt(
                bgp_group,
                "./bgpc:neighbor-group-afs/\
                bgpc:neighbor-group-af/bgpc:route-policy-in", default="", namespaces=C.NS
            )
            export_policy = self._find_txt(
                bgp_group,
                "./bgpc:neighbor-group-afs/\
                bgpc:neighbor-group-af/bgpc:route-policy-out", default="", namespaces=C.NS
            )
            multipath = (
                self._find_txt(
                    bgp_group,
                    "./bgpc:neighbor-group-afs/\
                    bgpc:neighbor-group-af/bgpc:multipath", namespaces=C.NS
                )
                == "true"
            )
            peer_as = napalm.base.helpers.convert(
                int, self._find_txt(
                    bgp_group,
                    "./bgpc:remote-as/bgpc:as-yy", namespaces=C.NS),
                0,
            )
            local_as = napalm.base.helpers.convert(
                int, self._find_txt(
                    bgp_group,
                    "./bgpc:local-as/bgpc:as-yy", namespaces=C.NS),
                0,
            )
            multihop_ttl = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_group,
                    "./bgpc:ebgp-multihop/bgpc:max-hop-count", namespaces=C.NS),
                0,
            )
            local_addr_raw = self._find_txt(
                bgp_group,
                "./bgpc:local-address/bgpc:local-ip-address", default="", namespaces=C.NS
            )
            local_address = napalm.base.helpers.convert(
                napalm.base.helpers.ip, local_addr_raw, local_addr_raw
            )
            af_table = self._find_txt(
                bgp_group,
                "./bgpc:neighbor-afs/bgpc:neighbor-af/bgpc:af-name", default="", namespaces=C.NS)
            prefix_limit = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_group,
                    "./bgpc:neighbor-group-afs/\
                    bgpc:neighbor-group-af/bgpc:maximum-prefixes/\
                    bgpc:prefix-limit", namespaces=C.NS
                ),
                0,
            )
            prefix_percent = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_group,
                    "./bgpc:neighbor-group-afs/\
                    bgpc:neighbor-group-af/bgpc:maximum-prefixes/\
                    bgpc:warning-percentage", namespaces=C.NS
                ),
                0,
            )
            prefix_timeout = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_group,
                    "./bgpc:neighbor-group-afs/\
                    bgpc:neighbor-group-af/bgpc:maximum-prefixes/\
                    bgpc:restart-time", namespaces=C.NS
                ),
                0,
            )
            remove_private = True  # is it specified in the XML?
            bgp_config[group_name] = {
                "apply_groups": [],  # on IOS-XR will always be empty list!
                "description": description,
                "local_as": local_as,
                "type": str(bgp_type),
                "import_policy": import_policy,
                "export_policy": export_policy,
                "local_address": local_address,
                "multipath": multipath,
                "multihop_ttl": multihop_ttl,
                "remote_as": peer_as,
                "remove_private_as": remove_private,
                "prefix_limit": build_prefix_limit(
                    af_table, prefix_limit, prefix_percent, prefix_timeout
                ),
                "neighbors": bgp_group_neighbors.get(group_name, {}),
            }
            if group and group == group_name:
                break
        if "" in bgp_group_neighbors.keys():
            bgp_config["_"] = {
                "apply_groups": [],
                "description": "",
                "local_as": 0,
                "type": "",
                "import_policy": "",
                "export_policy": "",
                "local_address": "",
                "multipath": False,
                "multihop_ttl": 0,
                "remote_as": 0,
                "remove_private_as": False,
                "prefix_limit": {},
                "neighbors": bgp_group_neighbors.get("", {}),
            }

        return bgp_config

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        """Detailed view of the BGP neighbors operational data."""
        def get_vrf_neighbors_detail(rpc_reply_etree, xpath, vrf_name, vrf_keepalive, vrf_holdtime):
            """Detailed view of the BGP neighbors operational data for a given VRF."""
            bgp_vrf_neighbors_detail = {}
            bgp_vrf_neighbors_detail[vrf_name] = {}
            for neighbor in rpc_reply_etree.xpath(xpath, namespaces=C.NS):
                up = (
                    self._find_txt(neighbor, "./bgp:connection-state", namespaces=C.NS)
                    == "bgp-st-estab"
                )
                local_as = napalm.base.helpers.convert(
                    int, self._find_txt(neighbor, "./bgp:local-as", namespaces=C.NS), 0
                )
                remote_as = napalm.base.helpers.convert(
                    int, self._find_txt(neighbor, "./bgp:remote-as", namespaces=C.NS), 0
                )
                router_id = napalm.base.helpers.ip(
                    self._find_txt(neighbor, "./bgp:router-id", namespaces=C.NS)
                )
                remote_address = napalm.base.helpers.ip(
                    self._find_txt(
                        neighbor, "./bgp:neighbor-address",
                        namespaces=C.NS
                    )
                )
                local_address_configured = (self._find_txt(
                    neighbor, "./bgp:is-local-address-configured", namespaces=C.NS)
                    == "true"
                )
                local_address = napalm.base.helpers.ip(self._find_txt(
                        neighbor, "./bgp:connection-local-address/\
                        bgp:ipv4-address", namespaces=C.NS
                    )
                    or self._find_txt(
                     neighbor, "./bgp:connection-local-address/\
                     bgp:ipv6-address", namespaces=C.NS
                    )
                )
                local_port = napalm.base.helpers.convert(
                    int, self._find_txt(
                     neighbor, "./bgp:connection-local-port", namespaces=C.NS)
                )
                remote_address = napalm.base.helpers.ip(
                    self._find_txt(
                        neighbor, "./bgp:connection-remote-address/\
                        bgp:ipv4-address", namespaces=C.NS
                    )
                    or self._find_txt(
                        neighbor, "./bgp:connection-remote-address/\
                        bgp:ipv6-address", namespaces=C.NS
                    )
                )
                remote_port = napalm.base.helpers.convert(
                    int, self._find_txt(
                     neighbor, "./bgp:connection-remote-port", namespaces=C.NS)
                )
                multihop = (self._find_txt(
                    neighbor, "\
                    ./bgp:is-external-neighbor-not-directly-connected", namespaces=C.NS
                    )
                    == "true"
                )
                remove_private_as = (self._find_txt(
                    neighbor, "./bgp:af-data/\
                    bgp:remove-private-as-from-updates", namespaces=C.NS
                    )
                    == "true"
                )
                multipath = (
                    self._find_txt(
                     neighbor, "./bgp:af-data/\
                     bgp:selective-multipath-eligible", namespaces=C.NS
                    )
                    == "true"
                )
                import_policy = self._find_txt(
                    neighbor, "./bgp:af-data/bgp:route-policy-in", default="", namespaces=C.NS
                )
                export_policy = self._find_txt(
                    neighbor, "./bgp:af-data/bgp:route-policy-out", default="", namespaces=C.NS
                )
                input_messages = napalm.base.helpers.convert(
                    int, self._find_txt(
                        neighbor, "./bgp:messges-received", namespaces=C.NS), 0
                )
                output_messages = napalm.base.helpers.convert(
                    int, self._find_txt(
                        neighbor, "./bgp:messages-sent", namespaces=C.NS), 0
                )
                connection_down_count = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor, "./bgp:connection-down-count", namespaces=C.NS),
                    0,
                )
                messages_queued_out = napalm.base.helpers.convert(
                    int, self._find_txt(
                        neighbor, "./bgp:messages-queued-out", namespaces=C.NS), 0
                )
                connection_state = (
                    self._find_txt(neighbor, "./bgp:connection-state", namespaces=C.NS)
                    .replace("bgp-st-", "")
                    .title()
                )
                if connection_state == "Estab":
                    connection_state = "Established"
                previous_connection_state = napalm.base.helpers.convert(
                    str,
                    _BGP_STATE_.get(self._find_txt(
                        neighbor, "./bgp:previous-connection-state", "0", namespaces=C.NS
                        )
                    ),
                )
                active_prefix_count = napalm.base.helpers.convert(
                    int, self._find_txt(
                     neighbor, "./bgp:af-data/bgp:number-of-bestpaths", namespaces=C.NS
                    ),
                    0,
                )
                accepted_prefix_count = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor, "./bgp:af-data/bgp:prefixes-accepted", namespaces=C.NS
                    ),
                    0,
                )
                suppressed_prefix_count = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor, "./bgp:af-data/bgp:prefixes-denied", namespaces=C.NS
                    ),
                    0,
                )
                received_prefix_count = accepted_prefix_count + suppressed_prefix_count
                advertised_prefix_count = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor, "./bgp:af-data/\
                        bgp:prefixes-advertised", namespaces=C.NS
                    ),
                    0,
                )
                suppress_4byte_as = (
                    self._find_txt(
                        neighbor, "./bgp:suppress4-byte-as", namespaces=C.NS) == "true"
                )
                local_as_prepend = (
                    self._find_txt(
                        neighbor, "./bgp:local-as-no-prepend", namespaces=C.NS) != "true"
                )
                holdtime = (
                    napalm.base.helpers.convert(
                        int, self._find_txt(
                            neighbor, "./bgp:hold-time", namespaces=C.NS), 0
                    )
                    or vrf_holdtime
                )
                configured_holdtime = napalm.base.helpers.convert(
                    int, self._find_txt(
                        neighbor, "./bgp:configured-hold-time", namespaces=C.NS), 0
                )
                keepalive = (
                    napalm.base.helpers.convert(
                        int, self._find_txt(
                            neighbor, "./bgp:keep-alive-time", namespaces=C.NS), 0
                    )
                    or vrf_keepalive
                )
                configured_keepalive = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor, "./bgp:configured-keepalive", namespaces=C.NS),
                    0,
                )
                flap_count = int(connection_down_count / 2)
                if up:
                    flap_count -= 1

                if remote_as not in bgp_vrf_neighbors_detail[vrf_name].keys():
                    bgp_vrf_neighbors_detail[vrf_name][remote_as] = []
                bgp_vrf_neighbors_detail[vrf_name][remote_as].append(
                    {
                        "up": up,
                        "local_as": local_as,
                        "remote_as": remote_as,
                        "router_id": router_id,
                        "local_address": local_address,
                        "routing_table": vrf_name,
                        "local_address_configured": local_address_configured,
                        "local_port": local_port,
                        "remote_address": remote_address,
                        "remote_port": remote_port,
                        "multihop": multihop,
                        "multipath": multipath,
                        "import_policy": import_policy,
                        "export_policy": export_policy,
                        "input_messages": input_messages,
                        "output_messages": output_messages,
                        "input_updates": 0,
                        "output_updates": 0,
                        "messages_queued_out": messages_queued_out,
                        "connection_state": connection_state,
                        "previous_connection_state": previous_connection_state,
                        "last_event": "",
                        "remove_private_as": remove_private_as,
                        "suppress_4byte_as": suppress_4byte_as,
                        "local_as_prepend": local_as_prepend,
                        "holdtime": holdtime,
                        "configured_holdtime": configured_holdtime,
                        "keepalive": keepalive,
                        "configured_keepalive": configured_keepalive,
                        "active_prefix_count": active_prefix_count,
                        "received_prefix_count": received_prefix_count,
                        "accepted_prefix_count": accepted_prefix_count,
                        "suppressed_prefix_count": suppressed_prefix_count,
                        "advertised_prefix_count": advertised_prefix_count,
                        "flap_count": flap_count,
                    }
                )
            return bgp_vrf_neighbors_detail

        rpc_reply = self.device.get(filter=(
                    'subtree', C.BGP_NEIGHBOR_REQ_FILTER)).xml
        # Converts string to tree
        rpc_reply_etree = ETREE.fromstring(rpc_reply)
        _BGP_STATE_ = {
            "0": "Unknown",
            "1": "Idle",
            "2": "Connect",
            "3": "OpenSent",
            "4": "OpenConfirm",
            "5": "Active",
            "6": "Established",
        }
        bgp_neighbors_detail = {}

        # get neighbors from default(global) VRF
        default_vrf_xpath = '''.//bgp:bgp/bgp:instances/bgp:instance/
          bgp:instance-active/bgp:default-vrf'''
        vrf_name = "default"
        default_vrf_keepalive = napalm.base.helpers.convert(int, self._find_txt(
                rpc_reply_etree, default_vrf_xpath+"/bgp:global-process-info/bgp:vrf/\
                bgp:keep-alive-time", namespaces=C.NS),)
        default_vrf_holdtime = napalm.base.helpers.convert(int, self._find_txt(
                rpc_reply_etree, default_vrf_xpath+"/bgp:global-process-info/bgp:vrf/\
                bgp:hold-time", namespaces=C.NS),)
        bgp_neighbors_detail["global"] = get_vrf_neighbors_detail(rpc_reply_etree,
                default_vrf_xpath+"/bgp:neighbors/bgp:neighbor", vrf_name,
                default_vrf_keepalive, default_vrf_holdtime)[vrf_name]

        # get neighbors from other VRFs
        vrf_xpath = '''.//bgp:bgp/bgp:instances/
                    bgp:instance/bgp:instance-active/bgp:vrfs'''
        for vrf in rpc_reply_etree.xpath(
                        vrf_xpath+"/bgp:vrf", namespaces=C.NS):
            vrf_name = self._find_txt(vrf, "./bgp:vrf-name", namespaces=C.NS)
            vrf_keepalive = napalm.base.helpers.convert(int, self._find_txt(
                    vrf, "./bgp:global-process-info/bgp:vrf/\
                    bgp:keep-alive-time", namespaces=C.NS),)
            vrf_holdtime = napalm.base.helpers.convert(int, self._find_txt(
                    vrf, "./bgp:global-process-info/bgp:vrf/\
                    bgp:hold-time", namespaces=C.NS),)
            bgp_neighbors_detail.update(get_vrf_neighbors_detail(
                    rpc_reply_etree, vrf_xpath+"/bgp:vrf[bgp:vrf-name='"+vrf_name+"']\
                    /bgp:neighbors/bgp:neighbor", vrf_name, vrf_keepalive, vrf_holdtime))

        return bgp_neighbors_detail

    def get_arp_table(self, vrf=""):
        """Return the ARP table."""
        if vrf:
            msg = "VRF support has not been added for \
                this getter on this platform."
            raise NotImplementedError(msg)

        arp_table = []

        rpc_reply = self.device.get(filter=('subtree', C.ARP_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)
        arp_entry_xpath = ".//arp:arp/arp:nodes/arp:node/arp:entries/arp:entry"
        for arp_entry in result_tree.xpath(arp_entry_xpath, namespaces=C.NS):
            interface = napalm.base.helpers.convert(str, self._find_txt(
                arp_entry, "./arp:interface-name", namespaces=C.NS))
            ip = napalm.base.helpers.convert(str, self._find_txt(
                arp_entry, "./arp:address", namespaces=C.NS))
            age = napalm.base.helpers.convert(float, self._find_txt(
                arp_entry, "./arp:age", default="0.0", namespaces=C.NS))
            mac_raw = self._find_txt(
                        arp_entry, "./arp:hardware-address", namespaces=C.NS)

            arp_table.append(
                {
                    "interface": interface,
                    "mac": napalm.base.helpers.mac(mac_raw),
                    "ip": napalm.base.helpers.ip(ip),
                    "age": age,
                }
            )

        return arp_table

    def get_ntp_peers(self):
        """Return the NTP peers configured on the device."""
        ntp_peers = {}

        rpc_reply = self.device.get_config(source="running", filter=(
                        'subtree', C.NTP_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        for version in ["ipv4", "ipv6"]:
            ntp_xpath = ".//ntpc:ntp/ntpc:peer-vrfs/ntpc:peer-vrf/\
                        ntpc:peer-{version}s".format(version=version)
            for peer in result_tree.xpath(ntp_xpath+"/ntpc:peer-{version}".format(
                    version=version), namespaces=C.NS):
                peer_type = self._find_txt(peer, "./ntpc:peer-type-{version}/\
                    ntpc:peer-type".format(version=version), namespaces=C.NS)
                if peer_type != "peer":
                    continue
                peer_address = self._find_txt(
                    peer, "./ntpc:address-{version}".format(
                            version=version), namespaces=C.NS)
                if not peer_address:
                    continue
                ntp_peers[peer_address] = {}

        return ntp_peers

    def get_ntp_servers(self):
        """Return the NTP servers configured on the device."""
        ntp_servers = {}

        rpc_reply = self.device.get_config(source="running", filter=(
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
                    ntpc:peer-type".format(version=version), namespaces=C.NS)
                if peer_type != "server":
                    continue
                server_address = self._find_txt(
                        peer, "./ntpc:address-{version}".format(
                                version=version), namespaces=C.NS)
                if not server_address:
                    continue
                ntp_servers[server_address] = {}

        return ntp_servers

    def get_ntp_stats(self):
        """Return NTP stats (associations)."""
        ntp_stats = []

        rpc_reply = self.device.get(filter=(
                            "subtree", C.NTP_STAT_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        xpath = ".//ntp:ntp/ntp:nodes/ntp:node/ntp:associations/\
                ntp:peer-summary-info/ntp:peer-info-common"
        for node in result_tree.xpath(xpath, namespaces=C.NS):
            synchronized = self._find_txt(
                        node, "./ntp:is-sys-peer", namespaces=C.NS) == "true"
            address = self._find_txt(node, "./ntp:address", namespaces=C.NS)
            if address == "DLRSC node":
                continue
            referenceid = self._find_txt(node, "./ntp:reference-id", namespaces=C.NS)
            hostpoll = napalm.base.helpers.convert(
                int, self._find_txt(node, "./ntp:host-poll", "0", namespaces=C.NS)
            )
            reachability = napalm.base.helpers.convert(
                int, self._find_txt(node, "./ntp:reachability", "0", namespaces=C.NS)
            )
            stratum = napalm.base.helpers.convert(
                int, self._find_txt(node, "./ntp:stratum", "0", namespaces=C.NS)
            )
            delay = napalm.base.helpers.convert(
                float, self._find_txt(node, "./ntp:delay", "0.0", namespaces=C.NS)
            )
            offset = napalm.base.helpers.convert(
                float, self._find_txt(node, "./ntp:offset", "0.0", namespaces=C.NS)
            )
            jitter = napalm.base.helpers.convert(
                float, self._find_txt(node, "./ntp:dispersion", "0.0", namespaces=C.NS)
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
        interfaces_ip = {}

        rpc_reply = self.device.dispatch(to_ele(C.INT_IPV4_IPV6_RPC_REQ)).xml
        # Converts string to etree
        ipv4_ipv6_tree = ETREE.fromstring(rpc_reply)

        # parsing IPv4
        int4_xpath = ".//int4:ipv4-network/int4:nodes/int4:node/\
            int4:interface-data/int4:vrfs/int4:vrf/int4:details"
        for interface in ipv4_ipv6_tree.xpath(int4_xpath+"/int4:detail", namespaces=C.NS):
            interface_name = napalm.base.helpers.convert(
                str,
                self._find_txt(interface, "./int4:interface-name", namespaces=C.NS),
            )
            primary_ip = napalm.base.helpers.ip(
                self._find_txt(
                    interface, "./int4:primary-address", namespaces=C.NS
                )
            )
            primary_prefix = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    interface, "./int4:prefix-length", namespaces=C.NS
                ),
            )
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = {}
            if "ipv4" not in interfaces_ip[interface_name].keys():
                interfaces_ip[interface_name]["ipv4"] = {}
            if primary_ip not in interfaces_ip[interface_name].get(
                    "ipv4", {}).keys():
                interfaces_ip[interface_name]["ipv4"][primary_ip] = {
                    "prefix_length": primary_prefix
                }
            for secondary_address in interface.xpath(
                            "./int4:secondary-address", namespaces=C.NS):
                secondary_ip = napalm.base.helpers.ip(
                    self._find_txt(secondary_address, "./int4:address", namespaces=C.NS)
                )
                secondary_prefix = napalm.base.helpers.convert(
                    int, self._find_txt(secondary_address, "./int4:prefix-length", namespaces=C.NS)
                )
                if secondary_ip not in interfaces_ip[interface_name]:
                    interfaces_ip[interface_name]["ipv4"][secondary_ip] = {
                        "prefix_length": secondary_prefix
                    }

        # parsing IPv6
        int6_xpath = ".//int6:ipv6-network/int6:nodes/int6:node/\
            int6:interface-data"
        for interface in ipv4_ipv6_tree.xpath(int6_xpath + "/int6:vrfs/int6:vrf/int6:global-details/\
                                int6:global-detail", namespaces=C.NS):
            interface_name = napalm.base.helpers.convert(
                str,
                self._find_txt(interface, "./int6:interface-name", namespaces=C.NS),
            )
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = {}
            if "ipv6" not in interfaces_ip[interface_name].keys():
                interfaces_ip[interface_name]["ipv6"] = {}
            for address in interface.xpath("./int6:address", namespaces=C.NS):
                address_ip = napalm.base.helpers.ip(
                    self._find_txt(address, "./int6:address", namespaces=C.NS)
                )
                address_prefix = napalm.base.helpers.convert(
                    int, self._find_txt(address, "./int6:prefix-length", namespaces=C.NS)
                )
                if (
                    address_ip
                    not in interfaces_ip[interface_name].get("ipv6", {}).keys()
                ):
                    interfaces_ip[interface_name]["ipv6"][address_ip] = {
                            "prefix_length": address_prefix
                        }

        return interfaces_ip

    def get_mac_address_table(self):
        """Return the MAC address table."""
        mac_table = []

        rpc_reply = self.device.get(filter=(
                    "subtree", C.MAC_TABLE_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        mac_xpath = ".//mac:l2vpn-forwarding/mac:nodes/mac:node/mac:l2fibmac-details"
        for mac_entry in result_tree.xpath(
                mac_xpath+"/mac:l2fibmac-detail", namespaces=C.NS):
            mac_raw = self._find_txt(mac_entry, "./mac:address", namespaces=C.NS)
            vlan = napalm.base.helpers.convert(
                int,
                self._find_txt(mac_entry, "./mac:name", namespaces=C.NS).replace(
                    "vlan", ""), 0,
            )
            interface = self._find_txt(mac_entry, "./mac:segment/mac:ac/\
                            mac:interface-handle", default="", namespaces=C.NS)

            mac_table.append(
                {
                    "mac": napalm.base.helpers.mac(mac_raw),
                    "interface": interface,
                    "vlan": vlan,
                    "active": True,
                    "static": False,
                    "moves": 0,
                    "last_move": 0.0,
                }
            )

        return mac_table

    def get_route_to(self, destination="", protocol="", longer=False):
        """Return route details to a specific destination."""
        routes = {}

        if not isinstance(destination, str):
            raise TypeError("Please specify a valid destination!")

        if longer:
            raise NotImplementedError("Longer prefixes not yet supported for IOS-XR")

        protocol = protocol.lower()
        if protocol == "direct":
            protocol = "connected"

        dest_split = destination.split("/")
        network = dest_split[0]
        prefix_length = 0
        if len(dest_split) == 2:
            prefix_length = dest_split[1]

        ipv = 4
        try:
            ipv = IPAddress(network).version
        except AddrFormatError:
            raise TypeError("Wrong destination IP Address!")

        if ipv == 6:
            route_info_rpc_command = (C.ROUTE_IPV6_RPC_REQ_FILTER).format(
                network=network, prefix_length=prefix_length)
        else:
            route_info_rpc_command = (C.ROUTE_IPV4_RPC_REQ_FILTER).format(
                network=network, prefix_length=prefix_length)

        rpc_reply = self.device.get(filter=('subtree', route_info_rpc_command)).xml
        # Converts string to etree
        routes_tree = ETREE.fromstring(rpc_reply)
        if ipv == 6:
            route_xpath = ".//rib{}:ipv6-rib".format(ipv)
        else:
            route_xpath = ".//rib{}:rib".format(ipv)
        route_xpath = route_xpath + "/rib{ip}:vrfs/rib{ip}:vrf/rib{ip}:afs/\
        rib{ip}:af/rib{ip}:safs/rib{ip}:saf/rib{ip}:ip-rib-route-table-names/\
        rib{ip}:ip-rib-route-table-name/rib{ip}:routes/rib{ip}:route".format(ip=ipv)
        for route in routes_tree.xpath(route_xpath, namespaces=C.NS):
            route_protocol = napalm.base.helpers.convert(
                str, self._find_txt(route, "./rib{}:protocol-name".format(ipv),
                    namespaces=C.NS).lower())
            if protocol and route_protocol != protocol:
                continue  # ignore routes learned via a different protocol
            # only in case the user requested a certain protocol
            route_details = {}
            address = self._find_txt(route, "./rib{}:prefix".format(
                            ipv), namespaces=C.NS)
            length = self._find_txt(route, "./rib{}:prefix-length-xr".format(
                            ipv), namespaces=C.NS)
            priority = napalm.base.helpers.convert(
                int, self._find_txt(route, "./rib{}:priority".format(
                            ipv), namespaces=C.NS))
            age = napalm.base.helpers.convert(
                int, self._find_txt(route, "./rib{}:route-age".format(
                            ipv), namespaces=C.NS))
            destination = napalm.base.helpers.convert(
                str, "{prefix}/{length}".format(
                    prefix=address, length=length))
            if destination not in routes.keys():
                routes[destination] = []

            route_details = {
                "current_active": False,
                "last_active": False,
                "age": age,
                "next_hop": "",
                "protocol": route_protocol,
                "outgoing_interface": "",
                "preference": priority,
                "selected_next_hop": False,
                "inactive_reason": "",
                "routing_table": "default",
                "protocol_attributes": {},
            }

            first_route = True
            for route_entry in route.xpath(
              ".//rib{ipv}:route-path/rib{ipv}:ipv{ipv}-rib-edm-path"
                                        .format(ipv=ipv), namespaces=C.NS):
                # get all possible entries
                next_hop = self._find_txt(
                 route_entry, "./rib{ipv}:address".format(ipv=ipv), namespaces=C.NS)
                single_route_details = {}
                single_route_details.update(route_details)
                single_route_details.update(
                    {"current_active": first_route, "next_hop": next_hop}
                )
                routes[destination].append(single_route_details)
                first_route = False

        return routes

    def get_snmp_information(self):
        """Return the SNMP configuration."""
        snmp_information = {}

        rpc_reply = self.device.get_config(source="running", filter=(
                                        "subtree", C.SNMP_RPC_REQ_FILTER)).xml
        # Converts string to etree
        snmp_result_tree = ETREE.fromstring(rpc_reply)

        _PRIVILEGE_MODE_MAP_ = {"read-only": "ro", "read-write": "rw"}

        snmp_information = {
            "chassis_id": self._find_txt(
                snmp_result_tree, ".//snmp:snmp/snmp:system/snmp:chassis-id", default="", namespaces=C.NS
            ),
            "contact": self._find_txt(
                snmp_result_tree, ".//snmp:snmp/snmp:system/snmp:contact", default="", namespaces=C.NS),
            "location": self._find_txt(
                snmp_result_tree, ".//snmp:snmp/snmp:system/snmp:location", default="", namespaces=C.NS),
            "community": {},
        }

        for community in snmp_result_tree.xpath(".//snmp:snmp/snmp:administration/\
             snmp:default-communities/snmp:default-community", namespaces=C.NS):
            name = self._find_txt(community, "./snmp:community-name", namespaces=C.NS)
            privilege = self._find_txt(community, "./snmp:priviledge", namespaces=C.NS)
            acl = (self._find_txt(community, "./snmp:v6-access-list", namespaces=C.NS)
                  or self._find_txt(community, "./snmp:v4-access-list", namespaces=C.NS))
            snmp_information["community"][name] = {
                "mode": _PRIVILEGE_MODE_MAP_.get(privilege, ""),
                "acl": acl,
            }

        return snmp_information

    def get_probes_config(self):
        """Return the configuration of the probes."""
        sla_config = {}

        _PROBE_TYPE_XML_TAG_MAP_ = {
            "icmp-echo": "icmp-ping",
            "udp-echo": "udp-ping",
            "icmp-jitter": "icmp-ping-timestamp",
            "udp-jitter": "udp-ping-timestamp",
        }

        rpc_reply = self.device.get_config(source="running", filter=(
                                    "subtree", C.PROBE_CFG_RPC_REQ_FILTER)).xml
        # Converts string to etree
        sla_config_result_tree = ETREE.fromstring(rpc_reply)

        probes_config_xpath = ".//prbc:ipsla/prbc:operation/prbc:definitions/\
            prbc:definition"
        for probe in sla_config_result_tree.xpath(probes_config_xpath, namespaces=C.NS):
            probe_name = self._find_txt(
                probe, "./prbc:operation-id", default="", namespaces=C.NS)
            operation_type_etree = probe.xpath(
                "./prbc:operation-type", namespaces=C.NS)
            if len(operation_type_etree):
                operation_type = operation_type_etree[0].getchildren(
                    )[0].tag.replace("{"+C.NS.get('prbc')+"}", "")
                probe_type = _PROBE_TYPE_XML_TAG_MAP_.get(operation_type, "")
                operation_xpath = "./prbc:operation-type/prbc:{op_type}".format(
                    op_type=operation_type)
                operation = probe.xpath(operation_xpath, namespaces=C.NS)[0]
                test_name = self._find_txt(
                    operation, "./prbc:tag", default="", namespaces=C.NS)
                source = self._find_txt(
                    operation, "./prbc:source-address", default="", namespaces=C.NS)
                target = self._find_txt(
                    operation, "./prbc:dest-address", default="", namespaces=C.NS)
                test_interval = napalm.base.helpers.convert(int, self._find_txt(
                    operation, "./prbc:frequency", default="", namespaces=C.NS))
                probe_count = napalm.base.helpers.convert(int, self._find_txt(
                    operation, "./prbc:history/prbc:buckets", default="", namespaces=C.NS))
                if probe_name not in sla_config.keys():
                    sla_config[probe_name] = {}
                if test_name not in sla_config[probe_name]:
                    sla_config[probe_name][test_name] = {}
                sla_config[probe_name][test_name] = {
                    "probe_type": probe_type,
                    "source": source,
                    "target": target,
                    "probe_count": probe_count,
                    "test_interval": test_interval,
                }

        return sla_config

    def get_probes_results(self):
        """Return the results of the probes."""
        sla_results = {}

        _PROBE_TYPE_XML_TAG_MAP_ = {
            "icmp-echo": "icmp-ping",
            "udp-echo": "udp-ping",
            "icmp-jitter": "icmp-ping-timestamp",
            "udp-jitter": "udp-ping-timestamp",
        }

        rpc_reply = self.device.get(filter=('subtree', C.PROBE_OPER_RPC_REQ_FILTER)).xml
        # Converts string to etree
        sla_results_tree = ETREE.fromstring(rpc_reply)

        probes_config = (
            self.get_probes_config()
        )  # need to retrieve also the configuration
        # source and tag/test_name not provided
        probe_result_xpath = ".//prb:ipsla/prb:operation-data/\
            prb:operations/prb:operation"
        for probe in sla_results_tree.xpath(probe_result_xpath, namespaces=C.NS):
            probe_name = self._find_txt(probe, "./prb:operation-id", default="", namespaces=C.NS)
            test_name = list(probes_config.get(probe_name).keys())[0]
            target = self._find_txt(
                probe, "./prb:history/prb:path/prb:lifes/prb:life/prb:buckets/\
                    prb:bucket[0]/prb:samples/prb:sample/prb:target-address/\
                    prb:ipv4-prefix-target/prb:address", default="", namespaces=C.NS
            )
            source = probes_config.get(probe_name).get(test_name, {}).get(
                                        "source", "")
            probe_type = _PROBE_TYPE_XML_TAG_MAP_.get(
                self._find_txt(
                    probe, "./prb:statistics/prb:latest/prb:target/\
                    prb:specific-stats/prb:op-type", default="",
                    namespaces=C.NS
                )
            )
            probe_count = (
                probes_config.get(probe_name).get(test_name, {}).get(
                        "probe_count", 0)
            )
            response_times = probe.xpath(
                "./prb:history/prb:target/prb:lifes/prb:life[last()]/\
                    prb:buckets/prb:bucket/prb:response-time",
                namespaces=C.NS
            )
            response_times = [
                napalm.base.helpers.convert(
                    int, self._find_txt(response_time, ".", default="0", namespaces=C.NS)
                )
                for response_time in response_times
            ]
            rtt = 0.0

            if len(response_times):
                rtt = sum(response_times, 0.0) / len(response_times)
            return_codes = probe.xpath(
                "./prb:history/prb:target/prb:lifes/prb:life[last()]/\
                    prb:buckets/prb:bucket/prb:return-code", namespaces=C.NS
            )
            return_codes = [
                self._find_txt(return_code, ".", default="", namespaces=C.NS)
                for return_code in return_codes
            ]

            last_test_loss = 0.0
            if len(return_codes):
                last_test_loss = napalm.base.helpers.convert(
                    int,
                    100
                    * (
                        1
                        - return_codes.count("ipsla-ret-code-ok")
                        / napalm.base.helpers.convert(float, len(return_codes))
                    ),
                )
            rms = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:aggregated/prb:hours/prb:hour/\
                    prb:distributed/prb:target/prb:distribution-intervals/\
                    prb:distribution-interval/prb:common-stats/\
                    prb:sum2-response-time", default="", namespaces=C.NS
                ),
            )
            global_test_updates = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:aggregated/prb:hours/prb:hour/\
                    prb:distributed/prb:target/prb:distribution-intervals/\
                    prb:distribution-interval/prb:common-stats/\
                    prb:update-count", default="", namespaces=C.NS
                ),
            )

            jitter = 0.0
            if global_test_updates:
                jitter = rtt - (rms / global_test_updates) ** 0.5
            # jitter = max(rtt - max(response_times), rtt - min(response_times))
            current_test_min_delay = 0.0  # no stats for undergoing test :(
            current_test_max_delay = 0.0
            current_test_avg_delay = 0.0
            last_test_min_delay = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe, "./prb:statistics/prb:latest/prb:target/\
                    prb:common-stats/prb:min-response-time", default="",
                    namespaces=C.NS
                ),
            )
            last_test_max_delay = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe, "./prb:statistics/prb:latest/prb:target/\
                    prb:common-stats/prb:max-response-time", default="",
                    namespaces=C.NS
                ),
            )
            last_test_sum_delay = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe, "./prb:statistics/prb:latest/prb:target/\
                    prb:common-stats/prb:sum-response-time", default="",
                    namespaces=C.NS
                ),
            )
            last_test_updates = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe, ".//prb:statistics/prb:latest/prb:target/\
                    prb:common-stats/prb:update-count", default="",
                    namespaces=C.NS
                ),
            )
            last_test_avg_delay = 0.0
            if last_test_updates:
                last_test_avg_delay = last_test_sum_delay / last_test_updates
            global_test_min_delay = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:aggregated/prb:hours/prb:hour/\
                    prb:distributed/prb:target/prb:distribution-intervals/\
                    prb:distribution-interval/prb:common-stats/\
                    prb:min-response-time", default="", namespaces=C.NS
                ),
            )
            global_test_max_delay = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:aggregated/prb:hours/prb:hour/\
                    prb:distributed/prb:target/prb:distribution-intervals/\
                    prb:distribution-interval/prb:common-stats/\
                    prb:max-response-time", default="", namespaces=C.NS
                ),
            )
            global_test_sum_delay = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:aggregated/prb:hours/prb:hour/\
                    prb:distributed/prb:target/prb:distribution-intervals/\
                    prb:distribution-interval/prb:common-stats/\
                    prb:sum-response-time", default="", namespaces=C.NS
                ),
            )
            global_test_avg_delay = 0.0
            if global_test_updates:
                global_test_avg_delay = global_test_sum_delay / global_test_updates
            if probe_name not in sla_results.keys():
                sla_results[probe_name] = {}
            sla_results[probe_name][test_name] = {
                "target": target,
                "source": source,
                "probe_type": probe_type,
                "probe_count": probe_count,
                "rtt": rtt,
                "round_trip_jitter": jitter,
                "last_test_loss": last_test_loss,
                "current_test_min_delay": current_test_min_delay,
                "current_test_max_delay": current_test_max_delay,
                "current_test_avg_delay": current_test_avg_delay,
                "last_test_min_delay": last_test_min_delay,
                "last_test_max_delay": last_test_max_delay,
                "last_test_avg_delay": last_test_avg_delay,
                "global_test_min_delay": global_test_min_delay,
                "global_test_max_delay": global_test_max_delay,
                "global_test_avg_delay": global_test_avg_delay,
            }

        return sla_results

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
        users = {}

        _CISCO_GROUP_TO_CISCO_PRIVILEGE_MAP = {
            "root-system": 15,
            "operator": 5,
            "sysadmin": 1,
            "serviceadmin": 1,
            "root-lr": 15,
        }

        _DEFAULT_USER_DETAILS = {"level": 0, "password": "", "sshkeys": []}

        rpc_reply = self.device.get_config(source="running", filter=(
                                            "subtree", C.USERS_RPC_REQ_FILTER)).xml
        # Converts string to etree
        users_xml_reply = ETREE.fromstring(rpc_reply)

        for user_entry in users_xml_reply.xpath(".//aaa:aaa/usr:usernames/\
                                            usr:username", namespaces=C.NS):
            username = self._find_txt(user_entry, "./usr:name", namespaces=C.NS)
            group = self._find_txt(user_entry, "./usr:usergroup-under-usernames/\
                                usr:usergroup-under-username/usr:name", namespaces=C.NS)
            level = _CISCO_GROUP_TO_CISCO_PRIVILEGE_MAP.get(group, 0)
            password = self._find_txt(user_entry, "./usr:password", default="", namespaces=C.NS)
            user_details = _DEFAULT_USER_DETAILS.copy()
            user_details.update(
                {"level": level, "password": password}
            )
            users[username] = user_details

        return users

    def get_config(self, retrieve="all", full=False):
        """Return device configuration."""
        # NOTE: 'full' argument ignored. 'with-default' capability not supported.

        # default values
        config = {"startup": "", "running": "", "candidate": ""}

        if retrieve.lower() in ["running", "all"]:
            config["running"] = str(
                                    self.device.get_config(
                                        source="running").xml)
        if retrieve.lower() in ["candidate", "all"]:
            config["candidate"] = str(
                                      self.device.get_config(
                                        source="candidate").xml)
        return config
