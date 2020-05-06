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
import re
import copy
from collections import defaultdict
import logging

# import third party lib
from lxml import etree as ETREE

from netaddr import IPAddress  # needed for traceroute, to check IP version
from netaddr.core import AddrFormatError

from napalm.pyIOSXR import IOSXR
from napalm.pyIOSXR.exceptions import ConnectError
from napalm.pyIOSXR.exceptions import TimeoutError
from napalm.pyIOSXR.exceptions import InvalidInputError

# import NAPALM base
import napalm.base.helpers
from napalm.base.netmiko_helpers import netmiko_args
from napalm.iosxr import constants as C
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionException
from napalm.base.exceptions import MergeConfigException
from napalm.base.exceptions import ReplaceConfigException
from napalm.base.exceptions import CommandTimeoutException

logger = logging.getLogger(__name__)


class IOSXRDriver(NetworkDriver):
    """IOS-XR driver class: inherits NetworkDriver from napalm.base."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.pending_changes = False
        self.replace = False
        if optional_args is None:
            optional_args = {}
        self.lock_on_connect = optional_args.get("config_lock", False)

        self.netmiko_optional_args = netmiko_args(optional_args)
        try:
            self.port = self.netmiko_optional_args.pop("port")
        except KeyError:
            self.port = 22

        self.platform = "iosxr"
        self.device = IOSXR(
            hostname,
            username,
            password,
            timeout=timeout,
            port=self.port,
            lock=self.lock_on_connect,
            **self.netmiko_optional_args,
        )

    def open(self):
        try:
            self.device.open()
        except ConnectError as conn_err:
            logger.error(conn_err.args[0])
            raise ConnectionException(conn_err.args[0])

    def close(self):
        logger.debug("Closed connection with device %s" % (self.hostname))
        self.device.close()

    def is_alive(self):
        """Returns a flag with the state of the connection."""
        if self.device is None:
            return {"is_alive": False}
        # Simply returns the flag from pyIOSXR
        return {"is_alive": self.device.is_alive()}

    def load_replace_candidate(self, filename=None, config=None):
        self.pending_changes = True
        self.replace = True
        if not self.lock_on_connect:
            self.device.lock()

        try:
            self.device.load_candidate_config(filename=filename, config=config)
        except InvalidInputError as e:
            self.pending_changes = False
            self.replace = False
            logger.error(e.args[0])
            raise ReplaceConfigException(e.args[0])

    def load_merge_candidate(self, filename=None, config=None):
        self.pending_changes = True
        self.replace = False
        if not self.lock_on_connect:
            self.device.lock()

        try:
            self.device.load_candidate_config(filename=filename, config=config)
        except InvalidInputError as e:
            self.pending_changes = False
            self.replace = False
            logger.error(e.args[0])
            raise MergeConfigException(e.args[0])

    def compare_config(self):
        if not self.pending_changes:
            return ""
        elif self.replace:
            return self.device.compare_replace_config().strip()
        else:
            return self.device.compare_config().strip()

    def commit_config(self, message=""):
        commit_args = {"comment": message} if message else {}
        if self.replace:
            self.device.commit_replace_config(**commit_args)
        else:
            self.device.commit_config(**commit_args)
        self.pending_changes = False
        if not self.lock_on_connect:
            self.device.unlock()

    def discard_config(self):
        self.device.discard_config()
        self.pending_changes = False
        if not self.lock_on_connect:
            self.device.unlock()

    def rollback(self):
        self.device.rollback()

    def get_facts(self):

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

        facts_rpc_request = "<Get><Operational><SystemTime/><PlatformInventory/>\
        </Operational></Get>"

        facts_rpc_reply = ETREE.fromstring(self.device.make_rpc_call(facts_rpc_request))
        system_time_xpath = ".//SystemTime/Uptime"
        platform_attr_xpath = ".//RackTable/Rack/Attributes/BasicInfo"
        system_time_tree = facts_rpc_reply.xpath(system_time_xpath)[0]
        try:
            platform_attr_tree = facts_rpc_reply.xpath(platform_attr_xpath)[0]
        except IndexError:
            platform_attr_tree = facts_rpc_reply.xpath(platform_attr_xpath)

        hostname = napalm.base.helpers.convert(
            str, napalm.base.helpers.find_txt(system_time_tree, "Hostname")
        )
        uptime = napalm.base.helpers.convert(
            int, napalm.base.helpers.find_txt(system_time_tree, "Uptime"), -1
        )
        serial = napalm.base.helpers.convert(
            str, napalm.base.helpers.find_txt(platform_attr_tree, "SerialNumber")
        )
        os_version = napalm.base.helpers.convert(
            str, napalm.base.helpers.find_txt(platform_attr_tree, "SoftwareRevision")
        )
        model = napalm.base.helpers.convert(
            str, napalm.base.helpers.find_txt(platform_attr_tree, "ModelName")
        )
        interface_list = sorted(list(self.get_interfaces().keys()))

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

        interfaces = {}

        INTERFACE_DEFAULTS = {
            "is_enabled": False,
            "is_up": False,
            "mac_address": "",
            "description": "",
            "speed": -1,
            "last_flapped": -1.0,
        }

        interfaces_rpc_request = "<Get><Operational><Interfaces/></Operational></Get>"

        interfaces_rpc_reply = ETREE.fromstring(
            self.device.make_rpc_call(interfaces_rpc_request)
        )

        for interface_tree in interfaces_rpc_reply.xpath(
            ".//Interfaces/InterfaceTable/Interface"
        ):
            interface_name = napalm.base.helpers.find_txt(
                interface_tree, "Naming/InterfaceName"
            )
            if not interface_name:
                continue
            is_up = (
                napalm.base.helpers.find_txt(interface_tree, "LineState")
                == "IM_STATE_UP"
            )
            enabled = (
                napalm.base.helpers.find_txt(interface_tree, "State")
                != "IM_STATE_ADMINDOWN"
            )
            raw_mac = napalm.base.helpers.find_txt(interface_tree, "MACAddress/Address")
            mac_address = napalm.base.helpers.convert(
                napalm.base.helpers.mac, raw_mac, raw_mac
            )
            speed = napalm.base.helpers.convert(
                int,
                napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(interface_tree, "Bandwidth"), 0
                )
                * 1e-3,
            )
            mtu = int(napalm.base.helpers.find_txt(interface_tree, "MTU"))
            description = napalm.base.helpers.find_txt(interface_tree, "Description")
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
        rpc_command = "<Get><Operational><Interfaces><InterfaceTable></InterfaceTable>\
        </Interfaces></Operational></Get>"
        result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

        interface_counters = {}

        for interface in result_tree.xpath(".//Interface"):
            interface_name = napalm.base.helpers.find_txt(interface, "InterfaceHandle")
            interface_stats = {}
            if not interface.xpath("InterfaceStatistics"):
                continue
            else:
                interface_stats = {}
                interface_stats["tx_multicast_packets"] = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        interface,
                        "InterfaceStatistics/FullInterfaceStats/MulticastPacketsSent",
                    ),
                )
                interface_stats["tx_discards"] = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        interface, "InterfaceStatistics/FullInterfaceStats/OutputDrops"
                    ),
                )
                interface_stats["tx_octets"] = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        interface, "InterfaceStatistics/FullInterfaceStats/BytesSent"
                    ),
                )
                interface_stats["tx_errors"] = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        interface, "InterfaceStatistics/FullInterfaceStats/OutputErrors"
                    ),
                )
                interface_stats["rx_octets"] = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        interface,
                        "InterfaceStatistics/FullInterfaceStats/BytesReceived",
                    ),
                )
                interface_stats["tx_unicast_packets"] = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        interface, "InterfaceStatistics/FullInterfaceStats/PacketsSent"
                    ),
                )
                interface_stats["rx_errors"] = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        interface, "InterfaceStatistics/FullInterfaceStats/InputErrors"
                    ),
                )
                interface_stats["tx_broadcast_packets"] = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        interface,
                        "InterfaceStatistics/FullInterfaceStats/BroadcastPacketsSent",
                    ),
                )
                interface_stats["rx_multicast_packets"] = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        interface,
                        "InterfaceStatistics/FullInterfaceStats/MulticastPacketsReceived",
                    ),
                )
                interface_stats["rx_broadcast_packets"] = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        interface,
                        "InterfaceStatistics/FullInterfaceStats/BroadcastPacketsReceived",
                    ),
                )
                interface_stats["rx_discards"] = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        interface, "InterfaceStatistics/FullInterfaceStats/InputDrops"
                    ),
                )
                interface_stats["rx_unicast_packets"] = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        interface,
                        "InterfaceStatistics/FullInterfaceStats/PacketsReceived",
                    ),
                )
            interface_counters[interface_name] = interface_stats

        return interface_counters

    def get_bgp_neighbors(self):
        def generate_vrf_query(vrf_name):
            """
            Helper to provide XML-query for the VRF-type we're interested in.
            """
            if vrf_name == "global":
                rpc_command = "<Get><Operational><BGP><InstanceTable><Instance><Naming>\
                <InstanceName>default</InstanceName></Naming><InstanceActive><DefaultVRF>\
                <GlobalProcessInfo></GlobalProcessInfo><NeighborTable></NeighborTable></DefaultVRF>\
                </InstanceActive></Instance></InstanceTable></BGP></Operational></Get>"

            else:
                rpc_command = "<Get><Operational><BGP><InstanceTable><Instance><Naming>\
                <InstanceName>default</InstanceName></Naming><InstanceActive><VRFTable><VRF>\
                <Naming>{vrf_name}</Naming><GlobalProcessInfo></GlobalProcessInfo><NeighborTable>\
                </NeighborTable></VRF></VRFTable></InstanceActive></Instance></InstanceTable>\
                </BGP></Operational></Get>".format(
                    vrf_name=vrf_name
                )
            return rpc_command

        """
        Initial run to figure out what VRF's are available
        Decided to get this one from Configured-section
        because bulk-getting all instance-data to do the same could get ridiculously heavy
        Assuming we're always interested in the DefaultVRF
        """

        active_vrfs = ["global"]

        rpc_command = "<Get><Operational><BGP><ConfigInstanceTable><ConfigInstance><Naming>\
        <InstanceName>default</InstanceName></Naming><ConfigInstanceVRFTable>\
        </ConfigInstanceVRFTable></ConfigInstance></ConfigInstanceTable></BGP></Operational></Get>"

        result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

        for node in result_tree.xpath(".//ConfigVRF"):
            active_vrfs.append(napalm.base.helpers.find_txt(node, "Naming/VRFName"))

        result = {}

        for vrf in active_vrfs:
            rpc_command = generate_vrf_query(vrf)
            result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

            this_vrf = {}
            this_vrf["peers"] = {}

            if vrf == "global":
                this_vrf["router_id"] = napalm.base.helpers.convert(
                    str,
                    napalm.base.helpers.find_txt(
                        result_tree,
                        "Get/Operational/BGP/InstanceTable/Instance/InstanceActive/DefaultVRF"
                        "/GlobalProcessInfo/VRF/RouterID",
                    ),
                )
            else:
                this_vrf["router_id"] = napalm.base.helpers.convert(
                    str,
                    napalm.base.helpers.find_txt(
                        result_tree,
                        "Get/Operational/BGP/InstanceTable/Instance/InstanceActive/VRFTable/VRF"
                        "/GlobalProcessInfo/VRF/RouterID",
                    ),
                )

            neighbors = {}

            for neighbor in result_tree.xpath(".//Neighbor"):
                this_neighbor = {}
                this_neighbor["local_as"] = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(neighbor, "LocalAS")
                )
                this_neighbor["remote_as"] = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(neighbor, "RemoteAS")
                )
                this_neighbor["remote_id"] = napalm.base.helpers.convert(
                    str, napalm.base.helpers.find_txt(neighbor, "RouterID")
                )

                if (
                    napalm.base.helpers.find_txt(neighbor, "ConnectionAdminStatus")
                    == "1"
                ):
                    this_neighbor["is_enabled"] = True

                try:
                    this_neighbor["description"] = napalm.base.helpers.convert(
                        str, napalm.base.helpers.find_txt(neighbor, "Description")
                    )
                except AttributeError:
                    logger.debug(
                        "No attribute 'description' for neighbor %s"
                        % (this_neighbor["remote_as"])
                    )
                    this_neighbor["description"] = ""

                this_neighbor["is_enabled"] = (
                    napalm.base.helpers.find_txt(neighbor, "ConnectionAdminStatus")
                    == "1"
                )

                if (
                    str(napalm.base.helpers.find_txt(neighbor, "ConnectionAdminStatus"))
                    == "1"
                ):
                    this_neighbor["is_enabled"] = True
                else:
                    this_neighbor["is_enabled"] = False

                if (
                    str(napalm.base.helpers.find_txt(neighbor, "ConnectionState"))
                    == "BGP_ST_ESTAB"
                ):
                    this_neighbor["is_up"] = True
                    this_neighbor["uptime"] = napalm.base.helpers.convert(
                        int,
                        napalm.base.helpers.find_txt(
                            neighbor, "ConnectionEstablishedTime"
                        ),
                    )
                else:
                    this_neighbor["is_up"] = False
                    this_neighbor["uptime"] = -1

                this_neighbor["address_family"] = {}

                if (
                    napalm.base.helpers.find_txt(
                        neighbor, "ConnectionRemoteAddress/AFI"
                    )
                    == "IPv4"
                ):
                    this_afi = "ipv4"
                elif (
                    napalm.base.helpers.find_txt(
                        neighbor, "ConnectionRemoteAddress/AFI"
                    )
                    == "IPv6"
                ):
                    this_afi = "ipv6"
                else:
                    this_afi = napalm.base.helpers.find_txt(
                        neighbor, "ConnectionRemoteAddress/AFI"
                    )

                this_neighbor["address_family"][this_afi] = {}

                try:
                    this_neighbor["address_family"][this_afi][
                        "received_prefixes"
                    ] = napalm.base.helpers.convert(
                        int,
                        napalm.base.helpers.find_txt(
                            neighbor, "AFData/Entry/PrefixesAccepted"
                        ),
                        0,
                    ) + napalm.base.helpers.convert(
                        int,
                        napalm.base.helpers.find_txt(
                            neighbor, "AFData/Entry/PrefixesDenied"
                        ),
                        0,
                    )
                    this_neighbor["address_family"][this_afi][
                        "accepted_prefixes"
                    ] = napalm.base.helpers.convert(
                        int,
                        napalm.base.helpers.find_txt(
                            neighbor, "AFData/Entry/PrefixesAccepted"
                        ),
                        0,
                    )
                    this_neighbor["address_family"][this_afi][
                        "sent_prefixes"
                    ] = napalm.base.helpers.convert(
                        int,
                        napalm.base.helpers.find_txt(
                            neighbor, "AFData/Entry/PrefixesAdvertised"
                        ),
                        0,
                    )
                except AttributeError:
                    this_neighbor["address_family"][this_afi]["received_prefixes"] = -1
                    this_neighbor["address_family"][this_afi]["accepted_prefixes"] = -1
                    this_neighbor["address_family"][this_afi]["sent_prefixes"] = -1

                neighbor_ip = napalm.base.helpers.ip(
                    napalm.base.helpers.find_txt(
                        neighbor, "Naming/NeighborAddress/IPV4Address"
                    )
                    or napalm.base.helpers.find_txt(
                        neighbor, "Naming/NeighborAddress/IPV6Address"
                    )
                )

                neighbors[neighbor_ip] = this_neighbor

            this_vrf["peers"] = neighbors
            result[vrf] = this_vrf

        return result

    def get_environment(self):
        def get_module_xml_query(module, selection):
            return "<Get><AdminOperational><EnvironmentalMonitoring><RackTable><Rack><Naming>\
            <rack>0</rack></Naming><SlotTable><Slot><Naming><slot>{slot}</slot></Naming>{name}\
            </Slot></SlotTable></Rack></RackTable></EnvironmentalMonitoring></AdminOperational>\
            </Get>".format(
                slot=module, name=selection
            )

        environment_status = {}
        environment_status["fans"] = {}
        environment_status["temperature"] = {}
        environment_status["power"] = {}
        environment_status["cpu"] = {}
        environment_status["memory"] = 0.0

        # finding slots with equipment we're interested in
        rpc_command = "<Get><AdminOperational><PlatformInventory><RackTable><Rack><Naming>\
        <Name>0</Name></Naming><SlotTable></SlotTable></Rack></RackTable></PlatformInventory>\
        </AdminOperational></Get>"

        result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

        active_modules = defaultdict(list)

        for slot in result_tree.xpath(".//Slot"):
            for card in slot.xpath(".//CardTable"):
                # find enabled slots, figoure out type and save for later
                if (
                    napalm.base.helpers.find_txt(
                        card, "Card/Attributes/FRUInfo/ModuleAdministrativeState"
                    )
                    == "ADMIN_UP"
                ):
                    slot_name = napalm.base.helpers.find_txt(slot, "Naming/Name")
                    module_type = re.sub(r"\d+", "", slot_name)
                    if len(module_type) > 0:
                        active_modules[module_type].append(slot_name)
                    else:
                        active_modules["LC"].append(slot_name)

        #
        # PSU's
        #

        for psu in active_modules["PM"]:
            if psu in ["PM6", "PM7"]:  # Cisco bug, chassis difference V01<->V02
                continue

            rpc_command = get_module_xml_query(psu, "")
            result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

            psu_status = {}
            psu_status["status"] = False
            psu_status["capacity"] = 0.0
            psu_status["output"] = 0.0

            for sensor in result_tree.xpath(".//SensorName"):
                if napalm.base.helpers.find_txt(sensor, "Naming/Name") == "host__VOLT":
                    this_psu_voltage = napalm.base.helpers.convert(
                        float, napalm.base.helpers.find_txt(sensor, "ValueBrief")
                    )
                elif (
                    napalm.base.helpers.find_txt(sensor, "Naming/Name") == "host__CURR"
                ):
                    this_psu_current = napalm.base.helpers.convert(
                        float, napalm.base.helpers.find_txt(sensor, "ValueBrief")
                    )
                elif napalm.base.helpers.find_txt(sensor, "Naming/Name") == "host__PM":
                    this_psu_capacity = napalm.base.helpers.convert(
                        float, napalm.base.helpers.find_txt(sensor, "ValueBrief")
                    )

            if this_psu_capacity > 0:
                psu_status["capacity"] = this_psu_capacity
                psu_status["status"] = True

            if this_psu_current and this_psu_voltage:
                psu_status["output"] = (
                    this_psu_voltage * this_psu_current
                ) / 1_000_000.0

            environment_status["power"][psu] = psu_status

        #
        # Memory
        #

        facts = self.get_facts()
        router_model = facts.get("model")
        is_xrv = router_model.lower().startswith("xrv")
        environment_status["memory"] = {"available_ram": 0.0, "used_ram": 0.0}

        if not is_xrv:
            rpc_command = "<Get><AdminOperational><MemorySummary>\
            </MemorySummary></AdminOperational></Get>"
            result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

            for node in result_tree.xpath(".//Node"):
                if (
                    napalm.base.helpers.find_txt(node, "Naming/NodeName/Slot")
                    == active_modules["RSP"][0]
                ):
                    available_ram = napalm.base.helpers.convert(
                        int,
                        napalm.base.helpers.find_txt(node, "Summary/SystemRAMMemory"),
                    )
                    free_ram = napalm.base.helpers.convert(
                        int,
                        napalm.base.helpers.find_txt(
                            node, "Summary/FreeApplicationMemory"
                        ),
                    )
                    break  # we're only looking at one of the RSP's

            if available_ram and free_ram:
                used_ram = available_ram - free_ram
                memory = {}
                memory["available_ram"] = available_ram
                memory["used_ram"] = used_ram
                environment_status["memory"] = memory

            #
            # Fans
            #

            for fan in active_modules["FT"]:
                rpc_command = get_module_xml_query(fan, "")
                result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))
                for module in result_tree.xpath(".//Module"):
                    for sensortype in module.xpath(".//SensorType"):
                        for sensorname in sensortype.xpath(".//SensorNameTable"):
                            if (
                                napalm.base.helpers.find_txt(
                                    sensorname, "SensorName/Naming/Name"
                                )
                                == "host__FanSpeed_0"
                            ):
                                environment_status["fans"][fan] = {
                                    "status": napalm.base.helpers.convert(
                                        int,
                                        napalm.base.helpers.find_txt(
                                            sensorname,
                                            "SensorName/ValueDetailed/Status",
                                        ),
                                    )
                                    == 1
                                }

        #
        # CPU
        #
        cpu = {}

        rpc_command = "<Get><Operational><SystemMonitoring></SystemMonitoring></Operational></Get>"
        result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

        for module in result_tree.xpath(".//CPUUtilization"):
            this_cpu = {}
            this_cpu["%usage"] = napalm.base.helpers.convert(
                float, napalm.base.helpers.find_txt(module, "TotalCPUFiveMinute")
            )

            rack = napalm.base.helpers.find_txt(module, "Naming/NodeName/Rack")
            slot = napalm.base.helpers.find_txt(module, "Naming/NodeName/Slot")
            instance = napalm.base.helpers.find_txt(module, "Naming/NodeName/Instance")
            position = "%s/%s/%s" % (rack, slot, instance)

            cpu[position] = this_cpu

        environment_status["cpu"] = cpu

        #
        # Temperature
        #

        slot_list = set()
        for category, slot in active_modules.items():
            slot_list |= set(slot)

        if not is_xrv:
            for slot in slot_list:
                rpc_command = get_module_xml_query(slot, "")
                result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))
                for sensor in result_tree.xpath(".//SensorName"):
                    if (
                        not napalm.base.helpers.find_txt(sensor, "Naming/Name")
                        == "host__Inlet0"
                    ):
                        continue
                    this_reading = {}
                    this_reading["temperature"] = napalm.base.helpers.convert(
                        float, napalm.base.helpers.find_txt(sensor, "ValueBrief")
                    )
                    threshold_value = [
                        napalm.base.helpers.convert(float, x.text)
                        for x in sensor.xpath("ThresholdTable/Threshold/ValueBrief")
                    ]
                    this_reading["is_alert"] = (
                        threshold_value[2]
                        <= this_reading["temperature"]
                        <= threshold_value[3]
                    )
                    this_reading["is_critical"] = (
                        threshold_value[4]
                        <= this_reading["temperature"]
                        <= threshold_value[5]
                    )
                    this_reading["temperature"] = this_reading["temperature"] / 10
                    environment_status["temperature"][slot] = this_reading

        return environment_status

    def get_lldp_neighbors(self):

        # init result dict
        lldp = {}
        sh_lldp = self.device.show_lldp_neighbors().splitlines()[5:-3]

        for n in sh_lldp:
            local_interface = n.split()[1]
            if local_interface not in lldp.keys():
                lldp[local_interface] = []

            lldp[local_interface].append(
                {
                    "hostname": napalm.base.helpers.convert(str, n.split()[0]),
                    "port": napalm.base.helpers.convert(str, n.split()[4]),
                }
            )

        return lldp

    def get_lldp_neighbors_detail(self, interface=""):

        lldp_neighbors = {}

        rpc_command = "<Get><Operational><LLDP></LLDP></Operational></Get>"

        result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

        for neighbor in result_tree.xpath(".//Neighbors/DetailTable/Detail/Entry"):
            interface_name = napalm.base.helpers.convert(
                str, napalm.base.helpers.find_txt(neighbor, "ReceivingInterfaceName")
            )
            parent_interface = napalm.base.helpers.convert(
                str,
                napalm.base.helpers.find_txt(neighbor, "ReceivingParentInterfaceName"),
            )
            chassis_id_raw = napalm.base.helpers.find_txt(neighbor, "ChassisID")
            chassis_id = napalm.base.helpers.convert(
                napalm.base.helpers.mac, chassis_id_raw, chassis_id_raw
            )
            port_id = napalm.base.helpers.convert(
                str, napalm.base.helpers.find_txt(neighbor, "PortIDDetail")
            )
            port_descr = napalm.base.helpers.convert(
                str, napalm.base.helpers.find_txt(neighbor, "Detail/PortDescription")
            )
            system_name = napalm.base.helpers.convert(
                str, napalm.base.helpers.find_txt(neighbor, "Detail/SystemName")
            )
            system_descr = napalm.base.helpers.convert(
                str, napalm.base.helpers.find_txt(neighbor, "Detail/SystemDescription")
            )
            system_capabilities = napalm.base.helpers.convert(
                str, napalm.base.helpers.find_txt(neighbor, "Detail/SystemCapabilities")
            )
            enabled_capabilities = napalm.base.helpers.convert(
                str,
                napalm.base.helpers.find_txt(neighbor, "Detail/EnabledCapabilities"),
            )

            if interface_name not in lldp_neighbors.keys():
                lldp_neighbors[interface_name] = []
            lldp_neighbors[interface_name].append(
                {
                    "parent_interface": parent_interface,
                    "remote_chassis_id": chassis_id,
                    "remote_port": port_id,
                    "remote_port_description": port_descr,
                    "remote_system_name": system_name,
                    "remote_system_description": system_descr,
                    "remote_system_capab": napalm.base.helpers.transform_lldp_capab(
                        system_capabilities
                    ),
                    "remote_system_enable_capab": napalm.base.helpers.transform_lldp_capab(
                        enabled_capabilities
                    ),
                }
            )

        return lldp_neighbors

    def cli(self, commands):

        cli_output = {}

        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            try:
                cli_output[str(command)] = str(self.device._execute_show(command))
            except TimeoutError:
                cli_output[
                    str(command)
                ] = 'Execution of command \
                    "{command}" took too long! Please adjust your params!'.format(
                    command=command
                )
                logger.error(str(cli_output))
                raise CommandTimeoutException(str(cli_output))

        return cli_output

    def get_bgp_config(self, group="", neighbor=""):

        bgp_config = {}

        # a helper
        def build_prefix_limit(af_table, limit, prefix_percent, prefix_timeout):
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
                        af_table[4:].lower(): {
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

        rpc_command = "<Get><Configuration><BGP><Instance><Naming>\
        <InstanceName>default</InstanceName></Naming></Instance></BGP></Configuration></Get>"
        result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

        if not group:
            neighbor = ""

        bgp_group_neighbors = {}
        for bgp_neighbor in result_tree.xpath(".//Neighbor"):
            group_name = napalm.base.helpers.find_txt(
                bgp_neighbor, "NeighborGroupAddMember"
            )
            peer = napalm.base.helpers.ip(
                napalm.base.helpers.find_txt(
                    bgp_neighbor, "Naming/NeighborAddress/IPV4Address"
                )
                or napalm.base.helpers.find_txt(
                    bgp_neighbor, "Naming/NeighborAddress/IPV6Address"
                )
            )
            if neighbor and peer != neighbor:
                continue
            description = napalm.base.helpers.find_txt(bgp_neighbor, "Description")
            peer_as = napalm.base.helpers.convert(
                int, napalm.base.helpers.find_txt(bgp_neighbor, "RemoteAS/AS_YY"), 0
            )
            local_as = napalm.base.helpers.convert(
                int, napalm.base.helpers.find_txt(bgp_neighbor, "LocalAS/AS_YY"), 0
            )
            af_table = napalm.base.helpers.find_txt(
                bgp_neighbor, "NeighborAFTable/NeighborAF/Naming/AFName"
            )
            prefix_limit = napalm.base.helpers.convert(
                int,
                napalm.base.helpers.find_txt(
                    bgp_neighbor,
                    "NeighborAFTable/NeighborAF/MaximumPrefixes/PrefixLimit",
                ),
                0,
            )
            prefix_percent = napalm.base.helpers.convert(
                int,
                napalm.base.helpers.find_txt(
                    bgp_neighbor,
                    "NeighborAFTable/NeighborAF/MaximumPrefixes/WarningPercentage",
                ),
                0,
            )
            prefix_timeout = napalm.base.helpers.convert(
                int,
                napalm.base.helpers.find_txt(
                    bgp_neighbor,
                    "NeighborAFTable/NeighborAF/MaximumPrefixes/RestartTime",
                ),
                0,
            )
            import_policy = napalm.base.helpers.find_txt(
                bgp_neighbor, "NeighborAFTable/NeighborAF/RoutePolicyIn"
            )
            export_policy = napalm.base.helpers.find_txt(
                bgp_neighbor, "NeighborAFTable/NeighborAF/RoutePolicyOut"
            )
            local_addr_raw = napalm.base.helpers.find_txt(
                bgp_neighbor, "LocalAddress/LocalIPAddress/IPV4Address"
            ) or napalm.base.helpers.find_txt(
                bgp_neighbor, "LocalAddress/LocalIPAddress/IPV6Address"
            )
            local_address = napalm.base.helpers.convert(
                napalm.base.helpers.ip, local_addr_raw, local_addr_raw
            )
            password = napalm.base.helpers.find_txt(
                bgp_neighbor, "Password/Password/Password"
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

        for bgp_group in result_tree.xpath(".//NeighborGroup"):
            group_name = napalm.base.helpers.find_txt(
                bgp_group, "Naming/NeighborGroupName"
            )
            if group and group != group_name:
                continue
            bgp_type = "external"  # by default external
            # must check
            description = napalm.base.helpers.find_txt(bgp_group, "Description")
            import_policy = napalm.base.helpers.find_txt(
                bgp_group, "NeighborGroupAFTable/NeighborGroupAF/RoutePolicyIn"
            )
            export_policy = napalm.base.helpers.find_txt(
                bgp_group, "NeighborGroupAFTable/NeighborGroupAF/RoutePolicyOut"
            )
            multipath = (
                napalm.base.helpers.find_txt(
                    bgp_group, "NeighborGroupAFTable/NeighborGroupAF/Multipath"
                )
                == "true"
            )
            peer_as = napalm.base.helpers.convert(
                int, napalm.base.helpers.find_txt(bgp_group, "RemoteAS/AS_YY"), 0
            )
            local_as = napalm.base.helpers.convert(
                int, napalm.base.helpers.find_txt(bgp_group, "LocalAS/AS_YY"), 0
            )
            multihop_ttl = napalm.base.helpers.convert(
                int,
                napalm.base.helpers.find_txt(bgp_group, "EBGPMultihop/MaxHopCount"),
                0,
            )
            local_addr_raw = napalm.base.helpers.find_txt(
                bgp_group, "LocalAddress/LocalIPAddress/IPV4Address"
            ) or napalm.base.helpers.find_txt(
                bgp_group, "LocalAddress/LocalIPAddress/IPV6Address"
            )
            local_address = napalm.base.helpers.convert(
                napalm.base.helpers.ip, local_addr_raw, local_addr_raw
            )
            af_table = napalm.base.helpers.find_txt(
                bgp_group, "NeighborAFTable/NeighborAF/Naming/AFName"
            )
            prefix_limit = napalm.base.helpers.convert(
                int,
                napalm.base.helpers.find_txt(
                    bgp_group,
                    "NeighborGroupAFTable/NeighborGroupAF/MaximumPrefixes/PrefixLimit",
                ),
                0,
            )
            prefix_percent = napalm.base.helpers.convert(
                int,
                napalm.base.helpers.find_txt(
                    bgp_group,
                    "NeighborGroupAFTable/NeighborGroupAF/MaximumPrefixes/WarningPercentage",
                ),
                0,
            )
            prefix_timeout = napalm.base.helpers.convert(
                int,
                napalm.base.helpers.find_txt(
                    bgp_group,
                    "NeighborGroupAFTable/NeighborGroupAF/MaximumPrefixes/RestartTime",
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

        bgp_neighbors_detail = {}

        active_vrfs = ["default"]

        active_vrfs_rpc_request = "<Get><Operational><BGP><ConfigInstanceTable><ConfigInstance>\
        <Naming><InstanceName>default</InstanceName></Naming><ConfigInstanceVRFTable/>\
        </ConfigInstance></ConfigInstanceTable></BGP></Operational></Get>"

        active_vrfs_rpc_reply = ETREE.fromstring(
            self.device.make_rpc_call(active_vrfs_rpc_request)
        )
        active_vrfs_tree = active_vrfs_rpc_reply.xpath(".//ConfigVRF")

        for active_vrf_tree in active_vrfs_tree:
            active_vrfs.append(
                napalm.base.helpers.find_txt(active_vrf_tree, "Naming/VRFName")
            )

        unique_active_vrfs = sorted(set(active_vrfs))

        bgp_neighbors_vrf_all_rpc = "<Get><Operational><BGP><InstanceTable><Instance><Naming>\
        <InstanceName>default</InstanceName></Naming>"

        for active_vrf in unique_active_vrfs:
            vrf_rpc = "<InstanceActive><VRFTable><VRF><Naming>{vrf_name}</Naming>\
            <GlobalProcessInfo/><NeighborTable/></VRF></VRFTable></InstanceActive>"
            bgp_neighbors_vrf_all_rpc += vrf_rpc.format(vrf_name=active_vrf)

        bgp_neighbors_vrf_all_rpc += (
            "</Instance></InstanceTable></BGP></Operational></Get>"
        )

        bgp_neighbors_vrf_all_tree = ETREE.fromstring(
            self.device.make_rpc_call(bgp_neighbors_vrf_all_rpc)
        )

        _BGP_STATE_ = {
            "0": "Unknown",
            "1": "Idle",
            "2": "Connect",
            "3": "OpenSent",
            "4": "OpenConfirm",
            "5": "Active",
            "6": "Established",
        }

        instance_active_list = bgp_neighbors_vrf_all_tree.xpath(
            ".//InstanceTable/Instance/InstanceActive/VRFTable/VRF"
        )

        for vrf_tree in instance_active_list:
            vrf_name = napalm.base.helpers.find_txt(vrf_tree, "Naming/VRFName")
            vrf_keepalive = napalm.base.helpers.convert(
                int,
                napalm.base.helpers.find_txt(
                    instance_active_list, "GlobalProcessInfo/VRF/KeepAliveTime"
                ),
            )
            vrf_holdtime = napalm.base.helpers.convert(
                int,
                napalm.base.helpers.find_txt(
                    instance_active_list, "GlobalProcessInfo/VRF/HoldTime"
                ),
            )
            if vrf_name not in bgp_neighbors_detail.keys():
                bgp_neighbors_detail[vrf_name] = {}
            for neighbor in vrf_tree.xpath("NeighborTable/Neighbor"):
                up = (
                    napalm.base.helpers.find_txt(neighbor, "ConnectionState")
                    == "BGP_ST_ESTAB"
                )
                local_as = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(neighbor, "LocalAS"), 0
                )
                remote_as = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(neighbor, "RemoteAS"), 0
                )
                router_id = napalm.base.helpers.ip(
                    napalm.base.helpers.find_txt(neighbor, "RouterID")
                )
                remote_address = napalm.base.helpers.ip(
                    napalm.base.helpers.find_txt(
                        neighbor, "Naming/NeighborAddress/IPV4Address"
                    )
                    or napalm.base.helpers.find_txt(
                        neighbor, "Naming/NeighborAddress/IPV6Address"
                    )
                )
                local_address_configured = (
                    napalm.base.helpers.find_txt(neighbor, "IsLocalAddressConfigured")
                    == "true"
                )
                local_address = napalm.base.helpers.ip(
                    napalm.base.helpers.find_txt(
                        neighbor, "ConnectionLocalAddress/IPV4Address"
                    )
                    or napalm.base.helpers.find_txt(
                        neighbor, "ConnectionLocalAddress/IPV6Address"
                    )
                )
                local_port = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(neighbor, "ConnectionLocalPort")
                )
                remote_address = napalm.base.helpers.ip(
                    napalm.base.helpers.find_txt(
                        neighbor, "ConnectionRemoteAddress/IPV4Address"
                    )
                    or napalm.base.helpers.find_txt(
                        neighbor, "ConnectionRemoteAddress/IPV6Address"
                    )
                )
                remote_port = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(neighbor, "ConnectionRemotePort")
                )
                multihop = (
                    napalm.base.helpers.find_txt(
                        neighbor, "IsExternalNeighborNotDirectlyConnected"
                    )
                    == "true"
                )
                remove_private_as = (
                    napalm.base.helpers.find_txt(
                        neighbor, "AFData/Entry/RemovePrivateASFromUpdates"
                    )
                    == "true"
                )
                multipath = (
                    napalm.base.helpers.find_txt(
                        neighbor, "AFData/Entry/SelectiveMultipathEligible"
                    )
                    == "true"
                )
                import_policy = napalm.base.helpers.find_txt(
                    neighbor, "AFData/Entry/RoutePolicyIn"
                )
                export_policy = napalm.base.helpers.find_txt(
                    neighbor, "AFData/Entry/RoutePolicyOut"
                )
                input_messages = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(neighbor, "MessgesReceived"), 0
                )
                output_messages = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(neighbor, "MessagesSent"), 0
                )
                connection_down_count = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(neighbor, "ConnectionDownCount"),
                    0,
                )
                messages_queued_out = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(neighbor, "MessagesQueuedOut"), 0
                )
                connection_state = (
                    napalm.base.helpers.find_txt(neighbor, "ConnectionState")
                    .replace("BGP_ST_", "")
                    .title()
                )
                if connection_state == "Estab":
                    connection_state = "Established"
                previous_connection_state = napalm.base.helpers.convert(
                    str,
                    _BGP_STATE_.get(
                        napalm.base.helpers.find_txt(
                            neighbor, "PreviousConnectionState", "0"
                        )
                    ),
                )
                active_prefix_count = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        neighbor, "AFData/Entry/NumberOfBestpaths"
                    ),
                    0,
                )
                accepted_prefix_count = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        neighbor, "AFData/Entry/PrefixesAccepted"
                    ),
                    0,
                )
                suppressed_prefix_count = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        neighbor, "AFData/Entry/PrefixesDenied"
                    ),
                    0,
                )
                received_prefix_count = accepted_prefix_count + suppressed_prefix_count
                advertised_prefix_count = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(
                        neighbor, "AFData/Entry/PrefixesAdvertised"
                    ),
                    0,
                )
                suppress_4byte_as = (
                    napalm.base.helpers.find_txt(neighbor, "Suppress4ByteAs") == "true"
                )
                local_as_prepend = (
                    napalm.base.helpers.find_txt(neighbor, "LocalASNoPrepend") != "true"
                )
                holdtime = (
                    napalm.base.helpers.convert(
                        int, napalm.base.helpers.find_txt(neighbor, "HoldTime"), 0
                    )
                    or vrf_holdtime
                )
                configured_holdtime = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(neighbor, "ConfiguredHoldTime"), 0
                )
                keepalive = (
                    napalm.base.helpers.convert(
                        int, napalm.base.helpers.find_txt(neighbor, "KeepAliveTime"), 0
                    )
                    or vrf_keepalive
                )
                configured_keepalive = napalm.base.helpers.convert(
                    int,
                    napalm.base.helpers.find_txt(neighbor, "ConfiguredKeepalive"),
                    0,
                )
                flap_count = int(connection_down_count / 2)
                if up:
                    flap_count -= 1
                if remote_as not in bgp_neighbors_detail[vrf_name].keys():
                    bgp_neighbors_detail[vrf_name][remote_as] = []
                bgp_neighbors_detail[vrf_name][remote_as].append(
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
        bgp_neighbors_detail["global"] = bgp_neighbors_detail.pop("default")
        return bgp_neighbors_detail

    def get_arp_table(self, vrf=""):
        if vrf:
            msg = "VRF support has not been added for this getter on this platform."
            raise NotImplementedError(msg)

        arp_table = []

        rpc_command = "<Get><Operational><ARP></ARP></Operational></Get>"

        result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

        for arp_entry in result_tree.xpath(".//EntryTable/Entry"):
            interface = napalm.base.helpers.convert(
                str, napalm.base.helpers.find_txt(arp_entry, ".//InterfaceName")
            )
            ip = napalm.base.helpers.convert(
                str, napalm.base.helpers.find_txt(arp_entry, ".//Address")
            )
            age = napalm.base.helpers.convert(
                float, napalm.base.helpers.find_txt(arp_entry, ".//Age"), 0.0
            )
            mac_raw = napalm.base.helpers.find_txt(arp_entry, ".//HardwareAddress")

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

        ntp_peers = {}

        rpc_command = "<Get><Configuration><NTP></NTP></Configuration></Get>"

        result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

        for version in ["IPV4", "IPV6"]:
            xpath = ".//Peer{version}Table/Peer{version}".format(version=version)
            for peer in result_tree.xpath(xpath):
                peer_type = napalm.base.helpers.find_txt(
                    peer, "PeerType{version}/Naming/PeerType".format(version=version)
                )
                if peer_type != "Peer":
                    continue
                peer_address = napalm.base.helpers.find_txt(
                    peer, "Naming/Address{version}".format(version=version)
                )
                if not peer_address:
                    continue
                ntp_peers[peer_address] = {}

        return ntp_peers

    def get_ntp_servers(self):

        ntp_servers = {}

        rpc_command = "<Get><Configuration><NTP></NTP></Configuration></Get>"

        result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

        for version in ["IPV4", "IPV6"]:
            xpath = ".//Peer{version}Table/Peer{version}".format(version=version)
            for peer in result_tree.xpath(xpath):
                peer_type = napalm.base.helpers.find_txt(
                    peer, "PeerType{version}/Naming/PeerType".format(version=version)
                )
                if peer_type != "Server":
                    continue
                server_address = napalm.base.helpers.find_txt(
                    peer, "Naming/Address{version}".format(version=version)
                )
                if not server_address:
                    continue
                ntp_servers[server_address] = {}

        return ntp_servers

    def get_ntp_stats(self):

        ntp_stats = []

        rpc_command = (
            "<Get><Operational><NTP><NodeTable></NodeTable></NTP></Operational></Get>"
        )

        result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

        xpath = ".//NodeTable/Node/Associations/PeerSummaryInfo/Entry/PeerInfoCommon"
        for node in result_tree.xpath(xpath):
            synchronized = napalm.base.helpers.find_txt(node, "IsSysPeer") == "true"
            address = napalm.base.helpers.find_txt(node, "Address")
            if address == "DLRSC node":
                continue
            referenceid = napalm.base.helpers.find_txt(node, "ReferenceID")
            hostpoll = napalm.base.helpers.convert(
                int, napalm.base.helpers.find_txt(node, "HostPoll", "0")
            )
            reachability = napalm.base.helpers.convert(
                int, napalm.base.helpers.find_txt(node, "Reachability", "0")
            )
            stratum = napalm.base.helpers.convert(
                int, napalm.base.helpers.find_txt(node, "Stratum", "0")
            )
            delay = napalm.base.helpers.convert(
                float, napalm.base.helpers.find_txt(node, "Delay", "0.0")
            )
            offset = napalm.base.helpers.convert(
                float, napalm.base.helpers.find_txt(node, "Offset", "0.0")
            )
            jitter = napalm.base.helpers.convert(
                float, napalm.base.helpers.find_txt(node, "Dispersion", "0.0")
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

        interfaces_ip = {}

        rpc_command_ipv4_ipv6 = "<Get><Operational><IPV4Network></IPV4Network>\
        <IPV6Network></IPV6Network></Operational></Get>"

        # only one request
        ipv4_ipv6_tree = ETREE.fromstring(
            self.device.make_rpc_call(rpc_command_ipv4_ipv6)
        )

        # parsing IPv4
        ipv4_xpath = ".//IPV4Network/InterfaceTable/Interface"
        for interface in ipv4_ipv6_tree.xpath(ipv4_xpath):
            interface_name = napalm.base.helpers.convert(
                str, napalm.base.helpers.find_txt(interface, "Naming/InterfaceName")
            )
            primary_ip = napalm.base.helpers.ip(
                napalm.base.helpers.find_txt(
                    interface, "VRFTable/VRF/Detail/PrimaryAddress"
                )
            )
            primary_prefix = napalm.base.helpers.convert(
                int,
                napalm.base.helpers.find_txt(
                    interface, "VRFTable/VRF/Detail/PrefixLength"
                ),
            )
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = {}
            if "ipv4" not in interfaces_ip[interface_name].keys():
                interfaces_ip[interface_name]["ipv4"] = {}
            if primary_ip not in interfaces_ip[interface_name].get("ipv4", {}).keys():
                interfaces_ip[interface_name]["ipv4"][primary_ip] = {
                    "prefix_length": primary_prefix
                }
            for secondary_address in interface.xpath(
                "VRFTable/VRF/Detail/SecondaryAddress/Entry"
            ):
                secondary_ip = napalm.base.helpers.ip(
                    napalm.base.helpers.find_txt(secondary_address, "Address")
                )
                secondary_prefix = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(secondary_address, "PrefixLength")
                )
                if secondary_ip not in interfaces_ip[interface_name]:
                    interfaces_ip[interface_name]["ipv4"][secondary_ip] = {
                        "prefix_length": secondary_prefix
                    }

        # parsing IPv6
        ipv6_xpath = (
            ".//IPV6Network/NodeTable/Node/InterfaceData"
            "/VRFTable/VRF/GlobalDetailTable/GlobalDetail"
        )
        for interface in ipv4_ipv6_tree.xpath(ipv6_xpath):
            interface_name = napalm.base.helpers.convert(
                str, napalm.base.helpers.find_txt(interface, "Naming/InterfaceName")
            )
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = {}
            if "ipv6" not in interfaces_ip[interface_name].keys():
                interfaces_ip[interface_name]["ipv6"] = {}
            for address in interface.xpath("AddressList/Entry"):
                address_ip = napalm.base.helpers.ip(
                    napalm.base.helpers.find_txt(address, "Address")
                )
                address_prefix = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(address, "PrefixLength")
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

        mac_table = []

        rpc_command = (
            "<Get><Operational><L2VPNForwarding></L2VPNForwarding></Operational></Get>"
        )

        result_tree = ETREE.fromstring(self.device.make_rpc_call(rpc_command))

        for mac_entry in result_tree.xpath(".//L2FIBMACDetailTable/L2FIBMACDetail"):
            mac_raw = napalm.base.helpers.find_txt(mac_entry, "Naming/Address")
            vlan = napalm.base.helpers.convert(
                int,
                napalm.base.helpers.find_txt(mac_entry, "Naming/Name", "").replace(
                    "vlan", ""
                ),
                0,
            )
            interface = napalm.base.helpers.find_txt(
                mac_entry, "Segment/AC/InterfaceHandle", ""
            )

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
        prefix_tag = ""
        if len(dest_split) == 2:
            prefix_tag = "<PrefixLength>{prefix_length}</PrefixLength>".format(
                prefix_length=dest_split[1]
            )

        ipv = 4
        try:
            ipv = IPAddress(network).version
        except AddrFormatError:
            logger.error("Wrong destination IP Address format supplied to get_route_to")
            raise TypeError("Wrong destination IP Address!")

        if ipv == 6:
            route_info_rpc_command = (
                "<Get><Operational><IPV6_RIB><VRFTable><VRF><Naming><VRFName>"
                "default</VRFName></Naming><AFTable><AF><Naming><AFName>IPv6</AFName></Naming>"
                "<SAFTable>"
                "<SAF><Naming><SAFName>Unicast</SAFName></Naming><IP_RIBRouteTable><IP_RIBRoute>"
                "<Naming>"
                "<RouteTableName>default</RouteTableName></Naming><RouteTable><Route><Naming>"
                "<Address>"
                "{network}</Address>{prefix}</Naming></Route></RouteTable></IP_RIBRoute>"
                "</IP_RIBRouteTable></SAF></SAFTable></AF></AFTable></VRF></VRFTable></IPV6_RIB>"
                "</Operational></Get>"
            ).format(network=network, prefix=prefix_tag)
        else:
            route_info_rpc_command = (
                "<Get><Operational><RIB><VRFTable><VRF><Naming><VRFName>"
                "default"
                "</VRFName></Naming><AFTable><AF><Naming><AFName>IPv4</AFName></Naming>"
                "<SAFTable><SAF>"
                "<Naming><SAFName>Unicast</SAFName></Naming><IP_RIBRouteTable><IP_RIBRoute>"
                "<Naming>"
                "<RouteTableName>default</RouteTableName></Naming><RouteTable><Route><Naming>"
                "<Address>"
                "{network}</Address>{prefix}</Naming></Route></RouteTable></IP_RIBRoute>"
                "</IP_RIBRouteTable>"
                "</SAF></SAFTable></AF></AFTable></VRF></VRFTable></RIB></Operational></Get>"
            ).format(network=network, prefix=prefix_tag)

        routes_tree = ETREE.fromstring(
            self.device.make_rpc_call(route_info_rpc_command)
        )

        for route in routes_tree.xpath(".//Route"):
            route_protocol = napalm.base.helpers.convert(
                str, napalm.base.helpers.find_txt(route, "ProtocolName").lower()
            )
            if protocol and route_protocol != protocol:
                continue  # ignore routes learned via a different protocol
                # only in case the user requested a certain protocol
            route_details = {}
            address = napalm.base.helpers.find_txt(route, "Prefix")
            length = napalm.base.helpers.find_txt(route, "PrefixLength")

            priority = napalm.base.helpers.convert(
                int, napalm.base.helpers.find_txt(route, "Priority")
            )
            age = napalm.base.helpers.convert(
                int, napalm.base.helpers.find_txt(route, "RouteAge")
            )
            destination = napalm.base.helpers.convert(
                str, "{prefix}/{length}".format(prefix=address, length=length)
            )
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

            # from BGP will try to get some more information
            if route_protocol == "bgp" and C.SR_638170159_SOLVED:
                # looks like IOS-XR does not filter correctly
                # !IMPORTANT
                bgp_route_info_rpc_command = "<Get><Operational><BGP><Active><DefaultVRF><AFTable>\
                <AF><Naming><AFName>IPv4Unicast</AFName></Naming><PathTable><Path><Naming><Network>\
                <IPV4Address>{network}</IPV4Address><IPV4PrefixLength>{prefix_len}\
                </IPV4PrefixLength></Network></Naming></Path></PathTable></AF></AFTable>\
                </DefaultVRF></Active></BGP></Operational></Get>".format(
                    network=network, prefix_len=dest_split[-1]
                )
                bgp_route_tree = ETREE.fromstring(
                    self.device.make_rpc_call(bgp_route_info_rpc_command)
                )
                for bgp_path in bgp_route_tree.xpath(".//Path"):
                    single_route_details = route_details.copy()
                    if "NotFound" not in bgp_path.keys():
                        best_path = (
                            napalm.base.helpers.find_txt(
                                bgp_path, "PathInformation/IsBestPath"
                            )
                            == "true"
                        )
                        local_preference = napalm.base.helpers.convert(
                            int,
                            napalm.base.helpers.find_txt(
                                bgp_path,
                                "AttributesAfterPolicyIn/CommonAttributes/LocalPreference",
                            ),
                            0,
                        )
                        local_preference = napalm.base.helpers.convert(
                            int,
                            napalm.base.helpers.find_txt(
                                bgp_path,
                                "AttributesAfterPolicyIn/CommonAttributes/LocalPreference",
                            ),
                            0,
                        )
                        remote_as = napalm.base.helpers.convert(
                            int,
                            napalm.base.helpers.find_txt(
                                bgp_path,
                                "AttributesAfterPolicyIn/CommonAttributes/NeighborAS",
                            ),
                            0,
                        )
                        remote_address = napalm.base.helpers.ip(
                            napalm.base.helpers.find_txt(
                                bgp_path, "PathInformation/NeighborAddress/IPV4Address"
                            )
                            or napalm.base.helpers.find_txt(
                                bgp_path, "PathInformation/NeighborAddress/IPV6Address"
                            )
                        )
                        as_path = " ".join(
                            [
                                bgp_as.text
                                for bgp_as in bgp_path.xpath(
                                    "AttributesAfterPolicyIn/CommonAttributes/NeighborAS/Entry"
                                )
                            ]
                        )
                        next_hop = napalm.base.helpers.find_txt(
                            bgp_path, "PathInformation/NextHop/IPV4Address"
                        ) or napalm.base.helpers.find_txt(
                            bgp_path, "PathInformation/NextHop/IPV6Address"
                        )
                        single_route_details["current_active"] = best_path
                        single_route_details["next_hop"] = next_hop
                        single_route_details["protocol_attributes"] = {
                            "local_preference": local_preference,
                            "as_path": as_path,
                            "remote_as": remote_as,
                            "remote_address": remote_address,
                        }
                    routes[destination].append(single_route_details)
            else:
                first_route = True
                for route_entry in route.xpath("RoutePath/Entry"):
                    # get all possible entries
                    next_hop = napalm.base.helpers.find_txt(route_entry, "Address")
                    single_route_details = {}
                    single_route_details.update(route_details)
                    single_route_details.update(
                        {"current_active": first_route, "next_hop": next_hop}
                    )
                    routes[destination].append(single_route_details)
                    first_route = False

        return routes

    def get_snmp_information(self):

        snmp_information = {}

        snmp_rpc_command = "<Get><Configuration><SNMP></SNMP></Configuration></Get>"

        snmp_result_tree = ETREE.fromstring(self.device.make_rpc_call(snmp_rpc_command))

        _PRIVILEGE_MODE_MAP_ = {"ReadOnly": "ro", "ReadWrite": "rw"}

        snmp_information = {
            "chassis_id": napalm.base.helpers.find_txt(
                snmp_result_tree, ".//ChassisID"
            ),
            "contact": napalm.base.helpers.find_txt(snmp_result_tree, ".//Contact"),
            "location": napalm.base.helpers.find_txt(snmp_result_tree, ".//Location"),
            "community": {},
        }

        for community in snmp_result_tree.xpath(".//DefaultCommunity"):
            name = napalm.base.helpers.find_txt(community, "Naming/CommunityName")
            privilege = napalm.base.helpers.find_txt(community, "Priviledge")
            acl = napalm.base.helpers.find_txt(community, "AccessList")
            snmp_information["community"][name] = {
                "mode": _PRIVILEGE_MODE_MAP_.get(privilege, ""),
                "acl": acl,
            }

        return snmp_information

    def get_probes_config(self):

        sla_config = {}

        _PROBE_TYPE_XML_TAG_MAP_ = {
            "ICMPEcho": "icmp-ping",
            "UDPEcho": "udp-ping",
            "ICMPJitter": "icmp-ping-timestamp",
            "UDPJitter": "udp-ping-timestamp",
        }

        sla_config_rpc_command = (
            "<Get><Configuration><IPSLA></IPSLA></Configuration></Get>"
        )

        sla_config_result_tree = ETREE.fromstring(
            self.device.make_rpc_call(sla_config_rpc_command)
        )

        for probe in sla_config_result_tree.xpath(".//Definition"):
            probe_name = napalm.base.helpers.find_txt(probe, "Naming/OperationID")
            operation_type = probe.xpath("OperationType")[0].getchildren()[0].tag
            probe_type = _PROBE_TYPE_XML_TAG_MAP_.get(operation_type, "")
            operation_xpath = "OperationType/{op_type}".format(op_type=operation_type)
            operation = probe.xpath(operation_xpath)[0]
            test_name = napalm.base.helpers.find_txt(operation, "Tag")
            source = napalm.base.helpers.find_txt(operation, "SourceAddress")
            target = napalm.base.helpers.find_txt(operation, "DestAddress")
            test_interval = napalm.base.helpers.convert(
                int, napalm.base.helpers.find_txt(operation, "Frequency", "0")
            )
            probe_count = napalm.base.helpers.convert(
                int, napalm.base.helpers.find_txt(operation, "History/Buckets", "0")
            )
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

        sla_results = {}

        _PROBE_TYPE_XML_TAG_MAP_ = {
            "ICMPEcho": "icmp-ping",
            "UDPEcho": "udp-ping",
            "ICMPJitter": "icmp-ping-timestamp",
            "UDPJitter": "udp-ping-timestamp",
        }

        sla_results_rpc_command = (
            "<Get><Operational><IPSLA></IPSLA></Operational></Get>"
        )

        sla_results_tree = ETREE.fromstring(
            self.device.make_rpc_call(sla_results_rpc_command)
        )

        probes_config = (
            self.get_probes_config()
        )  # need to retrieve also the configuration
        # source and tag/test_name not provided

        for probe in sla_results_tree.xpath(".//Operation"):
            probe_name = napalm.base.helpers.find_txt(probe, "Naming/OperationID")
            test_name = list(probes_config.get(probe_name).keys())[0]
            target = napalm.base.helpers.find_txt(
                probe,
                "History/Target/LifeTable/Life/BucketTable/Bucket[0]/TargetAddress\
                /IPv4AddressTarget",
            )
            source = probes_config.get(probe_name).get(test_name, {}).get("source", "")
            probe_type = _PROBE_TYPE_XML_TAG_MAP_.get(
                napalm.base.helpers.find_txt(
                    probe, "Statistics/Latest/Target/SpecificStats/op_type"
                )
            )
            probe_count = (
                probes_config.get(probe_name).get(test_name, {}).get("probe_count", 0)
            )
            response_times = probe.xpath(
                "History/Target/LifeTable/Life[last()]/BucketTable/Bucket/ResponseTime"
            )
            response_times = [
                napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(response_time, ".", "0")
                )
                for response_time in response_times
            ]
            rtt = 0.0

            if len(response_times):
                rtt = sum(response_times, 0.0) / len(response_times)
            return_codes = probe.xpath(
                "History/Target/LifeTable/Life[last()]/BucketTable/Bucket/ReturnCode"
            )
            return_codes = [
                napalm.base.helpers.find_txt(return_code, ".")
                for return_code in return_codes
            ]

            last_test_loss = 0.0
            if len(return_codes):
                last_test_loss = napalm.base.helpers.convert(
                    int,
                    100
                    * (
                        1
                        - return_codes.count("ipslaRetCodeOK")
                        / napalm.base.helpers.convert(float, len(return_codes))
                    ),
                )
            rms = napalm.base.helpers.convert(
                float,
                napalm.base.helpers.find_txt(
                    probe,
                    "Statistics/Aggregated/HourTable/Hour\
                    /Distributed/Target/DistributionIntervalTable/DistributionInterval/CommonStats\
                    /Sum2ResponseTime",
                ),
            )
            global_test_updates = napalm.base.helpers.convert(
                float,
                napalm.base.helpers.find_txt(
                    probe,
                    "Statistics/Aggregated/HourTable/Hour\
                    /Distributed/Target/DistributionIntervalTable/DistributionInterval/CommonStats\
                    /UpdateCount",
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
                napalm.base.helpers.find_txt(
                    probe, "Statistics/Latest/Target/CommonStats/MinResponseTime"
                ),
            )
            last_test_max_delay = napalm.base.helpers.convert(
                float,
                napalm.base.helpers.find_txt(
                    probe, "Statistics/Latest/Target/CommonStats/MaxResponseTime"
                ),
            )
            last_test_sum_delay = napalm.base.helpers.convert(
                float,
                napalm.base.helpers.find_txt(
                    probe, "Statistics/Latest/Target/CommonStats/SumResponseTime"
                ),
            )
            last_test_updates = napalm.base.helpers.convert(
                float,
                napalm.base.helpers.find_txt(
                    probe, "Statistics/Latest/Target/CommonStats/UpdateCount"
                ),
            )
            last_test_avg_delay = 0.0
            if last_test_updates:
                last_test_avg_delay = last_test_sum_delay / last_test_updates
            global_test_min_delay = napalm.base.helpers.convert(
                float,
                napalm.base.helpers.find_txt(
                    probe,
                    "Statistics/Aggregated/HourTable/Hour/Distributed/Target\
                    /DistributionIntervalTable/DistributionInterval/CommonStats/MinResponseTime",
                ),
            )
            global_test_max_delay = napalm.base.helpers.convert(
                float,
                napalm.base.helpers.find_txt(
                    probe,
                    "Statistics/Aggregated/HourTable/Hour/Distributed/Target\
                    /DistributionIntervalTable/DistributionInterval/CommonStats/MaxResponseTime",
                ),
            )
            global_test_sum_delay = napalm.base.helpers.convert(
                float,
                napalm.base.helpers.find_txt(
                    probe,
                    "Statistics/Aggregated/HourTable/Hour\
                    /Distributed/Target/DistributionIntervalTable/DistributionInterval\
                    /CommonStats/SumResponseTime",
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

        traceroute_result = {}

        ipv = 4
        try:
            ipv = IPAddress(destination).version
        except AddrFormatError:
            logger.error(
                "Incorrect format of IP Address in traceroute \
             with value provided:%s"
                % (str(destination))
            )
            return {"error": "Wrong destination IP Address!"}

        source_tag = ""
        ttl_tag = ""
        timeout_tag = ""
        vrf_tag = ""
        if source:
            source_tag = "<Source>{source}</Source>".format(source=source)
        if ttl:
            ttl_tag = "<MaxTTL>{maxttl}</MaxTTL>".format(maxttl=ttl)
        if timeout:
            timeout_tag = "<Timeout>{timeout}</Timeout>".format(timeout=timeout)
        if vrf:
            vrf_tag = "<VRFName>{vrf}</VRFName>".format(vrf=vrf)

        traceroute_rpc_command = "<Set><Action><TraceRoute><IPV{version}><Destination>{destination}\
        </Destination>{vrf_tag}{source_tag}{ttl_tag}{timeout_tag}</IPV{version}></TraceRoute></Action>\
        </Set>".format(
            version=ipv,
            destination=destination,
            vrf_tag=vrf_tag,
            source_tag=source_tag,
            ttl_tag=ttl_tag,
            timeout_tag=timeout_tag,
        )

        xml_tree_txt = self.device.make_rpc_call(traceroute_rpc_command)
        traceroute_tree = ETREE.fromstring(xml_tree_txt)

        results_tree = traceroute_tree.xpath(".//Results")
        if results_tree is None or not len(results_tree):
            return {"error": "Device returned empty results."}

        results_error = napalm.base.helpers.find_txt(results_tree[0], "Error")

        if results_error:
            return {"error": results_error}

        traceroute_result["success"] = {}

        last_hop_index = 1
        last_probe_index = 1
        last_probe_ip_address = "*"
        last_probe_host_name = ""
        last_hop_dict = {"probes": {}}

        for thanks_cisco in results_tree[0].getchildren():
            tag_name = thanks_cisco.tag
            tag_value = thanks_cisco.text
            if tag_name == "HopIndex":
                new_hop_index = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(thanks_cisco, ".", "-1")
                )
                if last_hop_index and last_hop_index != new_hop_index:
                    traceroute_result["success"][last_hop_index] = copy.deepcopy(
                        last_hop_dict
                    )
                    last_hop_dict = {"probes": {}}
                    last_probe_ip_address = "*"
                    last_probe_host_name = ""
                last_hop_index = new_hop_index
                continue
            tag_value = napalm.base.helpers.find_txt(thanks_cisco, ".", "")
            if tag_name == "ProbeIndex":
                last_probe_index = napalm.base.helpers.convert(int, tag_value, 0) + 1
                if last_probe_index not in last_hop_dict.get("probes").keys():
                    last_hop_dict["probes"][last_probe_index] = {}
                if not last_probe_host_name:
                    last_probe_host_name = last_probe_ip_address
                last_hop_dict["probes"][last_probe_index] = {
                    "ip_address": napalm.base.helpers.convert(
                        str, last_probe_ip_address
                    ),
                    "host_name": napalm.base.helpers.convert(str, last_probe_host_name),
                    "rtt": timeout * 1000.0,
                }
                continue
            if tag_name == "HopAddress":
                last_probe_ip_address = tag_value
                continue
            if tag_name == "HopHostName":
                last_probe_host_name = tag_value
                continue
            if tag_name == "DeltaTime":
                last_hop_dict["probes"][last_probe_index][
                    "rtt"
                ] = napalm.base.helpers.convert(float, tag_value, 0.0)
                continue

        if last_hop_index:
            traceroute_result["success"][last_hop_index] = last_hop_dict

        return traceroute_result

    def get_users(self):

        users = {}

        _CISCO_GROUP_TO_CISCO_PRIVILEGE_MAP = {
            "root-system": 15,
            "operator": 5,
            "sysadmin": 1,
            "serviceadmin": 1,
            "root-lr": 15,
        }

        _DEFAULT_USER_DETAILS = {"level": 0, "password": "", "sshkeys": []}

        users_xml_req = "<Get><Configuration><AAA></AAA></Configuration></Get>"

        users_xml_reply = ETREE.fromstring(self.device.make_rpc_call(users_xml_req))

        for user_entry in users_xml_reply.xpath(".//Username"):
            username = napalm.base.helpers.find_txt(user_entry, "Naming/Name")
            group = napalm.base.helpers.find_txt(
                user_entry, "UsergroupsUnderUsername/UsergroupUnderUsername/Naming/Name"
            )
            level = _CISCO_GROUP_TO_CISCO_PRIVILEGE_MAP.get(group, 0)
            password = napalm.base.helpers.find_txt(user_entry, "Password/Password")
            user_details = _DEFAULT_USER_DETAILS.copy()
            user_details.update({"level": level, "password": str(password)})
            users[username] = user_details

        return users

    def get_config(self, retrieve="all", full=False, sanitized=False):

        config = {"startup": "", "running": "", "candidate": ""}  # default values

        # IOS-XR only supports "all" on "show run"
        run_full = " all" if full else ""

        filter_strings = [r"^Building configuration.*$", r"^!! IOS XR Configuration.*$"]
        filter_pattern = napalm.base.helpers.generate_regex_or(filter_strings)

        if retrieve.lower() in ["running", "all"]:
            running = str(
                self.device._execute_config_show(f"show running-config{run_full}")
            )
            running = re.sub(filter_pattern, "", running, flags=re.M)
            config["running"] = running
        if retrieve.lower() in ["candidate", "all"]:
            candidate = str(
                self.device._execute_config_show("show configuration merge")
            )
            candidate = re.sub(filter_pattern, "", candidate, flags=re.M)
            config["candidate"] = candidate

        if sanitized:
            return napalm.base.helpers.sanitize_configs(
                config, C.CISCO_SANITIZE_FILTERS
            )

        return config
