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

from base import NetworkDriver
from napalm.utils import string_parsers

from pyIOSXR import IOSXR
from pyIOSXR.exceptions import InvalidInputError, XMLCLIError

from exceptions import MergeConfigException, ReplaceConfigException
import xml.etree.ElementTree as ET
from collections import defaultdict
import re


class IOSXRDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.device = IOSXR(hostname, username, password, timeout=timeout)
        self.pending_changes = False
        self.replace = False

    def open(self):
        self.device.open()

    def close(self):
        self.device.close()

    def load_replace_candidate(self, filename=None, config=None):
        self.pending_changes = True
        self.replace = True

        try:
            self.device.load_candidate_config(filename=filename, config=config)
        except InvalidInputError as e:
            self.pending_changes = False
            self.replace = False
            raise ReplaceConfigException(e.message)

    def load_merge_candidate(self, filename=None, config=None):
        self.pending_changes = True
        self.replace = False

        try:
            self.device.load_candidate_config(filename=filename, config=config)
        except InvalidInputError as e:
            self.pending_changes = False
            self.replace = False
            raise MergeConfigException(e.message)

    def compare_config(self):
        if not self.pending_changes:
            return ''
        elif self.replace:
            return self.device.compare_replace_config().strip()
        else:
            return self.device.compare_config().strip()

    def commit_config(self):
        if self.replace:
            self.device.commit_replace_config()
        else:
            self.device.commit_config()
        self.pending_changes = False

    def discard_config(self):
        self.device.discard_config()
        self.pending_changes = False

    def rollback(self):
        self.device.rollback()

    def get_facts(self):

        sh_ver = self.device.show_version()

        for line in sh_ver.splitlines():
            if 'Cisco IOS XR Software' in line:
                os_version = line.split()[-1]
            elif 'uptime' in line:
                uptime = string_parsers.convert_uptime_string_seconds(line)
                hostname = line.split()[0]
                fqdn = line.split()[0]
            elif 'Series' in line:
                model = ' '.join(line.split()[1:3])

        interface_list = list()

        for x in self.device.show_interface_description().splitlines()[3:-1]:
            if '.' not in x:
                interface_list.append(x.split()[0])

        result = {
            'vendor': u'Cisco',
            'os_version': unicode(os_version),
            'hostname': unicode(hostname),
            'uptime': uptime,
            'model': unicode(model),
            'serial_number': u'',
            'fqdn': unicode(fqdn),
            'interface_list': interface_list,
        }

        return result

    def get_interfaces(self):

        # init result dict
        result = {}

        # fetch show interface output
        sh_int = self.device.show_interfaces()
        # split per interface, eg by empty line
        interface_list = sh_int.rstrip().split('\n\n')
        # for each interface...
        for interface in interface_list:

            # splitting this and matching each line avoids issues with order
            # sorry...
            interface_lines = interface.split('\n')

            # init variables to match for
            interface_name = None
            is_enabled = None
            is_up = None
            mac_address = None
            description = None
            speed = None

            # loop though and match each line
            for line in interface_lines:
                description = ''
                if 'line protocol' in line:
                    lp = line.split()
                    interface_name = lp[0]
                    is_enabled = lp[2] == 'up,'
                    is_up = lp[6] == 'up'
                elif 'bia' in line:
                    mac_address = line.split()[-1].replace(')', '')
                elif 'Description' in line:
                    description = ' '.join(line.split()[1:])
                elif 'BW' in line:
                    speed = int(line.split()[4]) / 1000
            result[interface_name] = {
                'is_enabled': is_enabled,
                'is_up': is_up,
                'mac_address': unicode(mac_address),
                'description': unicode(description),
                'speed': speed,
                'last_flapped': -1.0,
            }

        return result

    def get_interfaces_counters(self):
        rpc_command = "<Get><Operational><Interfaces><InterfaceTable></InterfaceTable></Interfaces></Operational></Get>"
        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        interface_counters = dict()

        for interface in result_tree.iter('Interface'):

            interface_name = interface.find('InterfaceHandle').text

            interface_stats = dict()

            if interface.find('InterfaceStatistics') is None:
                continue
            else:
                interface_stats = dict()
                interface_stats['tx_multicast_packets'] = int(interface.find(
                    'InterfaceStatistics/FullInterfaceStats/MulticastPacketsSent').text)
                interface_stats['tx_discards'] = int(interface.find(
                    'InterfaceStatistics/FullInterfaceStats/OutputDrops').text)
                interface_stats['tx_octets'] = int(interface.find(
                    'InterfaceStatistics/FullInterfaceStats/BytesSent').text)
                interface_stats['tx_errors'] = int(interface.find(
                    'InterfaceStatistics/FullInterfaceStats/OutputErrors').text)
                interface_stats['rx_octets'] = int(interface.find(
                    'InterfaceStatistics/FullInterfaceStats/BytesReceived').text)
                interface_stats['tx_unicast_packets'] = int(interface.find(
                    'InterfaceStatistics/FullInterfaceStats/PacketsSent').text)
                interface_stats['rx_errors'] = int(interface.find(
                    'InterfaceStatistics/FullInterfaceStats/InputErrors').text)
                interface_stats['tx_broadcast_packets'] = int(interface.find(
                    'InterfaceStatistics/FullInterfaceStats/BroadcastPacketsSent').text)
                interface_stats['rx_multicast_packets'] = int(interface.find(
                    'InterfaceStatistics/FullInterfaceStats/MulticastPacketsReceived').text)
                interface_stats['rx_broadcast_packets'] = int(interface.find(
                    'InterfaceStatistics/FullInterfaceStats/BroadcastPacketsReceived').text)
                interface_stats['rx_discards'] = int(interface.find(
                    'InterfaceStatistics/FullInterfaceStats/InputDrops').text)
                interface_stats['rx_unicast_packets'] = int(interface.find(
                    'InterfaceStatistics/FullInterfaceStats/PacketsReceived').text)

            interface_counters[interface_name] = interface_stats

        return interface_counters

    def get_bgp_neighbors(self):
        def generate_vrf_query(vrf_name):
            """
            Helper to provide XML-query for the VRF-type we're interested in.
            """
            if vrf_name == "global":
                rpc_command = """<Get>
                        <Operational>
                            <BGP>
                                <InstanceTable>
                                    <Instance>
                                        <Naming>
                                            <InstanceName>
                                                default
                                            </InstanceName>
                                        </Naming>
                                        <InstanceActive>
                                            <DefaultVRF>
                                                <GlobalProcessInfo>
                                                </GlobalProcessInfo>
                                                <NeighborTable>
                                                </NeighborTable>
                                            </DefaultVRF>
                                        </InstanceActive>
                                    </Instance>
                                </InstanceTable>
                            </BGP>
                        </Operational>
                    </Get>"""

            else:
                rpc_command = """<Get>
                        <Operational>
                            <BGP>
                                <InstanceTable>
                                    <Instance>
                                        <Naming>
                                            <InstanceName>
                                                default
                                            </InstanceName>
                                        </Naming>
                                        <InstanceActive>
                                            <VRFTable>
                                                <VRF>
                                                    <Naming>
                                                        %s
                                                    </Naming>
                                                    <GlobalProcessInfo>
                                                    </GlobalProcessInfo>
                                                    <NeighborTable>
                                                    </NeighborTable>
                                                </VRF>
                                            </VRFTable>
                                         </InstanceActive>
                                    </Instance>
                                </InstanceTable>
                            </BGP>
                        </Operational>
                    </Get>""" % vrf_name
            return rpc_command

        """
        Initial run to figure out what VRF's are available
        Decided to get this one from Configured-section because bulk-getting all instance-data to do the same could get ridiculously heavy
        Assuming we're always interested in the DefaultVRF
        """

        active_vrfs = ["global"]

        rpc_command = """<Get>
                            <Operational>
                                <BGP>
                                    <ConfigInstanceTable>
                                        <ConfigInstance>
                                            <Naming>
                                                <InstanceName>
                                                    default
                                                </InstanceName>
                                            </Naming>
                                            <ConfigInstanceVRFTable>
                                            </ConfigInstanceVRFTable>
                                        </ConfigInstance>
                                    </ConfigInstanceTable>
                                </BGP>
                            </Operational>
                        </Get>"""

        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        for node in result_tree.iter('ConfigVRF'):
            active_vrfs.append(str(node.find('Naming/VRFName').text))

        result = dict()

        for vrf in active_vrfs:
            rpc_command = generate_vrf_query(vrf)
            result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

            this_vrf = dict()
            this_vrf['peers'] = dict()

            if vrf == "global":
                this_vrf['router_id'] = unicode(result_tree.find(
                    'Get/Operational/BGP/InstanceTable/Instance/InstanceActive/DefaultVRF/GlobalProcessInfo/VRF/RouterID').text)
            else:
                this_vrf['router_id'] = unicode(result_tree.find(
                    'Get/Operational/BGP/InstanceTable/Instance/InstanceActive/VRFTable/VRF/GlobalProcessInfo/VRF/RouterID').text)

            neighbors = dict()

            for neighbor in result_tree.iter('Neighbor'):
                this_neighbor = dict()
                this_neighbor['local_as'] = int(neighbor.find('LocalAS').text)
                this_neighbor['remote_as'] = int(neighbor.find('RemoteAS').text)
                this_neighbor['remote_id'] = unicode(neighbor.find('RouterID').text)

                if neighbor.find('ConnectionAdminStatus').text is "1":
                    this_neighbor['is_enabled'] = True
                try:
                    this_neighbor['description'] = unicode(neighbor.find('Description').text)
                except:
                    pass

                this_neighbor['is_enabled'] = str(neighbor.find('ConnectionAdminStatus').text) is "1"

                if str(neighbor.find('ConnectionAdminStatus').text) is "1":
                    this_neighbor['is_enabled'] = True
                else:
                    this_neighbor['is_enabled'] = False

                if str(neighbor.find('ConnectionState').text) == "BGP_ST_ESTAB":
                    this_neighbor['is_up'] = True
                    this_neighbor['uptime'] = int(neighbor.find('ConnectionEstablishedTime').text)
                else:
                    this_neighbor['is_up'] = False
                    this_neighbor['uptime'] = -1

                this_neighbor['address_family'] = dict()

                if neighbor.find('ConnectionRemoteAddress/AFI').text == "IPv4":
                    this_afi = "ipv4"
                elif neighbor.find('ConnectionRemoteAddress/AFI').text == "IPv6":
                    this_afi = "ipv6"
                else:
                    this_afi = neighbor.find('ConnectionRemoteAddress/AFI').text

                this_neighbor['address_family'][this_afi] = dict()

                try:
                    this_neighbor['address_family'][this_afi][
                        "received_prefixes"] = int(neighbor.find('AFData/Entry/PrefixesAccepted').text) + int(
                            neighbor.find('AFData/Entry/PrefixesDenied').text)
                    this_neighbor['address_family'][this_afi][
                        "accepted_prefixes"] = int(neighbor.find('AFData/Entry/PrefixesAccepted').text)
                    this_neighbor['address_family'][this_afi][
                        "sent_prefixes"] = int(neighbor.find('AFData/Entry/PrefixesAdvertised').text)
                except AttributeError:
                    this_neighbor['address_family'][this_afi]["received_prefixes"] = -1
                    this_neighbor['address_family'][this_afi]["accepted_prefixes"] = -1
                    this_neighbor['address_family'][this_afi]["sent_prefixes"] = -1

                try:
                    neighbor_ip = unicode(neighbor.find('Naming/NeighborAddress/IPV4Address').text)
                except:
                    neighbor_ip = unicode(neighbor.find('Naming/NeighborAddress/IPV6Address').text)

                neighbors[neighbor_ip] = this_neighbor

            this_vrf['peers'] = neighbors
            result[vrf] = this_vrf

        return result

    def get_environment(self):
        def get_module_xml_query(module,selection):
            return """<Get>
                        <AdminOperational>
                            <EnvironmentalMonitoring>
                                <RackTable>
                                    <Rack>
                                        <Naming>
                                            <rack>0</rack>
                                        </Naming>
                                        <SlotTable>
                                            <Slot>
                                                <Naming>
                                                    <slot>%s</slot>
                                                </Naming>
                                                %s
                                            </Slot>
                                        </SlotTable>
                                    </Rack>
                                </RackTable>
                            </EnvironmentalMonitoring>
                        </AdminOperational>
                    </Get>""" % (module,selection)

        environment_status = dict()
        environment_status['fans'] = dict()
        environment_status['temperature'] = dict()
        environment_status['power'] = dict()
        environment_status['cpu'] = dict()
        environment_status['memory'] = int()
        
        # finding slots with equipment we're interested in
        rpc_command = """<Get>
            <AdminOperational>
                <PlatformInventory>
                    <RackTable>
                        <Rack>
                            <Naming>
                                <Name>0</Name>
                            </Naming>
                            <SlotTable>
                            </SlotTable>
                        </Rack>
                    </RackTable>
                </PlatformInventory>
            </AdminOperational>
        </Get>"""

        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        active_modules = defaultdict(list)

        for slot in result_tree.iter("Slot"):
            for card in slot.iter("CardTable"):
                #find enabled slots, figoure out type and save for later
                if card.find('Card/Attributes/FRUInfo/ModuleAdministrativeState').text == "ADMIN_UP":
                    
                    slot_name = slot.find('Naming/Name').text
                    module_type = re.sub("\d+", "", slot_name)
                    if len(module_type) > 0:
                        active_modules[module_type].append(slot_name)
                    else:
                        active_modules["LC"].append(slot_name)

        #
        # PSU's
        #

        for psu in active_modules['PM']:
            if psu in ["PM6", "PM7"]:    # Cisco bug, chassis difference V01<->V02
                continue

            rpc_command = get_module_xml_query(psu,'')
            result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

            psu_status = dict()
            psu_status['status'] = False
            psu_status['capacity'] = float()
            psu_status['output'] = float()

            for sensor in result_tree.iter('SensorName'):
                if sensor.find('Naming/Name').text == "host__VOLT":
                    this_psu_voltage = float(sensor.find('ValueBrief').text)
                elif sensor.find('Naming/Name').text == "host__CURR":
                    this_psu_current = float(sensor.find('ValueBrief').text)
                elif sensor.find('Naming/Name').text == "host__PM":
                    this_psu_capacity = float(sensor.find('ValueBrief').text)

            if this_psu_capacity > 0:
                psu_status['capacity'] = this_psu_capacity
                psu_status['status'] = True

            if this_psu_current and this_psu_voltage:
                psu_status['output'] = (this_psu_voltage * this_psu_current) / 1000000.0

            environment_status['power'][psu] = psu_status

        #
        # Memory
        #
        
        rpc_command = "<Get><AdminOperational><MemorySummary></MemorySummary></AdminOperational></Get>"
        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        for node in result_tree.iter('Node'):
            print 
            if node.find('Naming/NodeName/Slot').text == active_modules['RSP'][0]:    # first enabled RSP
                available_ram = int(node.find('Summary/SystemRAMMemory').text)
                free_ram = int(node.find('Summary/FreeApplicationMemory').text)
                break    # we're only looking at one of the RSP's

        if available_ram and free_ram:
            used_ram = available_ram - free_ram
            memory = dict()
            memory['available_ram'] = available_ram
            memory['used_ram'] = used_ram
            environment_status['memory'] = memory

        #
        # Fans
        #

        for fan in active_modules['FT']:
            rpc_command = get_module_xml_query(fan,'')
            result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))
            for module in result_tree.iter('Module'):
                for sensortype in module.iter('SensorType'):
                    for sensorname in sensortype.iter('SensorNameTable'):
                        if sensorname.find('SensorName/Naming/Name').text == "host__FanSpeed_0":
                            environment_status['fans'][fan] = {'status': int(sensorname.find(
                                'SensorName/ValueDetailed/Status').text) is 1}

        #
        # CPU
        #
        cpu = dict()
 
        rpc_command = "<Get><Operational><SystemMonitoring></SystemMonitoring></Operational></Get>"
        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        for module in result_tree.iter('CPUUtilization'):
            this_cpu = dict()
            this_cpu["%usage"] = float(module.find('TotalCPUFiveMinute').text)

            rack = module.find('Naming/NodeName/Rack').text
            slot = module.find('Naming/NodeName/Slot').text
            instance = module.find('Naming/NodeName/Instance').text
            position =  "%s/%s/%s" % (rack,slot,instance)

            cpu[position] = this_cpu

        environment_status["cpu"] = cpu

        #
        # Temperature
        #

        temperature = dict()

        slot_list = set()
        for category, slot in active_modules.iteritems():
            slot_list |= set(slot)

        for slot in slot_list:
            rpc_command = get_module_xml_query(slot,'')
            result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

            for sensor in result_tree.findall(".//SensorName"):
                if not sensor.find('Naming/Name').text == "host__Inlet0":
                    continue
                this_reading = dict()
                this_reading['temperature'] = float(sensor.find('ValueBrief').text)

                threshold_value = [float(x.text) for x in sensor.findall("ThresholdTable/Threshold/ValueBrief")]

                this_reading['is_alert'] = threshold_value[2] <= this_reading['temperature'] <= threshold_value[3]
                this_reading['is_critical'] = threshold_value[4] <= this_reading['temperature'] <= threshold_value[5]

                this_reading['temperature'] = this_reading['temperature']/10

                environment_status["temperature"][slot] = this_reading

        return environment_status

    def get_lldp_neighbors(self):

        # init result dict
        lldp = {}

        # fetch sh ip bgp output
        sh_lldp = self.device.show_lldp_neighbors().splitlines()[5:-3]

        for n in sh_lldp:
            local_interface = n.split()[1]
            if local_interface not in lldp.keys():
                lldp[local_interface] = list()

            lldp[local_interface].append({'hostname': unicode(n.split()[0]), 'port': unicode(n.split()[4]), })

        return lldp
