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
from pyIOSXR.iosxr import __execute_show__
from pyIOSXR.exceptions import InvalidInputError, XMLCLIError

from exceptions import MergeConfigException, ReplaceConfigException
import xml.etree.ElementTree as ET
from collections import defaultdict
import re


class IOSXRDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.pending_changes = False
        self.replace = False

        if optional_args is None:
            optional_args = {}
        self.port = optional_args.get('port', 22)
        self.device = IOSXR(hostname, username, password, timeout=timeout, port=self.port)

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

    def cli(self, command = ''):

        if not command:
            return 'Please enter a valid command!'

        try:
            return __execute_show__(self.device.device, command, self.timeout)
        except TimeoutError:
            return 'Execution of command `{command}` took too long! Please adjust your params!'.format(
                command = command
            )


    def get_arp_table(self, interface = '', host = '', ip = '', mac = ''):

        arp_table = dict()

        rpc_command = '<Get><Operational><ARP></ARP></Operational></Get>'

        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        for arp_entry in result_tree.findall('.//ResolutionHistoryDynamic/Entry/Entry'):
            try:
                age_nsec  = int(arp_entry.find('NsecTimestamp').text)
                age_sec   = age_nsec * (10**(-9))
                interface = arp_entry.find('IDBInterfaceName').text
                ip        = arp_entry.find('IPv4Address').text
                mac       = arp_entry.find('MACAddress').text

                if interface not in arp_table.keys():
                    arp_table[interface] = list()
                arp_table[interface].append(
                    {
                        'mac'   : mac,
                        'ip'    : ip,
                        'age'   : age_sec
                    }
                )
            except Exception:
                continue

        return arp_table

    def get_mac_address_table(self, address = '', interface = '', dynamic = False, static = False, vlan = None):

        mac_table = dict()

        rpc_command = '<Get><Operational><L2VPNForwarding></L2VPNForwarding></Operational></Get>'

        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        for mac_entry in result_tree.findall('.//L2FIBMACDetailTable/L2FIBMACDetail'):
            try:
                mac         = mac_entry.find('Naming/Address').text
                vlan        = int(mac_entry.find('Naming/Name').text.replace('vlan', ''))
                interface   = mac_entry.find('Segment/AC/InterfaceHandle').text

                if vlan not in mac_table.keys():
                    mac_table[vlan] = list()
                mac_table[vlan].append(
                    {
                        'mac'       : mac,
                        'interface' : interface,
                        'active'    : True,
                        'static'    : False,
                        'moves'     : None,
                        'last_move' : None
                    }
                )

            except Exception:
                continue

        return mac_table

    def get_ntp_peers(self):

        ntp_peers = dict()

        rpc_command = '<Get><Operational><NTP><NodeTable></NodeTable></NTP></Operational></Get>'

        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        for node in result_tree.iter('PeerInfoCommon'):
            if node is None:
                continue
            try:
                address         = node.find('Address').text
                referenceid     = node.find('ReferenceID').text
                hostpoll        = int(node.find('HostPoll').text)
                reachability    = node.find('Reachability').text
                stratum         = int(node.find('Stratum').text)
                delay           = float(node.find('Delay').text)
                offset          = float(node.find('Offset').text)
                jitter          = float(node.find('Dispersion').text)
                ntp_peers[address] = {
                    'referenceid'   : referenceid,
                    'stratum'       : stratum,
                    'type'          : None,
                    'when'          : None,
                    'hostpoll'      : hostpoll,
                    'reachability'  : reachability,
                    'delay'         : delay,
                    'offset'        : offset,
                    'jitter'        : jitter
                }
            except Exception:
                continue

        return ntp_peers

    def get_lldp_neighbors_detail(self, interface = ''):

        lldp_neighbors = dict()

        rpc_command = '<Get><Operational><LLDP></LLDP></Operational></Get>'

        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        for neighbor in result_tree.findall('.//Neighbors/DetailTable/Detail/Entry'):
            if neighbor is None:
                continue
            try:
                interface_name      = neighbor.find('ReceivingInterfaceName').text
                parent_interface    = neighbor.find('ReceivingParentInterfaceName').text
                device_id           = neighbor.find('DeviceID').text
                chassis_id          = neighbor.find('ChassisID').text
                port_id             = neighbor.find('PortIDDetail').text
                port_descr          = neighbor.find('Detail/PortDescription').text
                system_name         = neighbor.find('Detail/SystemName').text
                system_descr        = neighbor.find('Detail/SystemDescription').text
                # few other optional...
                # time_remaining = neighbor.find('Detail/TimeRemaining').text
                # system_capabilities = neighbor.find('Detail/SystemCapabilities').text
                # enabled_capabilities = neighbor.find('Detail/EnabledCapabilities').text
                # media_attachement_unit_type = neighbor.find('Detail/MediaAttachmentUnitType').text
                # port_vlan_id = neighbor.find('Detail/PortVlanID').text
                if interface_name not in lldp_neighbors.keys():
                    lldp_neighbors[interface_name] = list()
                lldp_neighbors[interface_name].append({
                    'parent_interface'          : parent_interface,
                    'remote_device_id'          : device_id,
                    'remote_system_chassis_id'  : chassis_id,
                    'remote_port'               : port_id,
                    'remote_port_description'   : port_descr,
                    'remote_system_name'        : system_name,
                    'remote_system_description' : system_descr
                })
            except Exception:
                continue # jump to next neighbor

        return lldp_neighbors

    def get_bgp_neighbors_detail(self, neighbor_address = ''):

        bgp_neighbors = dict()

        rpc_command = '''
                <Get>
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
                </Get>
        '''

        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        for neighbor in result_tree.iter('Neighbor'):
            try:
                local_as                = int(neighbor.find('LocalAS').text)
                peer_as                 = int(neighbor.find('RemoteAS').text)
                description             = neighbor.find('Description').text
                up                      = (neighbor.find('ConnectionState').text == 'BGP_ST_ESTAB')
                elapsed_time            = neighbor.find('ConnectionEstablishedTime').text
                peer_address_tag        = neighbor.find('ConnectionRemoteAddress/IPV4Address') or neighbor.find('ConnectionRemoteAddress/IPV6Address')
                peer_address            = peer_address_tag.text
                input_messages          = int(neighbor.find('MessgesReceived').text)
                output_messages         = int(neighbor.find('MessagesSent').text)
                connection_up_count     = int(neighbor.find('ConnectionUpCount').text)
                connection_down_count   = int(neighbor.find('ConnectionDownCount').text)
                import_policy           = neighbor.find('RoutePolicyIn').text
                export_policy           = neighbor.find('RoutePolicyOut').text
                accepted_prefixes       = int(neighbor.find('PrefixesAccepted').text)
                supressed_prefixes      = int(neighbor.find('PrefixesDenied').text)
                advertised_prefixes     = int(neighbor.find('PrefixesAdvertised'.text))
                local_port = int(neighbor.find('ConnectionLocalPort').text)
                remote_port = int(neighbor.find('ConnectionRemotePort').text)
                flap_count = connection_down_count / 2
                if up:
                    flap_count -= 1
                if peer_as not in bgp_neighbors.keys():
                    bgp_neighbors[peer_as] = list()
                bgp_neighbors[peer_as].append({
                    'peer_address'      : peer_address,
                    'input_messages'    : input_messages,
                    'output_messages'   : output_messages,
                    'peer_as'           : peer_as,
                    'up'                : up,
                    'elapsed_time'      : elapsed_time,
                    'flap_count'        : flap_count
                })
            except Exception:
                continue

        return bgp_neighbors

    def show_route(self, destination = ''):

        routes = {}

        if not destination:
            return 'Please specify a valid destination!'

        dest_split = destination.split('/')
        network = dest_split[0]
        prefix_tag = ''
        if len(dest_split) == 2:
            prefix_tag = '''
                <PrefixLength>
                    {prefix_length}
                </PrefixLength>
            '''.format(prefix_length = dest_split[1])

        rpc_command = '''
                <Get>
                    <Operational>
                        <RIB>
                            <VRFTable>
                                <VRF>
                                    <Naming>
                                        <VRFName>
                                            default
                                        </VRFName>
                                    </Naming>
                                    <AFTable>
                                        <AF>
                                            <Naming>
                                                <AFName>
                                                    IPv4
                                                </AFName>
                                            </Naming>
                                            <SAFTable>
                                                <SAF>
                                                    <Naming>
                                                        <SAFName>
                                                            Unicast
                                                        </SAFName>
                                                    </Naming>
                                                    <IP_RIBRouteTable>
                                                        <IP_RIBRoute>
                                                            <Naming>
                                                                <RouteTableName>
                                                                    default
                                                                </RouteTableName>
                                                            </Naming>
                                                            <RouteTable>
                                                              <Route>
                                                                <Naming>
                                                                  <Address>
                                                                    {network}
                                                                  </Address>
                                                                  {prefix}
                                                                </Naming>
                                                              </Route>
                                                            </RouteTable>
                                                        </IP_RIBRoute>
                                                    </IP_RIBRouteTable>
                                              </SAF>
                                            </SAFTable>
                                        </AF>
                                    </AFTable>
                                </VRF>
                            </VRFTable>
                        </RIB>
                    </Operational>
                </Get>
        '''.format(
            network = network,
            prefix  = prefix_tag
        )

        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        for route in result_tree.iter('Route'):
            try:
                address  = route.find('Prefix').text
                length   = route.find('PrefixLength').text
                distance = route.find('Distance').text
                protocol = route.find('ProtocolName').text
                priority = route.find('Priority').text
                distance = route.find('Distance').text
                age      = route.find('RouteAge').text
            except Exception:
                continue
            for route_entry in route.findall('RoutePath/Entry'):
                try:
                    next_hop  = route_entry.find('Address').text
                    from_peer = route_entry.find('InformationSource').text
                except Exception:
                    continue
            destination = '{prefix}/{length}'.format(
                prefix = address,
                length = length
            )
            if destination not in routes.keys():
                routes[destination] = list()
            routes[destination].append({
                'active-tag'        : None,
                'age'               : age,
                'as-path'           : None,
                'local-preference'  : priority,
                'next-hop'          : next_hop,
                'protocol'          : protocol,
                'via'               : None
            })

        return routes

    def get_interfaces_ip(self):

        ip_list = list()

        rpc_command_ipv4 = '<Get><Operational><IPV4Network></IPV4Network></Operational></Get>'

        ipv4_tree = ET.fromstring(self.device.make_rpc_call(rpc_command_ipv4))

        for interface in ipv4_tree.findall('.//InterfaceTable/Interface'):
            try:
                primary_ipv4 = interface.find('VRFTable/VRF/Detail/PrimaryAddress').text
                if primary_ipv4 not in [None, '0.0.0.0']:
                    ip_list.append(primary_ipv4)
                secondary_ipv4 = interface.find('VRFTable/VRF/Detail/SecondaryAddress').text
                # in case of failure / secondary address not set, will jump to the next entry
                if secondary_ipv4 not in [None, '::']:
                    ip_list.append(secondary_ipv4)
            except Exception:
                continue

        rpc_command_ipv6 = '<Get><Operational><IPV6Network></IPV6Network></Operational></Get>'

        ipv6_tree = ET.fromstring(self.device.make_rpc_call(rpc_command_ipv6))

        for interface in ipv6_tree.findall('.//InterfaceData/VRFTable/VRF/GlobalDetailTable/GlobalDetail/AddressList/Entry/Address'):
            ip_list.append(interface.text)

        return ip_list
