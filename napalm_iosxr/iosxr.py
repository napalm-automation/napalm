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

# python std lib
import re
import copy
from collections import defaultdict

# third party libs
import xml.etree.ElementTree as ET

from netaddr import IPAddress
from netaddr.core import AddrFormatError

from pyIOSXR import IOSXR
from pyIOSXR.iosxr import __execute_show__
from pyIOSXR.exceptions import InvalidInputError, TimeoutError, EOFError

# napalm_base
from napalm_base.base import NetworkDriver
from napalm_base.utils import string_parsers
from napalm_base.exceptions import ConnectionException, MergeConfigException, ReplaceConfigException,\
                                   CommandErrorException, CommandTimeoutException


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
        self.lock_on_connect = optional_args.get('config_lock', True)
        self.device = IOSXR(hostname, username, password, timeout=timeout, port=self.port, lock=self.lock_on_connect)

    def open(self):
        try:
            self.device.open()
        except EOFError as ee:
            raise ConnectionException(ee.message)

    def close(self):
        self.device.close()

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
            raise ReplaceConfigException(e.message)

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
        if not self.lock_on_connect:
            self.device.unlock()

    def discard_config(self):
        self.device.discard_config()
        self.pending_changes = False
        if not self.lock_on_connect:
            self.device.unlock()

    def rollback(self):
        self.device.rollback()


    # perhaps both should be moved in napalm_base.helpers at some point
    @staticmethod
    def _find_txt(xml_tree, path, default = ''):
        try:
            return xml_tree.find(path).text.strip()
        except Exception:
            return default


    @staticmethod
    def _convert(to, who, default = u''):
        if who is None:
            return default
        try:
            return to(who)
        except:
            return default


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
                except AttributeError:
                    this_neighbor['description'] = u''

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
                except AttributeError:
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
        sh_lldp = self.device.show_lldp_neighbors().splitlines()[5:-3]

        for n in sh_lldp:
            local_interface = n.split()[1]
            if local_interface not in lldp.keys():
                lldp[local_interface] = list()

            lldp[local_interface].append({'hostname': unicode(n.split()[0]), 'port': unicode(n.split()[4]), })

        return lldp

    def get_lldp_neighbors_detail(self, interface = ''):

        lldp_neighbors = dict()

        rpc_command = '<Get><Operational><LLDP></LLDP></Operational></Get>'

        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        for neighbor in result_tree.findall('.//Neighbors/DetailTable/Detail/Entry'):
            if neighbor is None:
                continue
            try:
                interface_name      = unicode(neighbor.find('ReceivingInterfaceName').text)
                parent_interface    = unicode(neighbor.find('ReceivingParentInterfaceName').text)
                device_id           = unicode(neighbor.find('DeviceID').text)
                chassis_id          = unicode(neighbor.find('ChassisID').text)
                port_id             = unicode(neighbor.find('PortIDDetail').text)
                port_descr          = unicode(neighbor.find('Detail/PortDescription').text)
                system_name         = unicode(neighbor.find('Detail/SystemName').text)
                system_descr        = unicode(neighbor.find('Detail/SystemDescription').text)
                system_capabilities = unicode(neighbor.find('Detail/SystemCapabilities').text)
                enabled_capabilities= unicode(neighbor.find('Detail/EnabledCapabilities').text)
                # few other optional...
                # time_remaining = neighbor.find('Detail/TimeRemaining').text
                # media_attachement_unit_type = neighbor.find('Detail/MediaAttachmentUnitType').text
                # port_vlan_id = neighbor.find('Detail/PortVlanID').text

                if interface_name not in lldp_neighbors.keys():
                    lldp_neighbors[interface_name] = list()
                lldp_neighbors[interface_name].append({
                    'parent_interface'              : parent_interface,
                    'remote_chassis_id'             : chassis_id,
                    'remote_port'                   : port_id,
                    'remote_port_description'       : port_descr,
                    'remote_system_name'            : system_name,
                    'remote_system_description'     : system_descr,
                    'remote_system_capab'           : system_capabilities,
                    'remote_system_enable_capab'    :  enabled_capabilities
                })
            except Exception:
                continue # jump to next neighbor

        return lldp_neighbors

    def cli(self, commands = None):

        cli_output = dict()

        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            try:
                cli_output[unicode(command)] = unicode(__execute_show__(self.device.device, command, self.timeout))
            except TimeoutError:
                cli_output[unicode(command)] = 'Execution of command "{command}" took too long! Please adjust your params!'.format(
                    command = command
                )
                raise CommandTimeoutException(str(cli_output))
            except Exception as e:
                cli_output[unicode(command)] = 'Unable to execute command "{cmd}": {err}'.format(
                    cmd = command,
                    err = e
                )
                raise CommandErrorException(str(cli_output))

        return cli_output


    def get_bgp_config(self, group = '', neighbor = ''):

        bgp_config = {}

        # a helper
        def build_prefix_limit(af_table, limit, prefix_percent, prefix_timeout):
            prefix_limit = dict()
            inet  = False
            inet6 = False
            preifx_type = 'inet'
            if 'IPV4' in af_table:
                inet = True
            if 'IPv6' in af_table:
                inet6 = True
                preifx_type = 'inet6'
            if inet or inet6:
                prefix_limit = {
                    preifx_type: {
                        af_table[4:].lower(): {
                            'limit': limit,
                            'teardown': {
                                'threshold': prefix_percent,
                                'timeout'  : prefix_timeout
                            }
                        }
                    }
                }
            return prefix_limit

        # here begins actual method...

        rpc_command = '''
                <Get>
                    <Configuration>
                        <BGP>
                            <Instance>
                                <Naming>
                                    <InstanceName>
                                        default
                                    </InstanceName>
                                </Naming>
                            </Instance>
                        </BGP>
                    </Configuration>
                </Get>
        '''
        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        group    = group.lower()
        neighbor = neighbor.lower()

        if not group:
            neighbor = ''

        bgp_group_neighbors = {}
        for bgp_neighbor in result_tree.iter('Neighbor'):
            group_name     = self._find_txt(bgp_neighbor, 'NeighborGroupAddMember')
            peer           = self._find_txt(bgp_neighbor, 'Naming/NeighborAddress/IPV4Address') or self._find_txt(bgp_neighbor, 'Naming/NeighborAddress/IPV6Address')
            if neighbor and peer != neighbor:
                continue
            description    = unicode(self._find_txt(bgp_neighbor, 'Description'))
            peer_as        = int(self._find_txt(bgp_neighbor, 'RemoteAS/AS_YY', 0))
            local_as       = int(self._find_txt(bgp_neighbor, 'LocalAS/AS_YY', 0))
            af_table       = self._find_txt(bgp_neighbor, 'NeighborAFTable/NeighborAF/Naming/AFName')
            prefix_limit   = int(self._find_txt(bgp_neighbor, 'NeighborAFTable/NeighborAF/MaximumPrefixes/PrefixLimit', 0))
            prefix_percent = int(self._find_txt(bgp_neighbor, 'NeighborAFTable/NeighborAF/MaximumPrefixes/WarningPercentage', 0))
            prefix_timeout = int(self._find_txt(bgp_neighbor, 'NeighborAFTable/NeighborAF/MaximumPrefixes/RestartTime', 0))
            import_policy  = unicode(self._find_txt(bgp_neighbor, 'NeighborAFTable/NeighborAF/RoutePolicyIn'))
            export_policy  = unicode(self._find_txt(bgp_neighbor, 'NeighborAFTable/NeighborAF/RoutePolicyOut'))
            local_address  = unicode(self._find_txt(bgp_neighbor, 'LocalAddress/LocalIPAddress/IPV4Address') or self._find_txt(bgp_neighbor, 'LocalAddress/LocalIPAddress/IPV6Address'))
            password       = unicode(self._find_txt(bgp_neighbor, 'Password/Password/Password'))
            nhs            = False
            route_reflector= False
            if group_name not in bgp_group_neighbors.keys():
                bgp_group_neighbors[group_name] = dict()
            bgp_group_neighbors[group_name][peer] = {
                'description'           : description,
                'remote_as'               : peer_as,
                'prefix_limit'          : build_prefix_limit(af_table, prefix_limit, prefix_percent, prefix_timeout),
                'export_policy'         : export_policy,
                'import_policy'         : import_policy,
                'local_address'         : local_address,
                'local_as'              : local_as,
                'authentication_key'    : password,
                'nhs'                   : nhs,
                'route_reflector_client': route_reflector
            }
            if neighbor and peer == neighbor:
                break

        for bgp_group in result_tree.iter('NeighborGroup'):
            group_name    = self._find_txt(bgp_group, 'Naming/NeighborGroupName')
            if group and group != group_name:
                continue
            bgp_type = 'external' # by default external
            # must check
            description   = unicode(self._find_txt(bgp_group, 'Description'))
            import_policy = unicode(self._find_txt(bgp_group, 'NeighborGroupAFTable/NeighborGroupAF/RoutePolicyIn'))
            export_policy = unicode(self._find_txt(bgp_group, 'NeighborGroupAFTable/NeighborGroupAF/RoutePolicyOut'))
            multipath     = eval(self._find_txt(bgp_group, 'NeighborGroupAFTable/NeighborGroupAF/Multipath', 'false').title())

            peer_as       = int(self._find_txt(bgp_group, 'RemoteAS/AS_YY', 0))
            local_as      = int(self._find_txt(bgp_group, 'LocalAS/AS_YY', 0))
            multihop_ttl  = int(self._find_txt(bgp_group, 'EBGPMultihop/MaxHopCount', 0))
            local_address = unicode(self._find_txt(bgp_group, 'LocalAddress/LocalIPAddress/IPV4Address') or self._find_txt(bgp_group, 'LocalAddress/LocalIPAddress/IPV6Address'))
            af_table      = self._find_txt(bgp_group, 'NeighborAFTable/NeighborAF/Naming/AFName')
            prefix_limit  = int(self._find_txt(bgp_group, 'NeighborGroupAFTable/NeighborGroupAF/MaximumPrefixes/PrefixLimit', 0))
            prefix_percent= int(self._find_txt(bgp_group, 'NeighborGroupAFTable/NeighborGroupAF/MaximumPrefixes/WarningPercentage', 0))
            prefix_timeout= int(self._find_txt(bgp_group, 'NeighborGroupAFTable/NeighborGroupAF/MaximumPrefixes/RestartTime', 0))
            remove_private= True # is it specified in the XML?
            bgp_config[group_name] = {
                'apply_groups'      : [], # on IOS-XR will always be empty list!
                'description'       : description,
                'local_as'          : local_as,
                'type'              : unicode(bgp_type),
                'import_policy'     : import_policy,
                'export_policy'     : export_policy,
                'local_address'     : local_address,
                'multipath'         : multipath,
                'multihop_ttl'      : multihop_ttl,
                'remote_as'         : peer_as,
                'remove_private_as' : remove_private,
                'prefix_limit'      : build_prefix_limit(af_table, prefix_limit, prefix_percent, prefix_timeout),
                'neighbors'         : bgp_group_neighbors.get(group_name, {})
            }
            if group and group == group_name:
                break

        return bgp_config

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

        _BGP_STATE_ = {
            '0': 'Unknown',
            '1': 'Idle',
            '2': 'Connect',
            '3': 'OpenSent',
            '4': 'OpenConfirm',
            '5': 'Active',
            '6': 'Established'
        }

        routing_table = unicode(self._find_txt(result_tree, 'InstanceTable/Instance/Naming/InstanceName', 'default'))
        # if multi-VRF needed, create a loop through all instances
        for neighbor in result_tree.iter('Neighbor'):
            try:
                up                          = (self._find_txt(neighbor, 'ConnectionState') == 'BGP_ST_ESTAB')
                local_as                    = int(self._find_txt(neighbor, 'LocalAS', 0))
                remote_as                   = int(self._find_txt(neighbor, 'RemoteAS', 0))
                remote_address              = unicode(self._find_txt(neighbor, 'Naming/NeighborAddress/IPV4Address') \
                    or self._find_txt(neighbor, 'Naming/NeighborAddress/IPV6Address'))
                local_address_configured    = eval(self._find_txt(neighbor, 'IsLocalAddressConfigured', 'false').title())
                local_address               = unicode(self._find_txt(neighbor, 'ConnectionLocalAddress/IPV4Address') \
                    or self._find_txt(neighbor, 'ConnectionLocalAddress/IPV6Address'))
                local_port                  = int(self._find_txt(neighbor, 'ConnectionLocalPort'))
                remote_address              = unicode(self._find_txt(neighbor, 'ConnectionRemoteAddress/IPV4Address') \
                    or self._find_txt(neighbor, 'ConnectionRemoteAddress/IPV6Address'))
                remote_port                 = int(self._find_txt(neighbor, 'ConnectionRemotePort'))
                multihop                    = eval(self._find_txt(neighbor, 'IsExternalNeighborNotDirectlyConnected', 'false').title())
                remove_private_as           = eval(self._find_txt(neighbor, 'AFData/Entry/RemovePrivateASFromUpdates', 'false').title())
                multipath                   = eval(self._find_txt(neighbor, 'AFData/Entry/SelectiveMultipathEligible', 'false').title())
                import_policy               = unicode(self._find_txt(neighbor, 'AFData/Entry/RoutePolicyIn'))
                export_policy               = unicode(self._find_txt(neighbor, 'AFData/Entry/RoutePolicyOut'))
                input_messages              = int(self._find_txt(neighbor, 'MessgesReceived', 0))
                output_messages             = int(self._find_txt(neighbor, 'MessagesSent', 0))
                connection_up_count         = int(self._find_txt(neighbor, 'ConnectionUpCount', 0))
                connection_down_count       = int(self._find_txt(neighbor, 'ConnectionDownCount', 0))
                messages_queued_out         = int(self._find_txt(neighbor, 'MessagesQueuedOut', 0))
                connection_state            = unicode(self._find_txt(neighbor, 'ConnectionState').replace('BGP_ST_', '').title())
                if connection_state == u'Estab':
                    connection_state = u'Established'
                previous_connection_state   = unicode(_BGP_STATE_.get(self._find_txt(neighbor, 'PreviousConnectionState', '0')))
                active_prefix_count         = int(self._find_txt(neighbor, 'AFData/Entry/NumberOfBestpaths', 0))
                accepted_prefix_count       = int(self._find_txt(neighbor, 'AFData/Entry/PrefixesAccepted', 0))
                suppressed_prefix_count     = int(self._find_txt(neighbor, 'AFData/Entry/PrefixesDenied', 0))
                received_prefix_count       = accepted_prefix_count + suppressed_prefix_count # not quite right...
                advertise_prefix_count      = int(self._find_txt(neighbor, 'AFData/Entry/PrefixesAdvertised', 0))
                suppress_4byte_as           = eval(self._find_txt(neighbor, 'Suppress4ByteAs', 'false').title())
                local_as_prepend            = not eval(self._find_txt(neighbor, 'LocalASNoPrepend', 'false').title())
                holdtime                    = int(self._find_txt(neighbor, 'HoldTime', 0))
                configured_holdtime         = int(self._find_txt(neighbor, 'ConfiguredHoldTime', 0))
                keepalive                   = int(self._find_txt(neighbor, 'KeepAliveTime', 0))
                configured_keepalive        = int(self._find_txt(neighbor, 'ConfiguredKeepalive', 0))
                flap_count = connection_down_count / 2
                if up:
                    flap_count -= 1
                if remote_as not in bgp_neighbors.keys():
                    bgp_neighbors[remote_as] = list()
                bgp_neighbors[remote_as].append({
                    'up'                        : up,
                    'local_as'                  : local_as,
                    'remote_as'                 : remote_as,
                    'local_address'             : local_address,
                    'routing_table'             : routing_table,
                    'local_address_configured'  : local_address_configured,
                    'local_port'                : local_port,
                    'remote_address'            : remote_address,
                    'remote_port'               : remote_port,
                    'multihop'                  : multihop,
                    'multipath'                 : multipath,
                    'import_policy'             : import_policy,
                    'export_policy'             : export_policy,
                    'input_messages'            : input_messages,
                    'output_messages'           : output_messages,
                    'input_updates'             : 0,
                    'output_updates'            : 0,
                    'messages_queued_out'       : messages_queued_out,
                    'connection_state'          : connection_state,
                    'previous_connection_state' : previous_connection_state,
                    'last_event'                : u'',
                    'remove_private_as'         : remove_private_as,
                    'suppress_4byte_as'         : suppress_4byte_as,
                    'local_as_prepend'          : local_as_prepend,
                    'holdtime'                  : holdtime,
                    'configured_holdtime'       : configured_holdtime,
                    'keepalive'                 : keepalive,
                    'configured_keepalive'      : configured_keepalive,
                    'active_prefix_count'       : active_prefix_count,
                    'received_prefix_count'     : received_prefix_count,
                    'accepted_prefix_count'     : accepted_prefix_count,
                    'suppressed_prefix_count'   : suppressed_prefix_count,
                    'advertise_prefix_count'    : advertise_prefix_count,
                    'flap_count'                : flap_count
                })
            except Exception:
                continue

        return bgp_neighbors

    def get_arp_table(self):

        arp_table = list()

        rpc_command = '<Get><Operational><ARP></ARP></Operational></Get>'

        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        for arp_entry in result_tree.findall('.//EntryTable/Entry'):
            try:
                interface = unicode(arp_entry.find('.//InterfaceName').text)
                ip        = unicode(arp_entry.find('.//Address').text)
                age       = float(arp_entry.find('.//Age').text)
                mac_raw   = arp_entry.find('.//HardwareAddress').text
                mac_all   = mac_raw.replace('.', '').replace(':', '')
                mac_format= unicode(':'.join([mac_all[i:i+2] for i in range(12)[::2]]))

                arp_table.append(
                    {
                        'interface' : interface,
                        'mac'       : mac_format,
                        'ip'        : ip,
                        'age'       : age
                    }
                )
            except Exception:
                continue

        return arp_table

    def get_ntp_peers(self):

        ntp_stats = self.get_ntp_stats()
        return {ntp_peer.get('remote'): {} for ntp_peer in ntp_stats if ntp_peer.get('remote', '')}

    def get_ntp_stats(self):

        ntp_stats = list()

        rpc_command = '<Get><Operational><NTP><NodeTable></NodeTable></NTP></Operational></Get>'

        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        for node in result_tree.findall('.//NodeTable/Node/Associations/PeerSummaryInfo/Entry/PeerInfoCommon'):
            try:
                synchronized    = eval(self._find_txt(node, 'IsSysPeer', 'false').title())
                address         = unicode(self._find_txt(node, 'Address'))
                if address == 'DLRSC node':
                    continue
                referenceid     = unicode(self._find_txt(node, 'ReferenceID'))
                hostpoll        = int(self._find_txt(node, 'HostPoll', '0'))
                reachability    = int(self._find_txt(node, 'Reachability', '0'))
                stratum         = int(self._find_txt(node, 'Stratum', '0'))
                delay           = float(self._find_txt(node, 'Delay', '0.0'))
                offset          = float(self._find_txt(node, 'Offset', '0.0'))
                jitter          = float(self._find_txt(node, 'Dispersion', '0.0'))
                ntp_stats.append({
                    'remote'        : address,
                    'synchronized'  : synchronized,
                    'referenceid'   : referenceid,
                    'stratum'       : stratum,
                    'type'          : u'',
                    'when'          : u'',
                    'hostpoll'      : hostpoll,
                    'reachability'  : reachability,
                    'delay'         : delay,
                    'offset'        : offset,
                    'jitter'        : jitter
                })
            except Exception:
                continue

        return ntp_stats

    def get_interfaces_ip(self):

        interfaces_ip = dict()

        rpc_command_ipv4 = '<Get><Operational><IPV4Network></IPV4Network></Operational></Get>'

        ipv4_tree = ET.fromstring(self.device.make_rpc_call(rpc_command_ipv4))

        for interface in ipv4_tree.findall('.//InterfaceTable/Interface'):
            try:
                interface_name = unicode(interface.find('Naming/InterfaceName').text)
                primary_ip     = unicode(interface.find('VRFTable/VRF/Detail/PrimaryAddress').text)
                primary_prefix = int(interface.find('VRFTable/VRF/Detail/PrefixLength').text)
                if interface_name not in interfaces_ip.keys():
                    interfaces_ip[interface_name] = dict()
                if u'ipv4' not in interfaces_ip[interface_name].keys():
                    interfaces_ip[interface_name][u'ipv4'] = dict()
                if primary_ip not in interfaces_ip[interface_name].get(u'ipv4', {}).keys():
                    interfaces_ip[interface_name][u'ipv4'][primary_ip] = {
                        u'prefix_length': primary_prefix
                    }
                for secondary_address in interface.findall('VRFTable/VRF/Detail/SecondaryAddress/Entry'):
                    secondary_ip        = unicode(secondary_address.find('Address').text)
                    secondary_prefix    = int(secondary_address.find('PrefixLength').text)
                    if secondary_ip not in interfaces_ip[interface_name]:
                        interfaces_ip[interface_name][u'ipv4'][secondary_ip] = {
                            u'prefix_length': secondary_prefix
                        }
            except Exception:
                continue

        rpc_command_ipv6 = '<Get><Operational><IPV6Network></IPV6Network></Operational></Get>'

        ipv6_tree = ET.fromstring(self.device.make_rpc_call(rpc_command_ipv6))

        for interface in ipv6_tree.findall('.//InterfaceData/VRFTable/VRF/GlobalDetailTable/GlobalDetail'):
            interface_name = unicode(interface.find('Naming/InterfaceName').text)
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = dict()
            if u'ipv6' not in interfaces_ip[interface_name].keys():
                interfaces_ip[interface_name][u'ipv6'] = dict()
            for address in interface.findall('AddressList/Entry'):
                address_ip      = unicode(address.find('Address').text)
                address_prefix  = int(address.find('PrefixLength').text)
                if address_ip not in interfaces_ip[interface_name].get(u'ipv6', {}).keys():
                    interfaces_ip[interface_name][u'ipv6'][address_ip] = {
                        u'prefix_length': address_prefix
                    }

        return interfaces_ip

    def get_mac_address_table(self):

        mac_table = list()

        rpc_command = '<Get><Operational><L2VPNForwarding></L2VPNForwarding></Operational></Get>'

        result_tree = ET.fromstring(self.device.make_rpc_call(rpc_command))

        for mac_entry in result_tree.findall('.//L2FIBMACDetailTable/L2FIBMACDetail'):
            try:
                mac_raw     = mac_entry.find('Naming/Address').text
                # will throw error in case not found
                # and jump to next entry
                mac_str     = mac_raw.replace('.', '').replace(':', '')
                mac_format  = unicode(':'.join([ mac_str[i:i+2] for i in range(12)[::2] ]))
                vlan        = int(self._find_txt(mac_entry, 'Naming/Name', '').replace('vlan', ''))
                interface   = unicode(self._find_txt(mac_entry, 'Segment/AC/InterfaceHandle', u''))

                mac_table.append(
                    {
                        'mac'       : mac_format,
                        'interface' : interface,
                        'vlan'      : vlan,
                        'active'    : True,
                        'static'    : False,
                        'moves'     : 0,
                        'last_move' : 0.0
                    }
                )

            except Exception:
                continue

        return mac_table

    def get_route_to(self, destination = '', protocol = ''):

        routes = {}

        if not isinstance(destination, str):
            raise TypeError('Please specify a valid destination!')

        if not isinstance(protocol, str) or protocol.lower() not in ['static', 'bgp', 'isis']:
            raise TypeError("Protocol not supported: {protocol}.".format(
                protocol = protocol
            ))

        protocol = protocol.lower()
        dest_split = destination.split('/')
        network = dest_split[0]
        prefix_tag = ''
        if len(dest_split) == 2:
            prefix_tag = '''
                <PrefixLength>
                    {prefix_length}
                </PrefixLength>
            '''.format(prefix_length = dest_split[1])

        route_info_rpc_command = '''
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

        routes_tree = ET.fromstring(self.device.make_rpc_call(route_info_rpc_command))

        for route in routes_tree.iter('Route'):
            route_details = dict()
            try:
                address  = route.find('Prefix').text
                length   = route.find('PrefixLength').text
                distance = int(route.find('Distance').text)
                protocol = unicode(route.find('ProtocolName').text.upper())
                priority = int(route.find('Priority').text)
                age      = int(route.find('RouteAge').text)
                destination = unicode('{prefix}/{length}'.format(
                    prefix = address,
                    length = length
                ))
                if destination not in routes.keys():
                    routes[destination] = list()
            except Exception:
                continue

            route_details = {
                'current_active'    : False,
                'last_active'       : False,
                'age'               : age,
                'next_hop'          : u'',
                'protocol'          : protocol,
                'outgoing_interface': u'',
                'preference'        : priority,
                'selected_next_hop' : False,
                'inactive_reason'   : u'',
                'routing_table'     : u'default',
                'protocol_attributes': {}
            }

            # from BGP will try to get some more information
            if protocol.lower() == 'bgp':
                # looks like IOS-XR does not filter correctly
                # !IMPORTANT
                bgp_route_info_rpc_command = '''
                    <Get>
                        <Operational>
                            <BGP>
                                <Active>
                                    <DefaultVRF>
                                        <AFTable>
                                            <AF>
                                                <Naming>
                                                    <AFName>
                                                        IPv4Unicast
                                                    </AFName>
                                                </Naming>
                                                <PathTable>
                                                    <Path>
                                                        <Naming>
                                                            <Network>
                                                                <IPV4Address>
                                                                    {network}
                                                                </IPV4Address>
                                                                <IPV4PrefixLength>
                                                                    {prefix_len}
                                                                </IPV4PrefixLength>
                                                            </Network>
                                                        </Naming>
                                                    </Path>
                                                </PathTable>
                                            </AF>
                                        </AFTable>
                                    </DefaultVRF>
                                </Active>
                            </BGP>
                        </Operational>
                    </Get>
                '''.format(
                    network     = network,
                    prefix_len  = dest_split[-1]
                )
                bgp_route_tree = ET.fromstring(self.device.make_rpc_call(bgp_route_info_rpc_command))
                for bgp_path in bgp_route_tree.iter('Path'):
                    try:
                        best_path = eval(self._find_txt(bgp_path,'PathInformation/IsBestPath', 'false').title())
                        backup    = eval(self._find_txt(bgp_path,'PathInformation/IsPathBackup', 'false').title())
                        local_preference = int(
                            self._find_txt(bgp_path, 'AttributesAfterPolicyIn/CommonAttributes/LocalPreference', '0')
                        )
                        local_preference = int(
                            self._find_txt(bgp_path, 'AttributesAfterPolicyIn/CommonAttributes/LocalPreference', '0')
                        )
                        metric = int(
                            self._find_txt(bgp_path, 'AttributesAfterPolicyIn/CommonAttributes/Metric', '0')
                        )
                        remote_as       = int(
                           self._find_txt(bgp_path, 'AttributesAfterPolicyIn/CommonAttributes/NeighborAS', '0')
                        )
                        remote_address  = unicode(self._find_txt(bgp_path, 'PathInformation/NeighborAddress/IPV4Address') \
                            or self._find_txt(bgp_path, 'PathInformation/NeighborAddress/IPV6Address'))
                        as_path         = ' '.join(
                        [bgp_as.text for bgp_as in bgp_path.findall('AttributesAfterPolicyIn/CommonAttributes/NeighborAS/Entry')]
                        )
                        next_hop = unicode(self._find_txt(bgp_path, 'PathInformation/NextHop/IPV4Address') \
                            or self._find_txt(bgp_path, 'PathInformation/NextHop/IPV6Address') )
                    except Exception:
                        continue
                    single_route_details = route_details.copy()
                    single_route_details['current_active'] = best_path
                    single_route_details['next_hop'] = next_hop
                    single_route_details['protocol_attributes'] = {
                        'local_preference'  : local_preference,
                        'as_path'           : as_path,
                        'remote_as'         : remote_as,
                        'remote_address'    : remote_address
                    }
                    routes[destination].append(single_route_details)

            else:
                first_route = True
                for route_entry in route.findall('RoutePath/Entry'):
                    # get all possible entries
                    try:
                        next_hop  = unicode(route_entry.find('Address').text)
                    except Exception:
                        continue
                    single_route_details = route_details.copy()
                    single_route_details.update({
                        'current_active': first_route,
                        'next_hop'      : next_hop
                    })
                    routes[destination].append(single_route_details)
                    first_route = False

        return routes

    def get_snmp_information(self):

        snmp_information = dict()

        snmp_rpc_command = '<Get><Configuration><SNMP></SNMP></Configuration></Get>'

        snmp_result_tree = ET.fromstring(self.device.make_rpc_call(snmp_rpc_command))

        _PRIVILEGE_MODE_MAP_ = {
            'ReadOnly': u'ro',
            'ReadWrite': u'rw'
        }

        snmp_information = {
            'chassis_id': unicode(self._find_txt(snmp_result_tree, './/ChassisID')),
            'contact': unicode(self._find_txt(snmp_result_tree, './/Contact')),
            'location': unicode(self._find_txt(snmp_result_tree, './/Location')),
            'community': {}
        }

        for community in snmp_result_tree.iter('DefaultCommunity'):
            name = unicode(self._find_txt(community, 'Naming/CommunityName'))
            privilege = self._find_txt(community, 'Priviledge')
            acl = unicode(self._find_txt(community, 'AccessList'))
            snmp_information['community'][name] = {
                'mode': _PRIVILEGE_MODE_MAP_.get(privilege, u''),
                'acl' : acl
            }

        return snmp_information


    def get_probes_config(self):

        sla_config = dict()

        _PROBE_TYPE_XML_TAG_MAP_ = {
            'ICMPEcho': u'icmp-ping',
            'UDPEcho': u'udp-ping',
            'ICMPJitter': u'icmp-ping-timestamp',
            'UDPJitter': u'udp-ping-timestamp'
        }

        sla_config_rpc_command = '<Get><Configuration><IPSLA></IPSLA></Configuration></Get>'

        sla_config_result_tree = ET.fromstring(self.device.make_rpc_call(sla_config_rpc_command))

        for probe in sla_config_result_tree.findall('.//Definition'):
            probe_name = unicode(self._find_txt(probe, 'Naming/OperationID'))
            operation_type = probe.find('OperationType').getchildren()[0].tag
            probe_type = _PROBE_TYPE_XML_TAG_MAP_.get(operation_type, u'')
            operation = probe.find('OperationType').find(operation_type)
            test_name =  unicode(self._find_txt(operation, 'Tag'))
            source = unicode(self._find_txt(operation, 'SourceAddress'))
            target = unicode(self._find_txt(operation, 'DestAddress'))
            test_interval = int(self._find_txt(operation, 'Frequency', '0'))  # defined in seconds
            probe_count = int(self._find_txt(operation, 'History/Buckets', '0'))
            if probe_name not in sla_config.keys():
                sla_config[probe_name] = dict()
            if test_name not in sla_config[probe_name]:
                sla_config[probe_name][test_name] = dict()
            sla_config[probe_name][test_name] = {
                'probe_type': probe_type,
                'source': source,
                'target': target,
                'probe_count': probe_count,
                'test_interval': test_interval
            }

        return sla_config


    def get_probes_results(self):

        sla_results = dict()

        _PROBE_TYPE_XML_TAG_MAP_ = {
            'ICMPEcho': u'icmp-ping',
            'UDPEcho': u'udp-ping',
            'ICMPJitter': u'icmp-ping-timestamp',
            'UDPJitter': u'udp-ping-timestamp'
        }

        sla_results_rpc_command = '<Get><Operational><IPSLA></IPSLA></Operational></Get>'

        sla_results_tree = ET.fromstring(self.device.make_rpc_call(sla_results_rpc_command))

        probes_config = self.get_probes_config()  # need to retrieve also the configuration
        # source and tag/test_name not provided

        for probe in sla_results_tree.findall('.//Operation'):
            probe_name = unicode(self._find_txt(probe, 'Naming/OperationID'))
            test_name = probes_config.get(probe_name).keys()[0]
            target = unicode(self._find_txt(probe, 'History/Target/LifeTable/Life/BucketTable/Bucket[0]/TargetAddress/IPv4AddressTarget'))
            source = probes_config.get(probe_name).get(test_name, {}).get('source', '')
            probe_type = _PROBE_TYPE_XML_TAG_MAP_.get(self._find_txt(probe, 'Statistics/Latest/Target/SpecificStats/op_type'))
            test_interval = int(self._find_txt(probe, 'Common/OperationalState/Frequency')) * 1e-3  # here f is defined in miliseconds
            probe_count = probes_config.get(probe_name).get(test_name, {}).get('probe_count', 0)
            # rtt = float(self._find_txt(probe, 'Statistics/Aggregated/HourTable/Hour/Distributed/Target/DistributionIntervalTable/DistributionInterval/CommonStats/ResponseTime'))
            response_times = probe.findall('History/Target/LifeTable/Life[last()]/BucketTable/Bucket/ResponseTime')
            response_times = [int(self._find_txt(response_time, '.', '0')) for response_time in response_times]
            rtt = 0.0
            if len(response_times):
                rtt = sum(response_times, 0.0)/len(response_times)
            return_codes = probe.findall('History/Target/LifeTable/Life[last()]/BucketTable/Bucket/ReturnCode')
            return_codes = [self._find_txt(return_code, '.') for return_code in return_codes]
            last_test_loss = 0.0
            if len(return_codes):
                last_test_loss = int(100*(1-return_codes.count('ipslaRetCodeOK')/float(len(return_codes))))
            rms = float(self._find_txt(probe, 'Statistics/Aggregated/HourTable/Hour/Distributed/Target/DistributionIntervalTable/DistributionInterval/CommonStats/Sum2ResponseTime'))
            global_test_updates = float(self._find_txt(probe, 'Statistics/Aggregated/HourTable/Hour/Distributed/Target/DistributionIntervalTable/DistributionInterval/CommonStats/UpdateCount'))
            jitter = rtt-(rms/global_test_updates)**0.5
            # jitter = max(rtt - max(response_times), rtt - min(response_times))
            current_test_min_delay = 0.0  # no stats for undergoing test :(
            current_test_max_delay = 0.0
            current_test_avg_delay = 0.0
            last_test_min_delay = float(self._find_txt(probe, 'Statistics/Latest/Target/CommonStats/MinResponseTime'))
            last_test_max_delay = float(self._find_txt(probe, 'Statistics/Latest/Target/CommonStats/MaxResponseTime'))
            last_test_sum_delay = float(self._find_txt(probe, 'Statistics/Latest/Target/CommonStats/SumResponseTime'))
            last_test_updates = float(self._find_txt(probe, 'Statistics/Latest/Target/CommonStats/UpdateCount'))
            last_test_avg_delay = 0.0
            if last_test_updates:
                last_test_avg_delay = last_test_sum_delay/last_test_updates
            global_test_min_delay = float(self._find_txt(probe, 'Statistics/Aggregated/HourTable/Hour/Distributed/Target/DistributionIntervalTable/DistributionInterval/CommonStats/MinResponseTime'))
            global_test_max_delay = float(self._find_txt(probe, 'Statistics/Aggregated/HourTable/Hour/Distributed/Target/DistributionIntervalTable/DistributionInterval/CommonStats/MaxResponseTime'))
            global_test_sum_delay = float(self._find_txt(probe, 'Statistics/Aggregated/HourTable/Hour/Distributed/Target/DistributionIntervalTable/DistributionInterval/CommonStats/SumResponseTime'))
            global_test_avg_delay = 0.0
            if global_test_updates:
                global_test_avg_delay = global_test_sum_delay/global_test_updates
            if probe_name not in sla_results.keys():
                sla_results[probe_name] = dict()
            sla_results[probe_name][test_name] = {
                'target': target,
                'source': source,
                'probe_type': probe_type,
                'probe_count': probe_count,
                'rtt': rtt,
                'round_trip_jitter': jitter,
                'last_test_loss': last_test_loss,
                'current_test_min_delay': current_test_min_delay,
                'current_test_max_delay': current_test_max_delay,
                'current_test_avg_delay': current_test_avg_delay,
                'last_test_min_delay': last_test_min_delay,
                'last_test_max_delay': last_test_max_delay,
                'last_test_avg_delay': last_test_avg_delay,
                'global_test_min_delay': global_test_min_delay,
                'global_test_max_delay': global_test_max_delay,
                'global_test_avg_delay': global_test_avg_delay
            }

        return sla_results

    def traceroute(self, destination, source='', ttl=0, timeout=0):

        traceroute_result = dict()

        ipv = 4
        try:
            ipv = IPAddress(destination).version
        except AddrFormatError:
            return {'error': 'Wrong destination IP Address!'}

        source_tag = ''
        ttl_tag = ''
        timeout_tag = ''
        if source:
            source_tag = '<Source>{source}</Source>'.format(source = source)
        if ttl:
            ttl_tag = '<MaxTTL>{maxttl}</MaxTTL>'.format(maxttl = ttl)
        if timeout:
            timout_tag = '<Timeout>{timeout}</Timeout>'.format(timeout = timeout)
        else:
            timeout = 5  # seconds

        traceroute_rpc_command = '''
            <Set>
                <Action>
                    <TraceRoute>
                        <IPV{version}>
                            <Destination>
                                {destination}
                            </Destination>
                            {source_tag}
                            {ttl_tag}
                            {timeout_tag}
                        </IPV{version}>
                    </TraceRoute>
                </Action>
            </Set>
        '''.format(
            version=ipv,
            destination=destination,
            source_tag=source_tag,
            ttl_tag=ttl_tag,
            timeout_tag=timeout_tag
        )

        xml_tree_txt = self.device.make_rpc_call(traceroute_rpc_command)
        traceroute_tree = ET.fromstring(xml_tree_txt)

        results_tree = traceroute_tree.find('.//Results')
        results_error = self._find_txt(results_tree, 'Error')

        if results_error:
            return {'error': results_error}

        if results_tree is None or not len(results_tree):
            return {'error': 'Device returned empty results.'}

        traceroute_result['success'] = {}

        last_hop_index = 1
        last_probe_index = 1
        last_probe_ip_address = '*'
        last_probe_host_name = ''
        last_hop_dict = {'probes': {}}

        for thanks_cisco in results_tree.getchildren():
            tag_name = thanks_cisco.tag
            tag_value = thanks_cisco.text
            if tag_name == 'HopIndex':
                new_hop_index = int(self._find_txt(thanks_cisco, '.', '-1'))
                if last_hop_index and last_hop_index != new_hop_index:
                    traceroute_result['success'][last_hop_index] = copy.deepcopy(last_hop_dict)
                    last_hop_dict = {'probes': {}}
                    last_probe_ip_address = '*'
                    last_probe_host_name = ''
                last_hop_index = new_hop_index
                continue
            tag_value = unicode(self._find_txt(thanks_cisco, '.', ''))
            if tag_name == 'ProbeIndex':
                last_probe_index = self._convert(int, tag_value, 0) + 1
                if last_probe_index not in last_hop_dict.get('probes').keys():
                    last_hop_dict['probes'][last_probe_index] = {}
                if not last_probe_host_name:
                    last_probe_host_name = last_probe_ip_address
                last_hop_dict['probes'][last_probe_index] = {
                    'ip_address': unicode(last_probe_ip_address),
                    'host_name': unicode(last_probe_host_name),
                    'rtt': timeout * 1000.0
                }
                continue
            if tag_name == 'HopAddress':
                last_probe_ip_address = tag_value
                continue
            if tag_name == 'HopHostName':
                last_probe_host_name = tag_value
                continue
            if tag_name == 'DeltaTime':
                last_hop_dict['probes'][last_probe_index]['rtt'] = self._convert(float, tag_value, 0.0)
                continue

        if last_hop_index:
            traceroute_result['success'][last_hop_index] = last_hop_dict

        return traceroute_result

    def get_users(self):

        users = dict()

        _CISCO_GROUP_TO_CISCO_PRIVILEGE_MAP = {
            'root-system': 15,
            'operator': 5,
            'sysadmin': 1,
            'serviceadmin': 1,
            'root-lr': 15
        }

        _DEFAULT_USER_DETAILS = {
            'level': 0,
            'password': '',
            'sshkeys': []
        }

        users_xml_req = '<Get><Configuration><AAA></AAA></Configuration></Get>'

        users_xml_reply = ET.fromstring(self.device.make_rpc_call(users_xml_req))

        for user_entry in users_xml_reply.findall('.//Username'):
            username = unicode(self._find_txt(user_entry, 'Naming/Name'))
            group = self._find_txt(user_entry, 'UsergroupsUnderUsername/UsergroupUnderUsername/Naming/Name', '')
            level = _CISCO_GROUP_TO_CISCO_PRIVILEGE_MAP.get(group, 0)
            password = self._find_txt(user_entry, 'Password/Password')
            user_details = _DEFAULT_USER_DETAILS.copy()
            user_details.update({
                'level': level,
                'password': password
            })
            users[username] = user_details

        return users
