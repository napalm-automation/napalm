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

import re

from utils import junos_views
from base import NetworkDriver

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import ConfigLoadError
from exceptions import ReplaceConfigException, MergeConfigException



from utils import string_parsers


class JunOSDriver(NetworkDriver):

    def __init__(self, hostname, username, password, timeout=60):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.device = Device(hostname, user=username, password=password)
        self.config_replace = False

    def open(self):
        self.device.open()
        self.device.timeout = self.timeout
        self.device.bind(cu=Config)
        self.device.cu.lock()

    def close(self):
        self.device.cu.unlock()
        self.device.close()

    def _load_candidate(self, filename, config, overwrite):
        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()

        try:
            self.device.cu.load(configuration, format='text', overwrite=overwrite)
        except ConfigLoadError as e:
            if self.config_replace:
                raise ReplaceConfigException(e.message)
            else:
                raise MergeConfigException(e.message)

    def load_replace_candidate(self, filename=None, config=None):
        self.config_replace = True
        self._load_candidate(filename, config, True)

    def load_merge_candidate(self, filename=None, config=None):
        self.config_replace = False
        self._load_candidate(filename, config, False)

    def compare_config(self):
        diff = self.device.cu.diff()

        if diff is None:
            return ''
        else:
            return diff.strip()

    def commit_config(self):
        self.device.cu.commit()

    def discard_config(self):
        self.device.cu.rollback(rb_id=0)

    def rollback(self):
        self.device.cu.rollback(rb_id=1)
        self.commit_config()

    def get_facts(self):

        output = self.device.facts

        uptime = 0
        if 'RE0' in output:
            uptime = output['RE0']['up_time']

        interfaces = junos_views.junos_iface_table(self.device)
        interfaces.get()
        interface_list = interfaces.keys()

        return {
            'vendor': u'Juniper',
            'model': unicode(output['model']),
            'serial_number': unicode(output['serialnumber']),
            'os_version': unicode(output['version']),
            'hostname': unicode(output['hostname']),
            'fqdn': unicode(output['fqdn']),
            'uptime': string_parsers.convert_uptime_string_seconds(uptime),
            'interface_list': interface_list
        }

    def get_interfaces(self):

        # init result dict
        result = {}

        interfaces = junos_views.junos_iface_table(self.device)
        interfaces.get()

        # convert all the tuples to our pre-defined dict structure
        for iface in interfaces.keys():
            result[iface] = {
                'is_up': interfaces[iface]['is_up'],
                'is_enabled': interfaces[iface]['is_enabled'],
                'description': interfaces[iface]['description'] or u'',
                'last_flapped': interfaces[iface]['last_flapped'] or -1,
                'mac_address': unicode(interfaces[iface]['mac_address'])
            }
            result[iface]['last_flapped'] = float(result[iface]['last_flapped'])

            match = re.search(r'\d+', interfaces[iface]['speed'] or '')
            if match is not None:
                result[iface]['speed'] = int(match.group(0))
            else:
                result[iface]['speed'] = -1

        return result

    def get_interfaces_counters(self):
        query = junos_views.junos_iface_counter_table(self.device)
        query.get()
        interface_counters = dict()
        for interface, counters in query.items():
            interface_counters[interface] = {k: v or -1 for k, v in counters}
        return interface_counters

    def get_environment(self):
        environment = junos_views.junos_enviroment_table(self.device)
        routing_engine = junos_views.junos_routing_engine_table(self.device)
        temperature_thresholds = junos_views.junos_temperature_thresholds(self.device)
        environment.get()
        routing_engine.get()
        temperature_thresholds.get()
        environment_data = dict()

        for sensor_object, object_data in environment.items():
            structured_object_data = {k: v for k, v in object_data}

            if structured_object_data['class'] == 'Power':
                # Create a dict for the 'power' key
                try:
                    environment_data['power'][sensor_object] = dict()
                except KeyError:
                    environment_data['power'] = dict()
                    environment_data['power'][sensor_object] = dict()

                # Set these values to -1, because Junos does not provide them
                environment_data['power'][sensor_object]['capacity'] = -1.0
                environment_data['power'][sensor_object]['output'] = -1.0

            if structured_object_data['class'] == 'Fans':
                # Create a dict for the 'fans' key
                try:
                    environment_data['fans'][sensor_object] = dict()
                except KeyError:
                    environment_data['fans'] = dict()
                    environment_data['fans'][sensor_object] = dict()

            if structured_object_data['status'] == 'OK' and structured_object_data['class'] == 'Power':
                # If status is Failed, Absent or Testing, set status to False.
                environment_data['power'][sensor_object]['status'] = True

            elif structured_object_data['status'] != 'OK' and structured_object_data['class'] == 'Power':
                environment_data['power'][sensor_object]['status'] = False

            elif structured_object_data['status'] == 'OK' and structured_object_data['class'] == 'Fans':
                # If status is Failed, Absent or Testing, set status to False.
                environment_data['fans'][sensor_object]['status'] = True

            elif structured_object_data['status'] != 'OK' and structured_object_data['class'] == 'Fans':
                environment_data['fans'][sensor_object]['status'] = False

            for temperature_object, temperature_data in temperature_thresholds.items():
                structured_temperature_data = {k: v for k, v in temperature_data}
                if structured_object_data['class'] == 'Temp':
                    # Create a dict for the 'temperature' key
                    try:
                        environment_data['temperature'][sensor_object] = dict()
                    except KeyError:
                        environment_data['temperature'] = dict()
                        environment_data['temperature'][sensor_object] = dict()

                    environment_data['temperature'][sensor_object]['temperature'] = float(structured_object_data['temperature'])
                    # Set a default value (False) to the key is_critical and is_alert
                    environment_data['temperature'][sensor_object]['is_alert'] = False
                    environment_data['temperature'][sensor_object]['is_critical'] = False
                    # Check if the working temperature is equal to or higher than alerting threshold
                    if structured_temperature_data['red-alarm'] <= structured_object_data['temperature']:
                        environment_data['temperature'][sensor_object]['is_critical'] = True
                        environment_data['temperature'][sensor_object]['is_alert'] = True
                    elif structured_temperature_data['yellow-alarm'] <= structured_object_data['temperature']:
                        environment_data['temperature'][sensor_object]['is_alert'] = True

        for routing_engine_object, routing_engine_data in routing_engine.items():
            structured_routing_engine_data = {k: v for k, v in routing_engine_data}
            # Create dicts for 'cpu' and 'memory'.
            try:
                environment_data['cpu'] = dict()
                environment_data['cpu'][routing_engine_object] = dict()
                environment_data['memory'] = dict()
            except KeyError:
                environment_data['cpu'] = dict()
                environment_data['cpu'][routing_engine_object] = dict()
                environment_data['memory'] = dict()
            # Calculate the CPU usage by using the CPU idle value.
            environment_data['cpu'][routing_engine_object]['%usage'] = 100 - structured_routing_engine_data['cpu-idle']
            environment_data['memory']['available_ram'] = structured_routing_engine_data['memory-dram-size']
            # Junos gives us RAM in %, so calculation has to be made.
            # Sadly, bacause of this, results are not 100% accurate to the truth.
            environment_data['memory']['used_ram'] = (structured_routing_engine_data['memory-dram-size'] / 100 * structured_routing_engine_data['memory-buffer-utilization'])

        return environment_data

    # def get_bgp_neighbors(self):
    #
    #     # init result dict
    #     result = {}
    #
    #     instances = junos_views.junos_route_instance_table(self.device)
    #     instances.get()
    #
    #     for vrf in instances.keys():
    #         if not vrf.startswith('__'):
    #
    #             # init result dict for this vrf
    #             result[vrf] = {
    #                 'peers': {},
    #                 'router_id': None,
    #                 'local_as': None,
    #             }
    #
    #             # fetch sessions for vrf
    #             bgp = junos_views.junos_bgp_table(self.device)
    #             bgp.get(instance=vrf)
    #
    #             # assemble result dict
    #             bgp_result = {}
    #             [bgp_result.update({neigh:dict(bgp[neigh])}) for neigh in bgp.keys()]
    #             result[vrf]['peers'] = bgp_result
    #
    #     return result

    @staticmethod
    def _get_address_family(table):
        """
        Function to derive address family from a junos table name
        :params table: The name of the routing table
        :returns: address family
        """
        address_family_mapping = {
            'inet': 'ipv4',
            'inet6': 'ipv6'
        }
        family = table.split('.')[-2]
        return address_family_mapping[family]

    def get_bgp_neighbors(self):
        # Setup the views
        instances = junos_views.junos_route_instance_table(self.device)
        uptime_table = junos_views.junos_bgp_uptime_table(self.device)
        bgp_neigbors = junos_views.junos_bgp_table(self.device)
        # prepare data
        bgp_neigbor_data = dict()
        for instance, instance_data in instances.get().items():
            if instance.startswith('__'):
                # junos internal instances
                continue

            instance_name = "global" if instance == 'master' else instance

            bgp_neigbor_data[instance_name] = dict(peers=dict())
            for neighbor, neighbor_data in bgp_neigbors.get(instance=instance).items():
                structured_neighbor_data = {k: v for k, v in neighbor_data}
                peer = neighbor.split('+')[0]
                bgp_neigbor_data[instance_name]['peers'][peer] = dict()
                for key in ['local_as', 'remote_as', 'is_up', 'is_enabled', 'description', 'remote_id']:
                    bgp_neigbor_data[instance_name]['peers'][peer][key] = structured_neighbor_data[key] or u''
                if 'router_id' not in bgp_neigbor_data[instance_name].keys():
                    # we only need to set this once
                    bgp_neigbor_data[instance_name]['router_id'] = structured_neighbor_data['local_id']
                if structured_neighbor_data['is_up'] is False:
                    # if the session is down there is no table data to parse
                    continue
                elif isinstance(structured_neighbor_data['tables'], list):
                    for idx, table in enumerate(structured_neighbor_data['tables']):
                        family = self._get_address_family(table)
                        bgp_neigbor_data[instance_name]['peers'][peer][family] = dict()
                        for metric in ['received_prefixes', 'accepted_prefixes', 'sent_prefixes']:
                            bgp_neigbor_data[instance_name]['peers'][peer][family][metric] = structured_neighbor_data[metric][idx]
                else:
                    family = self._get_address_family(structured_neighbor_data['tables'])
                    bgp_neigbor_data[instance_name]['peers'][peer][family] = dict()
                    bgp_neigbor_data[instance_name]['peers'][peer][family]['received_prefixes'] = structured_neighbor_data['received_prefixes']
                    bgp_neigbor_data[instance_name]['peers'][peer][family]['accepted_prefixes'] = structured_neighbor_data['accepted_prefixes']
                    bgp_neigbor_data[instance_name]['peers'][peer][family]['sent_prefixes'] = structured_neighbor_data['sent_prefixes']
            for neighbor, uptime in uptime_table.get(instance=instance).items():
                bgp_neigbor_data[instance_name]['peers'][neighbor]['uptime'] = uptime[0][1]
        return bgp_neigbor_data

    def get_lldp_neighbors(self):
        lldp = junos_views.junos_lldp_table(self.device)
        lldp.get()

        result = lldp.items()

        neighbors = dict()
        for neigh in result:
            if neigh[0] not in neighbors.keys():
                neighbors[neigh[0]] = list()
            neighbors[neigh[0]].append({x[0]: unicode(x[1]) for x in neigh[1]})

        return neighbors
