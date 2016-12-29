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

"""Driver for JunOS devices."""

from __future__ import unicode_literals

# import stdlib
import re
import collections
from copy import deepcopy

# import third party lib
from lxml.builder import E

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import RpcError
from jnpr.junos.exception import ConfigLoadError
from jnpr.junos.exception import RpcTimeoutError
from jnpr.junos.exception import ConnectTimeoutError

# import NAPALM Base
import napalm_base.helpers
from napalm_base.base import NetworkDriver
from napalm_base.utils import string_parsers
from napalm_base.utils import py23_compat
import napalm_junos.constants as C
from napalm_base.exceptions import ConnectionException
from napalm_base.exceptions import MergeConfigException
from napalm_base.exceptions import CommandErrorException
from napalm_base.exceptions import ReplaceConfigException
from napalm_base.exceptions import CommandTimeoutException

# import local modules
from napalm_junos.utils import junos_views


class JunOSDriver(NetworkDriver):
    """JunOSDriver class - inherits NetworkDriver from napalm_base."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialise JunOS driver.

        Optional args:
            * port (int): custom port
            * config_lock (True/False): lock configuration DB after the connection is established.
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.config_replace = False
        self.locked = False

        if optional_args is None:
            optional_args = {}
        self.port = optional_args.get('port', 22)
        self.config_lock = optional_args.get('config_lock', True)

        self.device = Device(hostname, user=username, password=password, port=self.port)

    def open(self):
        """Open the connection wit the device."""
        try:
            self.device.open()
        except ConnectTimeoutError as cte:
            raise ConnectionException(cte.message)
        self.device.timeout = self.timeout
        if hasattr(self.device, "cu"):
            # make sure to remove the cu attr from previous session
            # ValueError: requested attribute name cu already exists
            del self.device.cu
        self.device.bind(cu=Config)
        if self.config_lock:
            self._lock()

    def close(self):
        """Close the connection."""
        if self.config_lock:
            self._unlock()
        self.device.close()

    def _lock(self):
        """Lock the config DB."""
        if not self.locked:
            self.device.cu.lock()
            self.locked = True

    def _unlock(self):
        """Unlock the config DB."""
        if self.locked:
            self.device.cu.unlock()
            self.locked = False

    def is_alive(self):
        # evaluate the state of the underlying SSH connection
        # and also the NETCONF status from PyEZ
        return {
            'is_alive': self.device._conn._session.transport.is_active() and self.device.connected
        }

    def _load_candidate(self, filename, config, overwrite):
        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()

        if not self.config_lock:
            # if not locked during connection time
            # will try to lock it if not already aquired
            self._lock()
            # and the device will be locked till first commit/rollback

        try:
            self.device.cu.load(configuration, format='text', overwrite=overwrite)
        except ConfigLoadError as e:
            if self.config_replace:
                raise ReplaceConfigException(e.message)
            else:
                raise MergeConfigException(e.message)

    def load_replace_candidate(self, filename=None, config=None):
        """Open the candidate config and merge."""
        self.config_replace = True
        self._load_candidate(filename, config, True)

    def load_merge_candidate(self, filename=None, config=None):
        """Open the candidate config and replace."""
        self.config_replace = False
        self._load_candidate(filename, config, False)

    def compare_config(self):
        """Compare candidate config with running."""
        diff = self.device.cu.diff()

        if diff is None:
            return ''
        else:
            return diff.strip()

    def commit_config(self):
        """Commit configuration."""
        self.device.cu.commit()
        if not self.config_lock:
            self._unlock()

    def discard_config(self):
        """Discard changes (rollback 0)."""
        self.device.cu.rollback(rb_id=0)
        if not self.config_lock:
            self._unlock()

    def rollback(self):
        """Rollback to previous commit."""
        self.device.cu.rollback(rb_id=1)
        self.commit_config()

    def get_facts(self):
        """Return facts of the device."""
        output = self.device.facts

        uptime = '0'
        if 'RE0' in output:
            uptime = output['RE0']['up_time']

        interfaces = junos_views.junos_iface_table(self.device)
        interfaces.get()
        interface_list = interfaces.keys()

        return {
            'vendor': u'Juniper',
            'model': py23_compat.text_type(output['model']),
            'serial_number': py23_compat.text_type(output['serialnumber']),
            'os_version': py23_compat.text_type(output['version']),
            'hostname': py23_compat.text_type(output['hostname']),
            'fqdn': py23_compat.text_type(output['fqdn']),
            'uptime': string_parsers.convert_uptime_string_seconds(uptime),
            'interface_list': interface_list
        }

    def get_interfaces(self):
        """Return interfaces details."""
        result = {}

        interfaces = junos_views.junos_iface_table(self.device)
        interfaces.get()

        # convert all the tuples to our pre-defined dict structure
        for iface in interfaces.keys():
            result[iface] = {
                'is_up': interfaces[iface]['is_up'],
                'is_enabled': interfaces[iface]['is_enabled'],
                'description': (interfaces[iface]['description'] or u''),
                'last_flapped': float((interfaces[iface]['last_flapped'] or -1)),
                'mac_address': napalm_base.helpers.convert(
                    napalm_base.helpers.mac,
                    interfaces[iface]['mac_address'],
                    py23_compat.text_type(interfaces[iface]['mac_address'])),
                'speed': -1
            }
            # result[iface]['last_flapped'] = float(result[iface]['last_flapped'])

            match = re.search(r'(\d+)(\w*)', interfaces[iface]['speed'] or u'')
            if match is None:
                continue
            speed_value = napalm_base.helpers.convert(int, match.group(1), -1)
            if speed_value == -1:
                continue
            speed_unit = match.group(2)
            if speed_unit.lower() == 'gbps':
                speed_value *= 1000
            result[iface]['speed'] = speed_value

        return result

    def get_interfaces_counters(self):
        """Return interfaces counters."""
        query = junos_views.junos_iface_counter_table(self.device)
        query.get()
        interface_counters = {}
        for interface, counters in query.items():
            interface_counters[interface] = {k: v if v is not None else -1 for k, v in counters}
        return interface_counters

    def get_environment(self):
        """Return environment details."""
        environment = junos_views.junos_enviroment_table(self.device)
        routing_engine = junos_views.junos_routing_engine_table(self.device)
        temperature_thresholds = junos_views.junos_temperature_thresholds(self.device)
        environment.get()
        routing_engine.get()
        temperature_thresholds.get()
        environment_data = {}

        for sensor_object, object_data in environment.items():
            structured_object_data = {k: v for k, v in object_data}

            if structured_object_data['class'] == 'Power':
                # Create a dict for the 'power' key
                try:
                    environment_data['power'][sensor_object] = {}
                except KeyError:
                    environment_data['power'] = {}
                    environment_data['power'][sensor_object] = {}

                # Set these values to -1, because Junos does not provide them
                environment_data['power'][sensor_object]['capacity'] = -1.0
                environment_data['power'][sensor_object]['output'] = -1.0

            if structured_object_data['class'] == 'Fans':
                # Create a dict for the 'fans' key
                try:
                    environment_data['fans'][sensor_object] = {}
                except KeyError:
                    environment_data['fans'] = {}
                    environment_data['fans'][sensor_object] = {}

            status = structured_object_data['status']
            env_class = structured_object_data['class']
            if (status == 'OK' and env_class == 'Power'):
                # If status is Failed, Absent or Testing, set status to False.
                environment_data['power'][sensor_object]['status'] = True

            elif (status != 'OK' and env_class == 'Power'):
                environment_data['power'][sensor_object]['status'] = False

            elif (status == 'OK' and env_class == 'Fans'):
                # If status is Failed, Absent or Testing, set status to False.
                environment_data['fans'][sensor_object]['status'] = True

            elif (status != 'OK' and env_class == 'Fans'):
                environment_data['fans'][sensor_object]['status'] = False

            for temperature_object, temperature_data in temperature_thresholds.items():
                structured_temperature_data = {k: v for k, v in temperature_data}
                if structured_object_data['class'] == 'Temp':
                    # Create a dict for the 'temperature' key
                    try:
                        environment_data['temperature'][sensor_object] = {}
                    except KeyError:
                        environment_data['temperature'] = {}
                        environment_data['temperature'][sensor_object] = {}
                    # Check we have a temperature field in this class (See #66)
                    if structured_object_data['temperature']:
                        environment_data['temperature'][sensor_object]['temperature'] = \
                            float(structured_object_data['temperature'])
                    # Set a default value (False) to the key is_critical and is_alert
                    environment_data['temperature'][sensor_object]['is_alert'] = False
                    environment_data['temperature'][sensor_object]['is_critical'] = False
                    # Check if the working temperature is equal to or higher than alerting threshold
                    temp = structured_object_data['temperature']
                    if structured_temperature_data['red-alarm'] <= temp:
                        environment_data['temperature'][sensor_object]['is_critical'] = True
                        environment_data['temperature'][sensor_object]['is_alert'] = True
                    elif structured_temperature_data['yellow-alarm'] <= temp:
                        environment_data['temperature'][sensor_object]['is_alert'] = True

        for routing_engine_object, routing_engine_data in routing_engine.items():
            structured_routing_engine_data = {k: v for k, v in routing_engine_data}
            # Create dicts for 'cpu' and 'memory'.
            try:
                environment_data['cpu'][routing_engine_object] = {}
                environment_data['memory'] = {}
            except KeyError:
                environment_data['cpu'] = {}
                environment_data['cpu'][routing_engine_object] = {}
                environment_data['memory'] = {}
            # Calculate the CPU usage by using the CPU idle value.
            environment_data['cpu'][routing_engine_object]['%usage'] = \
                100.0 - structured_routing_engine_data['cpu-idle']
            try:
                environment_data['memory']['available_ram'] = \
                    int(structured_routing_engine_data['memory-dram-size'])
            except ValueError:
                environment_data['memory']['available_ram'] = \
                    int(
                        ''.join(
                            i for i in structured_routing_engine_data['memory-dram-size']
                            if i.isdigit()
                        )
                    )
            # Junos gives us RAM in %, so calculation has to be made.
            # Sadly, bacause of this, results are not 100% accurate to the truth.
            environment_data['memory']['used_ram'] = \
                int(round(environment_data['memory']['available_ram'] / 100.0 *
                    structured_routing_engine_data['memory-buffer-utilization']))

        return environment_data

    @staticmethod
    def _get_address_family(table):
        """
        Function to derive address family from a junos table name.

        :params table: The name of the routing table
        :returns: address family
        """
        address_family_mapping = {
            'inet': 'ipv4',
            'inet6': 'ipv6',
            'inetflow': 'flow'
        }
        family = table.split('.')[-2]
        try:
            address_family = address_family_mapping[family]
        except KeyError:
            address_family = family
        return address_family

    def _parse_route_stats(self, neighbor):
        data = {}
        if not neighbor['is_up']:
            pass
        elif isinstance(neighbor['tables'], list):
            for idx, table in enumerate(neighbor['tables']):
                family = self._get_address_family(table)
                data[family] = {}
                data[family]['received_prefixes'] = neighbor['received_prefixes'][idx]
                data[family]['accepted_prefixes'] = neighbor['accepted_prefixes'][idx]
                data[family]['sent_prefixes'] = neighbor['sent_prefixes'][idx]
        else:
            family = self._get_address_family(neighbor['tables'])
            data[family] = {}
            data[family]['received_prefixes'] = neighbor['received_prefixes']
            data[family]['accepted_prefixes'] = neighbor['accepted_prefixes']
            data[family]['sent_prefixes'] = neighbor['sent_prefixes']
        return data

    @staticmethod
    def _parse_value(value):
        if isinstance(value, py23_compat.string_types):
            return py23_compat.text_type(value)
        elif value is None:
            return u''
        else:
            return value

    def get_bgp_neighbors(self):
        """Return BGP neighbors details."""
        instances = junos_views.junos_route_instance_table(self.device)
        uptime_table = junos_views.junos_bgp_uptime_table(self.device)
        bgp_neighbors = junos_views.junos_bgp_table(self.device)
        keys = ['local_as', 'remote_as', 'is_up', 'is_enabled', 'description', 'remote_id']
        bgp_neighbor_data = {}
        for instance, instance_data in instances.get().items():
            if instance.startswith('__'):
                # junos internal instances
                continue
            instance_name = "global" if instance == 'master' else instance
            bgp_neighbor_data[instance_name] = {'peers': {}}
            for neighbor, data in bgp_neighbors.get(instance=instance).items():
                neighbor_data = {k: v for k, v in data}
                peer_ip = napalm_base.helpers.ip(neighbor.split('+')[0])
                if 'router_id' not in bgp_neighbor_data[instance_name]:
                    # we only need to set this once
                    bgp_neighbor_data[instance_name]['router_id'] = \
                        py23_compat.text_type(neighbor_data['local_id'])
                peer = {
                    key: self._parse_value(value)
                    for key, value in neighbor_data.items()
                    if key in keys
                }
                peer['address_family'] = self._parse_route_stats(neighbor_data)
                bgp_neighbor_data[instance_name]['peers'][peer_ip] = peer
            for neighbor, uptime in uptime_table.get(instance=instance).items():
                bgp_neighbor_data[instance_name]['peers'][neighbor]['uptime'] = uptime[0][1]
        bgp_tmp_dict = {}
        for k, v in bgp_neighbor_data.items():
            if bgp_neighbor_data[k]['peers']:
                bgp_tmp_dict[k] = v
        return bgp_tmp_dict

    def get_lldp_neighbors(self):
        """Return LLDP neighbors details."""
        lldp = junos_views.junos_lldp_table(self.device)
        lldp.get()

        result = lldp.items()

        neighbors = {}
        for neigh in result:
            if neigh[0] not in neighbors.keys():
                neighbors[neigh[0]] = []
            neighbors[neigh[0]].append({x[0]: py23_compat.text_type(x[1]) for x in neigh[1]})

        return neighbors

    def get_lldp_neighbors_detail(self, interface=''):
        """Detailed view of the LLDP neighbors."""
        lldp_neighbors = {}

        lldp_table = junos_views.junos_lldp_neighbors_detail_table(self.device)
        lldp_table.get()
        interfaces = lldp_table.get().keys()

        old_junos = napalm_base.helpers.convert(
            int, self.device.facts.get('version', '0.0').split('.')[0], '0') < 13

        lldp_table.GET_RPC = 'get-lldp-interface-neighbors'
        if old_junos:
            lldp_table.GET_RPC = 'get-lldp-interface-neighbors-information'

        for interface in interfaces:
            if old_junos:
                lldp_table.get(interface_name=interface)
            else:
                lldp_table.get(interface_device=interface)
            for item in lldp_table:
                if interface not in lldp_neighbors.keys():
                    lldp_neighbors[interface] = []
                lldp_neighbors[interface].append({
                    'parent_interface': item.parent_interface,
                    'remote_port': item.remote_port,
                    'remote_chassis_id': napalm_base.helpers.convert(
                        napalm_base.helpers.mac, item.remote_chassis_id, item.remote_chassis_id),
                    'remote_port_description': napalm_base.helpers.convert(
                        py23_compat.text_type, item.remote_port_description),
                    'remote_system_name': item.remote_system_name,
                    'remote_system_description': item.remote_system_description,
                    'remote_system_capab': item.remote_system_capab,
                    'remote_system_enable_capab': item.remote_system_enable_capab
                })

        return lldp_neighbors

    def cli(self, commands):
        """Execute raw CLI commands and returns their output."""
        cli_output = {}

        if not isinstance(commands, list):
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            cli_output[py23_compat.text_type(command)] = py23_compat.text_type(
                self.device.cli(command))

        return cli_output

    def get_bgp_config(self, group='', neighbor=''):
        """Return BGP configuration."""
        def update_dict(d, u):  # for deep dictionary update
            for k, v in u.items():
                if isinstance(d, collections.Mapping):
                    if isinstance(v, collections.Mapping):
                        r = update_dict(d.get(k, {}), v)
                        d[k] = r
                    else:
                        d[k] = u[k]
                else:
                    d = {k: u[k]}
            return d

        def build_prefix_limit(**args):
            """
            Transform the lements of a dictionary into nested dictionaries.

            Example:
                {
                    'inet_unicast_limit': 500,
                    'inet_unicast_teardown_threshold': 95,
                    'inet_unicast_teardown_timeout': 5
                }

                becomes:

                {
                    'inet': {
                        'unicast': {
                            'limit': 500,
                            'teardown': {
                                'threshold': 95,
                                'timeout': 5
                            }
                        }
                    }
                }
            """
            prefix_limit = {}

            for key, value in args.items():
                key_levels = key.split('_')
                length = len(key_levels)-1
                temp_dict = {
                    key_levels[length]: value
                }
                for index in reversed(range(length)):
                    level = key_levels[index]
                    temp_dict = {level: temp_dict}
                update_dict(prefix_limit, temp_dict)

            return prefix_limit

        _COMMON_FIELDS_DATATYPE_ = {
            'description': py23_compat.text_type,
            'local_address': py23_compat.text_type,
            'local_as': int,
            'remote_as': int,
            'import_policy': py23_compat.text_type,
            'export_policy': py23_compat.text_type,
            'inet_unicast_limit_prefix_limit': int,
            'inet_unicast_teardown_threshold_prefix_limit': int,
            'inet_unicast_teardown_timeout_prefix_limit': int,
            'inet_unicast_novalidate_prefix_limit': int,
            'inet_flow_limit_prefix_limit': int,
            'inet_flow_teardown_threshold_prefix_limit': int,
            'inet_flow_teardown_timeout_prefix_limit': int,
            'inet_flow_novalidate_prefix_limit': py23_compat.text_type,
            'inet6_unicast_limit_prefix_limit': int,
            'inet6_unicast_teardown_threshold_prefix_limit': int,
            'inet6_unicast_teardown_timeout_prefix_limit': int,
            'inet6_unicast_novalidate_prefix_limit': int,
            'inet6_flow_limit_prefix_limit': int,
            'inet6_flow_teardown_threshold_prefix_limit': int,
            'inet6_flow_teardown_timeout_prefix_limit': int,
            'inet6_flow_novalidate_prefix_limit': py23_compat.text_type,
        }

        _PEER_FIELDS_DATATYPE_MAP_ = {
            'authentication_key': py23_compat.text_type,
            'route_reflector_client': bool,
            'nhs': bool
        }
        _PEER_FIELDS_DATATYPE_MAP_.update(
            _COMMON_FIELDS_DATATYPE_
        )

        _GROUP_FIELDS_DATATYPE_MAP_ = {
            'type': py23_compat.text_type,
            'apply_groups': list,
            'remove_private_as': bool,
            'multipath': bool,
            'multihop_ttl': int
        }
        _GROUP_FIELDS_DATATYPE_MAP_.update(
            _COMMON_FIELDS_DATATYPE_
        )

        _DATATYPE_DEFAULT_ = {
            py23_compat.text_type: '',
            int: 0,
            bool: False,
            list: []
        }

        bgp_config = {}

        if group:
            bgp = junos_views.junos_bgp_config_group_table(self.device)
            bgp.get(group=group)
        else:
            bgp = junos_views.junos_bgp_config_table(self.device)
            bgp.get()
            neighbor = ''  # if no group is set, no neighbor should be set either
        bgp_items = bgp.items()

        if neighbor:
            neighbor_ip = napalm_base.helpers.ip(neighbor)

        for bgp_group in bgp_items:
            bgp_group_name = bgp_group[0]
            bgp_group_details = bgp_group[1]
            bgp_config[bgp_group_name] = {
                field: _DATATYPE_DEFAULT_.get(datatype)
                for field, datatype in _GROUP_FIELDS_DATATYPE_MAP_.items()
                if '_prefix_limit' not in field
            }
            for elem in bgp_group_details:
                if not('_prefix_limit' not in elem[0] and elem[1] is not None):
                    continue
                datatype = _GROUP_FIELDS_DATATYPE_MAP_.get(elem[0])
                default = _DATATYPE_DEFAULT_.get(datatype)
                key = elem[0]
                value = elem[1]
                if key in ['export_policy', 'import_policy']:
                    if isinstance(value, list):
                        value = ' '.join(value)
                if key == 'local_address':
                    value = napalm_base.helpers.convert(
                        napalm_base.helpers.ip, value, value)
                if key == 'neighbors':
                    bgp_group_peers = value
                    continue
                bgp_config[bgp_group_name].update({
                    key: napalm_base.helpers.convert(datatype, value, default)
                })
            prefix_limit_fields = {}
            for elem in bgp_group_details:
                if '_prefix_limit' in elem[0] and elem[1] is not None:
                    datatype = _GROUP_FIELDS_DATATYPE_MAP_.get(elem[0])
                    default = _DATATYPE_DEFAULT_.get(datatype)
                    prefix_limit_fields.update({
                        elem[0].replace('_prefix_limit', ''):
                            napalm_base.helpers.convert(datatype, elem[1], default)
                    })
            bgp_config[bgp_group_name]['prefix_limit'] = build_prefix_limit(**prefix_limit_fields)

            bgp_config[bgp_group_name]['neighbors'] = {}
            for bgp_group_neighbor in bgp_group_peers.items():
                bgp_peer_address = napalm_base.helpers.ip(bgp_group_neighbor[0])
                if neighbor and bgp_peer_address != neighbor:
                    continue  # if filters applied, jump over all other neighbors
                bgp_group_details = bgp_group_neighbor[1]
                bgp_peer_details = {
                    field: _DATATYPE_DEFAULT_.get(datatype)
                    for field, datatype in _PEER_FIELDS_DATATYPE_MAP_.items()
                    if '_prefix_limit' not in field
                }
                for elem in bgp_group_details:
                    if not('_prefix_limit' not in elem[0] and elem[1] is not None):
                        continue
                    datatype = _PEER_FIELDS_DATATYPE_MAP_.get(elem[0])
                    default = _DATATYPE_DEFAULT_.get(datatype)
                    key = elem[0]
                    value = elem[1]
                    if key in ['export_policy', 'import_policy']:
                        if isinstance(value, list):
                            value = ' '.join(value)
                    if key == 'local_address':
                        value = napalm_base.helpers.convert(
                            napalm_base.helpers.ip, value, value)
                    bgp_peer_details.update({
                        key: napalm_base.helpers.convert(datatype, value, default)
                    })
                prefix_limit_fields = {}
                for elem in bgp_group_details:
                    if '_prefix_limit' in elem[0] and elem[1] is not None:
                        datatype = _PEER_FIELDS_DATATYPE_MAP_.get(elem[0])
                        default = _DATATYPE_DEFAULT_.get(datatype)
                        prefix_limit_fields.update({
                            elem[0].replace('_prefix_limit', ''):
                                napalm_base.helpers.convert(datatype, elem[1], default)
                        })
                bgp_peer_details['prefix_limit'] = build_prefix_limit(**prefix_limit_fields)
                bgp_config[bgp_group_name]['neighbors'][bgp_peer_address] = bgp_peer_details
                if neighbor and bgp_peer_address == neighbor_ip:
                    break  # found the desired neighbor

        return bgp_config

    def get_bgp_neighbors_detail(self, neighbor_address=''):
        """Detailed view of the BGP neighbors operational data."""
        bgp_neighbors = {}

        bgp_neighbors_table = junos_views.junos_bgp_neighbors_table(self.device)

        bgp_neighbors_table.get(
            neighbor_address=neighbor_address
        )
        bgp_neighbors_items = bgp_neighbors_table.items()

        default_neighbor_details = {
            'up': False,
            'local_as': 0,
            'remote_as': 0,
            'router_id': u'',
            'local_address': u'',
            'routing_table': u'',
            'local_address_configured': False,
            'local_port': 0,
            'remote_address': u'',
            'remote_port': 0,
            'multihop': False,
            'multipath': False,
            'remove_private_as': False,
            'import_policy': u'',
            'export_policy': u'',
            'input_messages': -1,
            'output_messages': -1,
            'input_updates': -1,
            'output_updates': -1,
            'messages_queued_out': -1,
            'connection_state': u'',
            'previous_connection_state': u'',
            'last_event': u'',
            'suppress_4byte_as': False,
            'local_as_prepend': False,
            'holdtime': 0,
            'configured_holdtime': 0,
            'keepalive': 0,
            'configured_keepalive': 0,
            'active_prefix_count': -1,
            'received_prefix_count': -1,
            'accepted_prefix_count': -1,
            'suppressed_prefix_count': -1,
            'advertised_prefix_count': -1,
            'flap_count': 0
        }

        OPTION_KEY_MAP = {
            'RemovePrivateAS': 'remove_private_as',
            'Multipath': 'multipath',
            'Multihop': 'multihop',
            'AddressFamily': 'local_address_configured'
            # 'AuthKey'        : 'authentication_key_set'
            # but other vendors do not specify if auth key is set
            # other options:
            # Preference, HoldTime, Ttl, LogUpDown, Refresh
        }

        for bgp_neighbor in bgp_neighbors_items:
            remote_as = int(bgp_neighbor[0])
            neighbor_details = deepcopy(default_neighbor_details)
            neighbor_details.update(
                {elem[0]: elem[1] for elem in bgp_neighbor[1] if elem[1] is not None}
            )
            options = neighbor_details.pop('options', '')
            if isinstance(options, str):
                options_list = options.split()
                for option in options_list:
                    key = OPTION_KEY_MAP.get(option)
                    if key is not None:
                        neighbor_details[key] = True
            four_byte_as = neighbor_details.pop('4byte_as', 0)
            local_address = neighbor_details.pop('local_address', '')
            local_details = local_address.split('+')
            neighbor_details['local_address'] = napalm_base.helpers.convert(
                napalm_base.helpers.ip, local_details[0], local_details[0])
            if len(local_details) == 2:
                neighbor_details['local_port'] = int(local_details[1])
            else:
                neighbor_details['local_port'] = 179
            neighbor_details['suppress_4byte_as'] = (remote_as != four_byte_as)
            peer_address = neighbor_details.pop('peer_address', '')
            remote_details = peer_address.split('+')
            neighbor_details['remote_address'] = napalm_base.helpers.convert(
                napalm_base.helpers.ip, remote_details[0], remote_details[0])
            if len(remote_details) == 2:
                neighbor_details['remote_port'] = int(remote_details[1])
            else:
                neighbor_details['remote_port'] = 179
            neighbors_rib = neighbor_details.pop('rib')
            neighbors_rib_items = neighbors_rib.items()
            for rib_entry in neighbors_rib_items:
                _table = py23_compat.text_type(rib_entry[0])
                if _table not in bgp_neighbors.keys():
                    bgp_neighbors[_table] = {}
                if remote_as not in bgp_neighbors[_table].keys():
                    bgp_neighbors[_table][remote_as] = []
                neighbor_rib_details = deepcopy(neighbor_details)
                neighbor_rib_details.update({
                    elem[0]: elem[1] for elem in rib_entry[1]
                })
                neighbor_rib_details['routing_table'] = py23_compat.text_type(_table)
                bgp_neighbors[_table][remote_as].append(neighbor_rib_details)

        return bgp_neighbors

    def get_arp_table(self):
        """Return the ARP table."""
        # could use ArpTable
        # from jnpr.junos.op.phyport import ArpTable
        # and simply use it
        # but
        # we need:
        #   - filters
        #   - group by VLAN ID
        #   - hostname & TTE fields as well

        arp_table = []

        arp_table_raw = junos_views.junos_arp_table(self.device)
        arp_table_raw.get()
        arp_table_items = arp_table_raw.items()

        for arp_table_entry in arp_table_items:
            arp_entry = {
                elem[0]: elem[1] for elem in arp_table_entry[1]
            }
            arp_entry['mac'] = napalm_base.helpers.mac(arp_entry.get('mac'))
            arp_entry['ip'] = napalm_base.helpers.ip(arp_entry.get('ip'))
            arp_table.append(arp_entry)

        return arp_table

    def get_ntp_peers(self):
        """Return the NTP peers configured on the device."""
        ntp_table = junos_views.junos_ntp_peers_config_table(self.device)
        ntp_table.get()

        ntp_peers = ntp_table.items()

        if not ntp_peers:
            return {}

        return {napalm_base.helpers.ip(peer[0]): {} for peer in ntp_peers}

    def get_ntp_servers(self):
        """Return the NTP servers configured on the device."""
        ntp_table = junos_views.junos_ntp_servers_config_table(self.device)
        ntp_table.get()

        ntp_servers = ntp_table.items()

        if not ntp_servers:
            return {}

        return {napalm_base.helpers.ip(server[0]): {} for server in ntp_servers}

    def get_ntp_stats(self):
        """Return NTP stats (associations)."""
        # NTP Peers does not have XML RPC defined
        # thus we need to retrieve raw text and parse...
        # :(

        ntp_stats = []

        REGEX = (
            '^\s?(\+|\*|x|-)?([a-zA-Z0-9\.+-:]+)'
            '\s+([a-zA-Z0-9\.]+)\s+([0-9]{1,2})'
            '\s+(-|u)\s+([0-9h-]+)\s+([0-9]+)'
            '\s+([0-9]+)\s+([0-9\.]+)\s+([0-9\.-]+)'
            '\s+([0-9\.]+)\s?$'
        )

        ntp_assoc_output = self.device.cli('show ntp associations no-resolve')
        ntp_assoc_output_lines = ntp_assoc_output.splitlines()

        for ntp_assoc_output_line in ntp_assoc_output_lines[3:]:  # except last line
            line_search = re.search(REGEX, ntp_assoc_output_line, re.I)
            if not line_search:
                continue  # pattern not found
            line_groups = line_search.groups()
            try:
                ntp_stats.append({
                    'remote': napalm_base.helpers.ip(line_groups[1]),
                    'synchronized': (line_groups[0] == '*'),
                    'referenceid': py23_compat.text_type(line_groups[2]),
                    'stratum': int(line_groups[3]),
                    'type': py23_compat.text_type(line_groups[4]),
                    'when': py23_compat.text_type(line_groups[5]),
                    'hostpoll': int(line_groups[6]),
                    'reachability': int(line_groups[7]),
                    'delay': float(line_groups[8]),
                    'offset': float(line_groups[9]),
                    'jitter': float(line_groups[10])
                })
            except Exception:
                continue  # jump to next line

        return ntp_stats

    def get_interfaces_ip(self):
        """Return the configured IP addresses."""
        interfaces_ip = {}

        interface_table = junos_views.junos_ip_interfaces_table(self.device)
        interface_table.get()
        interface_table_items = interface_table.items()

        _FAMILY_VMAP_ = {
            'inet': u'ipv4',
            'inet6': u'ipv6'
            # can add more mappings
        }

        for interface_details in interface_table_items:
            ip_network = interface_details[0]
            ip_address = ip_network.split('/')[0]
            address = napalm_base.helpers.convert(
                napalm_base.helpers.ip, ip_address, ip_address)
            prefix = napalm_base.helpers.convert(int, ip_network.split('/')[-1], 0)
            try:
                interface_details_dict = dict(interface_details[1])
                family_raw = interface_details_dict.get('family')
                interface = py23_compat.text_type(interface_details_dict.get('interface'))
            except ValueError:
                continue
            family = _FAMILY_VMAP_.get(family_raw)
            if not family or not interface:
                continue
            if interface not in interfaces_ip.keys():
                interfaces_ip[interface] = {}
            if family not in interfaces_ip[interface].keys():
                interfaces_ip[interface][family] = {}
            if address not in interfaces_ip[interface][family].keys():
                interfaces_ip[interface][family][address] = {}
            interfaces_ip[interface][family][address][u'prefix_length'] = prefix

        return interfaces_ip

    def get_mac_address_table(self):
        """Return the MAC address table."""
        mac_address_table = []

        if self.device.facts.get('personality', '') in ['SWITCH']:  # for EX & QFX devices
            mac_table = junos_views.junos_mac_address_table_switch(self.device)
        else:
            mac_table = junos_views.junos_mac_address_table(self.device)

        mac_table.get()
        mac_table_items = mac_table.items()

        default_values = {
            'mac': u'',
            'interface': u'',
            'vlan': 0,
            'static': False,
            'active': True,
            'moves': 0,
            'last_move': 0.0
        }

        for mac_table_entry in mac_table_items:
            mac_entry = default_values.copy()
            mac_entry.update(
                {elem[0]: elem[1] for elem in mac_table_entry[1]}
            )
            mac = mac_entry.get('mac')
            mac_entry['mac'] = napalm_base.helpers.mac(mac)
            mac_address_table.append(mac_entry)

        return mac_address_table

    def get_route_to(self, destination='', protocol=''):
        """Return route details to a specific destination, learned from a certain protocol."""
        routes = {}

        if not isinstance(destination, py23_compat.string_types):
            raise TypeError('Please specify a valid destination!')

        if protocol and isinstance(destination, py23_compat.string_types):
            protocol = protocol.lower()

        if protocol == 'connected':
            protocol = 'direct'  # this is how is called on JunOS

        _COMMON_PROTOCOL_FIELDS_ = [
            'destination',
            'prefix_length',
            'protocol',
            'current_active',
            'last_active',
            'age',
            'next_hop',
            'outgoing_interface',
            'selected_next_hop',
            'preference',
            'inactive_reason',
            'routing_table'
        ]  # identifies the list of fileds common for all protocols

        _BOOLEAN_FIELDS_ = [
            'current_active',
            'selected_next_hop',
            'last_active'
        ]  # fields expected to have boolean values

        _PROTOCOL_SPECIFIC_FIELDS_ = {
            'bgp': [
                'local_as',
                'remote_as',
                'as_path',
                'communities',
                'local_preference',
                'preference2',
                'remote_address',
                'metric',
                'metric2'
            ],
            'isis': [
                'level',
                'metric',
                'local_as'
            ]
        }

        routes_table = junos_views.junos_protocol_route_table(self.device)

        rt_kargs = {
            'destination': destination
        }
        if protocol and isinstance(destination, py23_compat.string_types):
            rt_kargs['protocol'] = protocol

        try:
            routes_table.get(**rt_kargs)
        except RpcTimeoutError:
            # on devices with milions of routes
            # in case the destination is too generic (e.g.: 10/8)
            # will take very very long to determine all routes and
            # moreover will return a huge list
            raise CommandTimeoutException(
                'Too many routes returned! Please try with a longer prefix or a specific protocol!'
            )
        except RpcError as rpce:
            if len(rpce.errs) > 0 and 'bad_element' in rpce.errs[0]:
                raise CommandErrorException(
                    'Unknown protocol: {proto}'.format(proto=rpce.errs[0]['bad_element']))
            raise CommandErrorException(rpce)
        except Exception as err:
            raise CommandErrorException('Cannot retrieve routes! Reason: {err}'.format(err=err))

        routes_items = routes_table.items()

        for route in routes_items:
            d = {}
            # next_hop = route[0]
            d = {elem[0]: elem[1] for elem in route[1]}
            destination = napalm_base.helpers.ip(d.pop('destination', ''))
            prefix_length = d.pop('prefix_length', 32)
            destination = '{d}/{p}'.format(
                d=destination,
                p=prefix_length
            )
            d.update({key: False for key in _BOOLEAN_FIELDS_ if d.get(key) is None})
            as_path = d.get('as_path')
            if as_path is not None:
                d['as_path'] = as_path.split(' I ')[0]\
                                      .replace('AS path:', '')\
                                      .replace('I', '')\
                                      .strip()
                # to be sure that contains only AS Numbers
            if d.get('inactive_reason') is None:
                d['inactive_reason'] = u''
            route_protocol = d.get('protocol').lower()
            if protocol and protocol != route_protocol:
                continue
            communities = d.get('communities')
            if communities is not None and type(communities) is not list:
                d['communities'] = [communities]
            d_keys = list(d.keys())
            # fields that are not in _COMMON_PROTOCOL_FIELDS_ are supposed to be protocol specific
            all_protocol_attributes = {
                key: d.pop(key)
                for key in d_keys
                if key not in _COMMON_PROTOCOL_FIELDS_
            }
            protocol_attributes = {
                key: value for key, value in all_protocol_attributes.items()
                if key in _PROTOCOL_SPECIFIC_FIELDS_.get(route_protocol, [])
            }
            d['protocol_attributes'] = protocol_attributes
            if destination not in routes.keys():
                routes[destination] = []
            routes[destination].append(d)

        return routes

    def get_snmp_information(self):
        """Return the SNMP configuration."""
        snmp_information = {}

        snmp_config = junos_views.junos_snmp_config_table(self.device)
        snmp_config.get()
        snmp_items = snmp_config.items()

        if not snmp_items:
            return snmp_information

        snmp_information = {
            py23_compat.text_type(ele[0]): ele[1] if ele[1] else ''
            for ele in snmp_items[0][1]
        }

        snmp_information['community'] = {}
        communities_table = snmp_information.pop('communities_table')
        if not communities_table:
            return snmp_information

        for community in communities_table.items():
            community_name = py23_compat.text_type(community[0])
            community_details = {
                'acl': ''
            }
            community_details.update({
                py23_compat.text_type(ele[0]): py23_compat.text_type(
                    ele[1] if ele[0] != 'mode'
                    else C.SNMP_AUTHORIZATION_MODE_MAP.get(ele[1]))
                for ele in community[1]
            })
            snmp_information['community'][community_name] = community_details

        return snmp_information

    def get_probes_config(self):
        """Return the configuration of the RPM probes."""
        probes = {}

        probes_table = junos_views.junos_rpm_probes_config_table(self.device)
        probes_table.get()
        probes_table_items = probes_table.items()

        for probe_test in probes_table_items:
            test_name = py23_compat.text_type(probe_test[0])
            test_details = {
                p[0]: p[1] for p in probe_test[1]
            }
            probe_name = napalm_base.helpers.convert(
                py23_compat.text_type, test_details.pop('probe_name'))
            target = napalm_base.helpers.convert(
                py23_compat.text_type, test_details.pop('target', ''))
            test_interval = napalm_base.helpers.convert(int, test_details.pop('test_interval', '0'))
            probe_count = napalm_base.helpers.convert(int, test_details.pop('probe_count', '0'))
            probe_type = napalm_base.helpers.convert(
                py23_compat.text_type, test_details.pop('probe_type', ''))
            source = napalm_base.helpers.convert(
                py23_compat.text_type, test_details.pop('source_address', ''))
            if probe_name not in probes.keys():
                probes[probe_name] = {}
            probes[probe_name][test_name] = {
                'probe_type': probe_type,
                'target': target,
                'source': source,
                'probe_count': probe_count,
                'test_interval': test_interval
            }

        return probes

    def get_probes_results(self):
        """Return the results of the RPM probes."""
        probes_results = {}

        probes_results_table = junos_views.junos_rpm_probes_results_table(self.device)
        probes_results_table.get()
        probes_results_items = probes_results_table.items()

        for probe_result in probes_results_items:
            probe_name = py23_compat.text_type(probe_result[0])
            test_results = {
                p[0]: p[1] for p in probe_result[1]
            }
            test_results['last_test_loss'] = napalm_base.helpers.convert(
                int, test_results.pop('last_test_loss'), 0)
            for test_param_name, test_param_value in test_results.items():
                if isinstance(test_param_value, float):
                    test_results[test_param_name] = test_param_value * 1e-3
                    # convert from useconds to mseconds
            test_name = test_results.pop('test_name', '')
            source = test_results.get('source', u'')
            if source is None:
                test_results['source'] = u''
            if probe_name not in probes_results.keys():
                probes_results[probe_name] = {}
            probes_results[probe_name][test_name] = test_results

        return probes_results

    def traceroute(self,
                   destination,
                   source=C.TRACEROUTE_SOURCE,
                   ttl=C.TRACEROUTE_TTL,
                   timeout=C.TRACEROUTE_TIMEOUT):
        """Execute traceroute and return results."""
        traceroute_result = {}

        # calling form RPC does not work properly :(
        # but defined junos_route_instance_table just in case

        source_str = ''
        maxttl_str = ''
        wait_str = ''

        if source:
            source_str = 'source {source}'.format(source=source)
        if ttl:
            maxttl_str = 'ttl {ttl}'.format(ttl=ttl)
        if timeout:
            wait_str = 'wait {timeout}'.format(timeout=timeout)

        traceroute_command = 'traceroute {destination} {source} {maxttl} {wait}'.format(
            destination=destination,
            source=source_str,
            maxttl=maxttl_str,
            wait=wait_str
        )

        traceroute_rpc = E('command', traceroute_command)
        rpc_reply = self.device._conn.rpc(traceroute_rpc)._NCElement__doc
        # make direct RPC call via NETCONF
        traceroute_results = rpc_reply.find('.//traceroute-results')

        traceroute_failure = napalm_base.helpers.find_txt(
            traceroute_results, 'traceroute-failure', '')
        error_message = napalm_base.helpers.find_txt(
            traceroute_results, 'rpc-error/error-message', '')

        if traceroute_failure and error_message:
            return {'error': '{}: {}'.format(traceroute_failure, error_message)}

        traceroute_result['success'] = {}
        for hop in traceroute_results.findall('hop'):
            ttl_value = napalm_base.helpers.convert(
                int, napalm_base.helpers.find_txt(hop, 'ttl-value'), 1)
            if ttl_value not in traceroute_result['success']:
                traceroute_result['success'][ttl_value] = {'probes': {}}
            for probe in hop.findall('probe-result'):
                probe_index = napalm_base.helpers.convert(
                    int, napalm_base.helpers.find_txt(probe, 'probe-index'), 0)
                ip_address = napalm_base.helpers.convert(
                    napalm_base.helpers.ip, napalm_base.helpers.find_txt(probe, 'ip-address'), '*')
                host_name = py23_compat.text_type(
                    napalm_base.helpers.find_txt(probe, 'host-name', '*'))
                rtt = napalm_base.helpers.convert(
                    float, napalm_base.helpers.find_txt(probe, 'rtt'), 0) * 1e-3  # ms
                traceroute_result['success'][ttl_value]['probes'][probe_index] = {
                    'ip_address': ip_address,
                    'host_name': host_name,
                    'rtt': rtt
                }

        return traceroute_result

    def ping(self, destination, source=C.PING_SOURCE, ttl=C.PING_TTL,
             timeout=C.PING_TIMEOUT, size=C.PING_SIZE, count=C.PING_COUNT):

        ping_dict = {}

        source_str = ''
        maxttl_str = ''
        timeout_str = ''
        size_str = ''
        count_str = ''

        if source:
            source_str = 'source {source}'.format(source=source)
        if ttl:
            maxttl_str = 'ttl {ttl}'.format(ttl=ttl)
        if timeout:
            timeout_str = 'wait {timeout}'.format(timeout=timeout)
        if size:
            size_str = 'size {size}'.format(size=size)
        if count:
            count_str = 'count {count}'.format(count=count)

        ping_command = 'ping {destination} {source} {ttl} {timeout} {size} {count}'.format(
            destination=destination,
            source=source_str,
            ttl=maxttl_str,
            timeout=timeout_str,
            size=size_str,
            count=count_str
        )

        ping_rpc = E('command', ping_command)
        rpc_reply = self.device._conn.rpc(ping_rpc)._NCElement__doc
        # make direct RPC call via NETCONF
        probe_summary = rpc_reply.find('.//probe-results-summary')

        if probe_summary is None:
            rpc_error = rpc_reply.find('.//rpc-error')
            return {'error': '{}'.format(
                napalm_base.helpers.find_txt(rpc_error, 'error-message'))}

        packet_loss = napalm_base.helpers.convert(
            int, napalm_base.helpers.find_txt(probe_summary, 'packet-loss'), 100)

        # rtt values are valid only if a we get an ICMP reply
        if packet_loss is not 100:
            ping_dict['success'] = {}
            ping_dict['success']['probes_sent'] = int(
                probe_summary.findtext("probes-sent"))
            ping_dict['success']['packet_loss'] = packet_loss
            ping_dict['success'].update({

                'rtt_min': round((napalm_base.helpers.convert(
                    float, napalm_base.helpers.find_txt(
                        probe_summary, 'rtt-minimum'), -1) * 1e-3), 3),

                'rtt_max': round((napalm_base.helpers.convert(
                    float, napalm_base.helpers.find_txt(
                        probe_summary, 'rtt-maximum'), -1) * 1e-3), 3),

                'rtt_avg': round((napalm_base.helpers.convert(
                    float, napalm_base.helpers.find_txt(
                        probe_summary, 'rtt-average'), -1) * 1e-3), 3),

                'rtt_stddev': round((napalm_base.helpers.convert(
                    float, napalm_base.helpers.find_txt(
                        probe_summary, 'rtt-stddev'), -1) * 1e-3), 3)
            })

            tmp = rpc_reply.find('.//ping-results')

            results_array = []
            for probe_result in tmp.findall('probe-result'):

                ip_address = napalm_base.helpers.convert(
                    napalm_base.helpers.ip,
                    napalm_base.helpers.find_txt(probe_result, 'ip-address'), '*')

                rtt = round(
                    (napalm_base.helpers.convert(
                        float, napalm_base.helpers.find_txt(
                            probe_result, 'rtt'), -1) * 1e-3), 3)

                results_array.append({'ip_address': ip_address,
                                      'rtt': rtt})

            ping_dict['success'].update({'results': results_array})
        else:
            return {'error': 'Packet loss {}'.format(packet_loss)}

        return ping_dict

    def get_users(self):
        """Return the configuration of the users."""
        users = {}

        _JUNOS_CLASS_CISCO_PRIVILEGE_LEVEL_MAP = {
            'super-user': 15,
            'superuser': 15,
            'operator': 5,
            'read-only': 1,
            'unauthorized': 0
        }

        _DEFAULT_USER_DETAILS = {
            'level': 0,
            'password': '',
            'sshkeys': []
        }

        users_table = junos_views.junos_users_table(self.device)
        users_table.get()
        users_items = users_table.items()

        for user_entry in users_items:
            username = user_entry[0]
            user_details = _DEFAULT_USER_DETAILS.copy()
            user_details.update({
                d[0]: d[1] for d in user_entry[1] if d[1]
            })
            user_class = user_details.pop('class', '')
            user_details = {
                key: py23_compat.text_type(user_details[key])
                for key in user_details.keys()
            }
            level = _JUNOS_CLASS_CISCO_PRIVILEGE_LEVEL_MAP.get(user_class, 0)
            user_details.update({
                'level': level
            })
            user_details['sshkeys'] = [
                user_details.pop(key)
                for key in ['ssh_rsa', 'ssh_dsa', 'ssh_ecdsa']
                if user_details.get(key, '')
            ]
            users[username] = user_details

        return users

    def get_optics(self):
        """Return optics information."""
        optics_table = junos_views.junos_intf_optics_table(self.device)
        optics_table.get()
        optics_items = optics_table.items()

        # Formatting data into return data structure
        optics_detail = {}
        for intf_optic_item in optics_items:
            interface_name = py23_compat.text_type(intf_optic_item[0])
            optics = dict(intf_optic_item[1])
            if interface_name not in optics_detail:
                optics_detail[interface_name] = {}

            # Defaulting avg, min, max values to 0.0 since device does not
            # return these values
            intf_optics = {
                'physical_channels': {
                    'channel': [{
                            'index': 0,
                            'state': {
                                'input_power': {
                                    'instant': (
                                        float(optics['input_power'])
                                        if optics['input_power'] != '- Inf'
                                        else 0.0),
                                    'avg': 0.0,
                                    'max': 0.0,
                                    'min': 0.0
                                    },
                                'output_power': {
                                    'instant': (
                                        float(optics['output_power'])
                                        if optics['output_power'] != '- Inf'
                                        else 0.0),
                                    'avg': 0.0,
                                    'max': 0.0,
                                    'min': 0.0
                                    },
                                'laser_bias_current': {
                                    'instant': (
                                        float(optics['laser_bias_current'])
                                        if optics['laser_bias_current'] != '- Inf'
                                        else 0.0),
                                    'avg': 0.0,
                                    'max': 0.0,
                                    'min': 0.0
                                    }
                                }
                        }]
                    }
                }
            optics_detail[interface_name] = intf_optics

        return optics_detail

    def get_config(self, retrieve='all'):
        rv = {
            'startup': '',
            'running': '',
            'candidate': ''
        }

        options = {
            'format': 'text',
            'database': 'candidate'
        }

        if retrieve in ('candidate', 'all'):
            config = self.device.rpc.get_config(filter_xml=None, options=options)
            rv['candidate'] = py23_compat.text_type(config.text)
        if retrieve in ('running', 'all'):
            options['database'] = 'committed'
            config = self.device.rpc.get_config(filter_xml=None, options=options)
            rv['running'] = py23_compat.text_type(config.text)
        return rv

    def get_network_instances(self, name=''):

        network_instances = {}

        ri_table = junos_views.junos_nw_instances_table(self.device)
        ri_table.get()
        ri_entries = ri_table.items()

        vrf_interfaces = []

        for ri_entry in ri_entries:
            ri_name = py23_compat.text_type(ri_entry[0])
            ri_details = {
                d[0]: d[1] for d in ri_entry[1]
            }
            ri_type = ri_details['instance_type']
            if ri_type is None:
                ri_type = 'default'
            ri_rd = ri_details['route_distinguisher']
            ri_interfaces = ri_details['interfaces']
            network_instances[ri_name] = {
                'name': ri_name,
                'type': C.OC_NETWORK_INSTANCE_TYPE_MAP.get(ri_type, ri_type),  # default: return raw
                'state': {
                    'route_distinguisher': ri_rd if ri_rd else ''
                },
                'interfaces': {
                    'interface': {
                        intrf_name: {} for intrf_name in ri_interfaces if intrf_name
                    }
                }
            }
            vrf_interfaces.extend(network_instances[ri_name]['interfaces']['interface'].keys())

        all_interfaces = self.get_interfaces().keys()
        default_interfaces = list(set(all_interfaces) - set(vrf_interfaces))
        if 'default' not in network_instances:
            network_instances['default'] = {
                'name': 'default',
                'type': C.OC_NETWORK_INSTANCE_TYPE_MAP.get('default'),
                'state': {
                    'route_distinguisher': ''
                },
                'interfaces': {
                    'interface': {
                        py23_compat.text_type(intrf_name): {}
                        for intrf_name in default_interfaces
                    }
                }
            }

        if not name:
            return network_instances
        if name not in network_instances:
            return {}
        return {name: network_instances[name]}
