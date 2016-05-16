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
import collections
from lxml.builder import E

from napalm_junos.utils import junos_views
from napalm_base.base import NetworkDriver

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import ConfigLoadError, ConnectTimeoutError
from napalm_base.exceptions import ConnectionException, ReplaceConfigException, MergeConfigException,\
                                   CommandErrorException

from napalm_base.utils import string_parsers


class JunOSDriver(NetworkDriver):

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
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
        try:
            self.device.open()
        except ConnectTimeoutError as cte:
            raise ConnectionException(cte.message)
        self.device.timeout = self.timeout
        self.device.bind(cu=Config)
        if self.config_lock:
            self.lock()

    def close(self):
        if self.config_lock:
            self.unlock()
        self.device.close()

    def lock(self):
        if not self.locked:
            self.device.cu.lock()
            self.locked = True

    def unlock(self):
        if self.locked:
            self.device.cu.unlock()
            self.locked = False

    def _load_candidate(self, filename, config, overwrite):
        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()

        if not self.config_lock:
            # if not locked during connection time
            # will try to lock it if not already aquired
            self.lock()
            # and the device will be locked till first commit/rollback

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
        if not self.config_lock:
            self.unlock()

    def discard_config(self):
        self.device.cu.rollback(rb_id=0)
        if not self.config_lock:
            self.unlock()

    def rollback(self):
        self.device.cu.rollback(rb_id=1)
        self.commit_config()


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
                'description': (interfaces[iface]['description'] or u''),
                'last_flapped': float((interfaces[iface]['last_flapped'] or -1)),
                'mac_address': unicode((interfaces[iface]['mac_address'] or '')),
                'speed': -1
            }
            # result[iface]['last_flapped'] = float(result[iface]['last_flapped'])

            match = re.search(r'(\d+)(\w*)', interfaces[iface]['speed'] or u'')
            if match is None:
                continue
            speed_value = self._convert(int, match.group(1), -1)
            if speed_value == -1:
                continue
            speed_unit = match.group(2)
            if speed_unit.lower() == 'gbps':
                speed_value *= 1000
            result[iface]['speed'] = speed_value

        return result

    def get_interfaces_counters(self):
        query = junos_views.junos_iface_counter_table(self.device)
        query.get()
        interface_counters = dict()
        for interface, counters in query.items():
            interface_counters[interface] = {k: v if v is not None else -1 for k, v in counters}
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
                environment_data['cpu'][routing_engine_object] = dict()
                environment_data['memory'] = dict()
            except KeyError:
                environment_data['cpu'] = dict()
                environment_data['cpu'][routing_engine_object] = dict()
                environment_data['memory'] = dict()
            # Calculate the CPU usage by using the CPU idle value.
            environment_data['cpu'][routing_engine_object]['%usage'] = 100.0 - structured_routing_engine_data['cpu-idle']
            try:
                environment_data['memory']['available_ram'] = int(structured_routing_engine_data['memory-dram-size'])
            except ValueError:
                environment_data['memory']['available_ram'] = int(''.join(i for i in structured_routing_engine_data['memory-dram-size'] if i.isdigit()))
            # Junos gives us RAM in %, so calculation has to be made.
            # Sadly, bacause of this, results are not 100% accurate to the truth.
            environment_data['memory']['used_ram'] = (environment_data['memory']['available_ram'] / 100 * structured_routing_engine_data['memory-buffer-utilization'])

        return environment_data

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
        if isinstance(value, basestring):
            return unicode(value)
        elif value is None:
            return u''
        else:
            return value

    def get_bgp_neighbors(self):
        instances = junos_views.junos_route_instance_table(self.device)
        uptime_table = junos_views.junos_bgp_uptime_table(self.device)
        bgp_neighbors = junos_views.junos_bgp_table(self.device)
        keys =['local_as', 'remote_as', 'is_up', 'is_enabled', 'description', 'remote_id']
        bgp_neighbor_data = {}
        for instance, instance_data in instances.get().items():
            if instance.startswith('__'):
                # junos internal instances
                continue
            instance_name = "global" if instance == 'master' else instance
            bgp_neighbor_data[instance_name] = {'peers': {}}
            for neighbor, data in bgp_neighbors.get(instance=instance).items():
                neighbor_data = {k: v for k, v in data}
                peer_ip = neighbor.split('+')[0]
                if 'router_id' not in bgp_neighbor_data[instance_name]:
                    # we only need to set this once
                    bgp_neighbor_data[instance_name]['router_id'] = unicode(neighbor_data['local_id'])
                peer = {key:self._parse_value(value) for key, value in neighbor_data.iteritems() if key in keys}
                peer['address_family'] = self._parse_route_stats(neighbor_data)
                bgp_neighbor_data[instance_name]['peers'][peer_ip] = peer
            for neighbor, uptime in uptime_table.get(instance=instance).items():
                bgp_neighbor_data[instance_name]['peers'][neighbor]['uptime'] = uptime[0][1]
        for key in bgp_neighbor_data.keys():
            if not bgp_neighbor_data[key]['peers']:
                del bgp_neighbor_data[key]
        return bgp_neighbor_data

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


    def get_lldp_neighbors_detail(self, interface=''):

        lldp_neighbors = dict()

        lldp_table = junos_views.junos_lldp_neighbors_detail_table(self.device)
        lldp_table.get()
        interfaces = lldp_table.get().keys()

        old_junos = self._convert(int, self.device.facts.get('version', '0.0').split('.')[0], '0') < 13

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
                    lldp_neighbors[interface] = list()
                lldp_neighbors[interface].append({
                    'parent_interface'          : item.parent_interface,
                    'remote_port'               : item.remote_port,
                    'remote_chassis_id'         : item.remote_chassis_id,
                    'remote_port'               : item.remote_port,
                    'remote_port_description'   : item.remote_port_description,
                    'remote_system_name'        : item.remote_system_name,
                    'remote_system_description' : item.remote_system_description,
                    'remote_system_capab'       : item.remote_system_capab,
                    'remote_system_enable_capab': item.remote_system_enable_capab
                })

        return lldp_neighbors


    def cli(self, commands = None):

        cli_output = dict()

        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            try:
                cli_output[unicode(command)] = unicode(self.device.cli(command))
            except Exception as e:
                cli_output[unicode(command)] = 'Unable to execute command "{cmd}": {err}'.format(
                    cmd = command,
                    err = e
                )
                raise CommandErrorException(str(cli_output))

        return cli_output


    def get_bgp_config(self, group='', neighbor=''):

        def update_dict(d, u): # for deep dictionary update
            for k, v in u.iteritems():
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
            This helper will transform the lements of a dictionary into nested dictionaries:
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

            prefix_limit = dict()

            for key, value in args.iteritems():
                key_levels = key.split('_')
                length     = len(key_levels)-1
                temp_dict = {
                    key_levels[length]: value
                }
                for index in reversed(range(length)):
                    level = key_levels[index]
                    temp_dict = {level: temp_dict}
                update_dict(prefix_limit, temp_dict)

            return prefix_limit

        _COMMON_FIELDS_DATATYPE_ = {
            'description': unicode,
            'local_address': unicode,
            'local_as': int,
            'remote_as': int,
            'import_policy': unicode,
            'export_policy': unicode,
            'inet_unicast_limit_prefix_limit': int,
            'inet_unicast_teardown_threshold_prefix_limit': int,
            'inet_unicast_teardown_timeout_prefix_limit': int,
            'inet_unicast_novalidate_prefix_limit': int,
            'inet_flow_limit_prefix_limit': int,
            'inet_flow_teardown_threshold_prefix_limit': int,
            'inet_flow_teardown_timeout_prefix_limit': int,
            'inet_flow_novalidate_prefix_limit': unicode,
            'inet6_unicast_limit_prefix_limit': int,
            'inet6_unicast_teardown_threshold_prefix_limit': int,
            'inet6_unicast_teardown_timeout_prefix_limit': int,
            'inet6_unicast_novalidate_prefix_limit': int,
            'inet6_flow_limit_prefix_limit': int,
            'inet6_flow_teardown_threshold_prefix_limit': int,
            'inet6_flow_teardown_timeout_prefix_limit': int,
            'inet6_flow_novalidate_prefix_limit': unicode,
        }

        _PEER_FIELDS_DATATYPE_MAP_ = {
            'group': unicode,
            'authentication_key': unicode,
            'route_reflector_client': bool,
            'nhs': bool
        }
        _PEER_FIELDS_DATATYPE_MAP_.update(
            _COMMON_FIELDS_DATATYPE_
        )

        _GROUP_FIELDS_DATATYPE_MAP_ = {
            'type': unicode,
            'apply_groups': list,
            'remove_private_as': bool,
            'multipath': bool,
            'multihop_ttl': int
        }
        _GROUP_FIELDS_DATATYPE_MAP_.update(
            _COMMON_FIELDS_DATATYPE_
        )

        _DATATYPE_DEFAULT_ = {
            unicode: u'',
            int: 0,
            bool: False,
            list: []
        }

        bgp_config = dict()

        if group:
            bgp = junos_views.junos_bgp_config_group_table(self.device)
            bgp.get(group = group)
        else:
            bgp = junos_views.junos_bgp_config_table(self.device)
            bgp.get()
            neighbor = '' # if no group is set, no neighbor should be set either
        bgp_items = bgp.items()

        peers = junos_views.junos_bgp_config_peers_table(self.device)
        peers.get() # unfortunately cannot add filters for group name of neighbor address
        peers_items = peers.items()

        bgp_neighbors = dict()

        for bgp_group_neighbor in peers_items:
            bgp_peer_address = bgp_group_neighbor[0]
            if neighbor and bgp_peer_address != neighbor:
                continue  # if filters applied, jump over all other neighbors
            bgp_group_details = bgp_group_neighbor[1]
            bgp_peer_details = {
                field: _DATATYPE_DEFAULT_.get(datatype) \
                for field, datatype in _PEER_FIELDS_DATATYPE_MAP_.iteritems() \
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
                bgp_peer_details.update({
                    key: self._convert(datatype, value, default)
                })
            prefix_limit_fields = dict()
            for elem in bgp_group_details:
                if '_prefix_limit' in elem[0] and elem[1] is not None:
                    datatype = _PEER_FIELDS_DATATYPE_MAP_.get(elem[0])
                    default = _DATATYPE_DEFAULT_.get(datatype)
                    prefix_limit_fields.update({
                        elem[0].replace('_prefix_limit', ''): self._convert(datatype, elem[1], default)
                    })
            bgp_peer_details['prefix_limit'] = build_prefix_limit(**prefix_limit_fields)
            # and all these things only because PyEZ cannto convert to a specifc datatype when retrieving config...
            group = bgp_peer_details.pop('group')
            if group not in bgp_neighbors.keys():
                bgp_neighbors[group] = dict()
            bgp_neighbors[group][bgp_peer_address] = bgp_peer_details
            if neighbor and bgp_peer_address == neighbor:
                break # found the desired neighbor

        for bgp_group in bgp_items:
            bgp_group_name = bgp_group[0]
            bgp_group_details = bgp_group[1]
            bgp_config[bgp_group_name] = {
                field: _DATATYPE_DEFAULT_.get(datatype) \
                for field, datatype in _GROUP_FIELDS_DATATYPE_MAP_.iteritems() \
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
                bgp_config[bgp_group_name].update({
                    key: self._convert(datatype, value, default)
                })
            prefix_limit_fields = dict()
            for elem in bgp_group_details:
                if '_prefix_limit' in elem[0] and elem[1] is not None:
                    datatype = _GROUP_FIELDS_DATATYPE_MAP_.get(elem[0])
                    default = _DATATYPE_DEFAULT_.get(datatype)
                    prefix_limit_fields.update({
                        elem[0].replace('_prefix_limit', ''): self._convert(datatype, elem[1], default)
                    })
            bgp_config[bgp_group_name]['prefix_limit'] = build_prefix_limit(**prefix_limit_fields)
            bgp_config[bgp_group_name]['neighbors'] = bgp_neighbors.get(bgp_group_name, {})

        return bgp_config

    def get_bgp_neighbors_detail(self, neighbor_address = ''):

        bgp_neighbors = dict()

        bgp_neighbors_table  = junos_views.junos_bgp_neighbors_table(self.device)

        bgp_neighbors_table.get(
            neighbor_address = neighbor_address
        )
        bgp_neighbors_items = bgp_neighbors_table.items()

        default_neighbor_details = {
            'up'                        : False,
            'local_as'                  : 0,
            'remote_as'                 : 0,
            'local_address'             : u'',
            'routing_table'             : u'',
            'local_address_configured'  : False,
            'local_port'                : 0,
            'remote_address'            : u'',
            'remote_port'               : 0,
            'multihop'                  : False,
            'multipath'                 : False,
            'remove_private_as'         : False,
            'import_policy'             : u'',
            'export_policy'             : u'',
            'input_messages'            : 0,
            'output_messages'           : 0,
            'input_updates'             : 0,
            'output_updates'            : 0,
            'messages_queued_out'       : 0,
            'connection_state'          : u'',
            'previous_connection_state' : u'',
            'last_event'                : u'',
            'suppress_4byte_as'         : False,
            'local_as_prepend'          : False,
            'holdtime'                  : 0,
            'configured_holdtime'       : 0,
            'keepalive'                 : 0,
            'configured_keepalive'      : 0,
            'active_prefix_count'       : 0,
            'received_prefix_count'     : 0,
            'accepted_prefix_count'     : 0,
            'suppressed_prefix_count'   : 0,
            'advertise_prefix_count'    : 0,
            'flap_count'                : 0
        }

        _OPTION_KEY_MAP_ = {
            'RemovePrivateAS': 'remove_private_as',
            'Multipath'      : 'multipath',
            'Multihop'       : 'multihop',
            'AddressFamily'  : 'local_address_configured'
            # 'AuthKey'        : 'authentication_key_set'
            # but other vendors do not specify if auth key is set
            # other options:
            # Preference, HoldTime, Ttl, LogUpDown, Refresh
        }

        for bgp_neighbor in bgp_neighbors_items:
            remote_as = int(bgp_neighbor[0])
            if remote_as not in bgp_neighbors.keys():
                bgp_neighbors[remote_as] = list()
            neighbor_details = default_neighbor_details.copy()
            neighbor_details.update(
                {elem[0]: elem[1] for elem in bgp_neighbor[1] if elem[1] is not None}
            )
            options = neighbor_details.pop('options', '')
            if isinstance(options, str):
                options_list = options.split()
                for option in options_list:
                    key = _OPTION_KEY_MAP_.get(option)
                    if key is None:
                        continue
                    neighbor_details[key] = True
            four_byte_as = neighbor_details.pop('4byte_as', 0)
            local_address = neighbor_details.pop('local_address', '')
            local_details = local_address.split('+')
            neighbor_details['local_address'] = unicode(local_details[0])
            if len(local_details) == 2:
                neighbor_details['local_port']= int(local_details[1])
            else:
                neighbor_details['local_port']=179
            neighbor_details['suppress_4byte_as'] = (remote_as != four_byte_as)
            peer_address = neighbor_details.pop('peer_address', '')
            remote_details = peer_address.split('+')
            neighbor_details['remote_address'] = unicode(remote_details[0])
            if len(remote_details) == 2:
                neighbor_details['remote_port']    = int(remote_details[1])
            else:
                neighbor_details['remote_port'] = 179
            bgp_neighbors[remote_as].append(neighbor_details)

        return bgp_neighbors


    def get_arp_table(self):

        # could use ArpTable
        # from jnpr.junos.op.phyport import ArpTable
        # and simply use it
        # but
        # we need:
        #   - filters
        #   - group by VLAN ID
        #   - hostname & TTE fields as well

        arp_table = list()

        arp_table_raw = junos_views.junos_arp_table(self.device)
        arp_table_raw.get()
        arp_table_items = arp_table_raw.items()

        for arp_table_entry in arp_table_items:
            arp_entry = {
                elem[0]: elem[1] for elem in arp_table_entry[1]
            }
            tte = arp_entry.pop('tte')
            arp_entry['age'] = tte
            # must compute age based on TTE
            arp_table.append(arp_entry)

        return arp_table

    def get_ntp_peers(self):

        ntp_table = junos_views.junos_ntp_peers_config_table(self.device)
        ntp_table.get()

        ntp_peers = ntp_table.items()

        if not ntp_peers:
            return {}

        return {unicode(peer[0]):{} for peer in ntp_peers}

    def get_ntp_stats(self):

        # NTP Peers does not have XML RPC defined
        # thus we need to retrieve raw text and parse...
        # :(

        ntp_stats = list()

        REGEX = (
            '^\s?(\+|\*|x|-)?([a-zA-Z0-9\.+-:]+)'
            '\s+([a-zA-Z0-9\.]+)\s+([0-9]{1,2})'
            '\s+(-|u)\s+([0-9h-]+)\s+([0-9]+)'
            '\s+([0-9]+)\s+([0-9\.]+)\s+([0-9\.-]+)'
            '\s+([0-9\.]+)\s?$'
        )

        ntp_assoc_output = self.device.cli('show ntp associations no-resolve')
        ntp_assoc_output_lines = ntp_assoc_output.splitlines()

        for ntp_assoc_output_line in ntp_assoc_output_lines[3:]: #except last line
            line_search = re.search(REGEX, ntp_assoc_output_line, re.I)
            if not line_search:
                continue # pattern not found
            line_groups = line_search.groups()
            try:
                ntp_stats.append({
                    'remote'        : unicode(line_groups[1]),
                    'synchronized'  : (line_groups[0] == '*'),
                    'referenceid'   : unicode(line_groups[2]),
                    'stratum'       : int(line_groups[3]),
                    'type'          : unicode(line_groups[4]),
                    'when'          : unicode(line_groups[5]),
                    'hostpoll'      : int(line_groups[6]),
                    'reachability'  : int(line_groups[7]),
                    'delay'         : float(line_groups[8]),
                    'offset'        : float(line_groups[9]),
                    'jitter'        : float(line_groups[10])
                })
            except Exception:
                continue # jump to next line

        return ntp_stats

    def get_interfaces_ip(self):

        interfaces_ip = dict()

        interface_table = junos_views.junos_ip_interfaces_table(self.device)
        interface_table.get()
        interface_table_items = interface_table.items()

        _FAMILY_VMAP_ = {
            'inet'  : u'ipv4',
            'inet6' : u'ipv6'
            # can add more mappings
        }

        for interface_details in interface_table_items:
            try:
                ip_address = interface_details[0]
                address    = unicode(ip_address.split('/')[0])
                prefix     = self._convert(int, ip_address.split('/')[-1], 0)
                interface  = unicode(interface_details[1][0][1])
                family_raw = interface_details[1][1][1]
                family     = _FAMILY_VMAP_.get(family_raw)
                if not family:
                    continue
                if interface not in interfaces_ip.keys():
                    interfaces_ip[interface] = dict()
                if family not in interfaces_ip[interface].keys():
                    interfaces_ip[interface][family] = dict()
                if address not in interfaces_ip[interface][family].keys():
                    interfaces_ip[interface][family][address] = dict()
                interfaces_ip[interface][family][address][u'prefix_length'] = prefix
            except Exception:
                continue

        return interfaces_ip

    def get_mac_address_table(self):

        mac_address_table = list()

        mac_table = junos_views.junos_mac_address_table(self.device)
        mac_table.get()
        mac_table_items = mac_table.items()

        default_values = {
            'mac'       : u'',
            'interface' : u'',
            'vlan'      : 0,
            'static'    : False,
            'active'    : True,
            'moves'     : 0,
            'last_move' : 0.0
        }

        for mac_table_entry in mac_table_items:
            mac_entry = default_values.copy()
            mac_entry.update(
                {elem[0]: elem[1] for elem in mac_table_entry[1]}
            )
            mac_address_table.append(mac_entry)

        return mac_address_table

    def get_route_to(self, destination = '', protocol = ''):

        routes = {}

        if not isinstance(destination, str):
            raise TypeError('Please specify a valid destination!')

        if not isinstance(protocol, str) or protocol.lower() not in ['static', 'bgp', 'isis']:
            raise TypeError("Protocol not supported: {protocol}.".format(
                protocol = protocol
            ))

        protocol = protocol.lower()

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
        ] # identifies the list of fileds common for all protocols

        _BOOLEAN_FIELDS_ = [
            'current_active',
            'selected_next_hop',
            'last_active'
        ] # fields expected to have boolean values

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

        try:
            routes_table.get(
                destination=destination,
                protocol=protocol
            )
        except RpcTimeoutError:
            # on devices with milions of routes
            # in case the destination is too generic (e.g.: 10/8)
            # will take very very long to determine all routes and
            # moreover will return a huge list
            raise CommandTimeoutException('Too many routes returned! Please try with a longer prefix!')
        except Exception as e:
            raise CommandErrorException('Cannot retrieve routes! Reason: {err}'.format(err = e))

        routes_items = routes_table.items()

        for route in routes_items:
            d = dict()
            next_hop = route[0]
            d = {elem[0]: elem[1] for elem in route[1]}
            destination = d.pop('destination', '')
            prefix_length = d.pop('prefix_length', 32)
            destination = '{d}/{p}'.format(
                d=destination,
                p=prefix_length
            )
            d.update({key: False for key in _BOOLEAN_FIELDS_ if d.get(key) is None})
            as_path = d.get('as_path')
            if as_path is not None:
                d['as_path'] = as_path.split(' I ')[0].replace('AS path:', '').replace('I', '').strip()
                # to be sure that contains only AS Numbers
            if d.get('inactive_reason') is None:
                d['inactive_reason'] = u''
            communities = d.get('communities')
            if communities is not None and type(communities) is not list:
                d['communities'] = [communities]
            d['next_hop'] = unicode(next_hop)
            d_keys = d.keys()
            # fields that are not in _COMMON_PROTOCOL_FIELDS_ are supposed to be protocol specific
            all_protocol_attributes = {key: d.pop(key) for key in d_keys if key not in _COMMON_PROTOCOL_FIELDS_}
            protocol_attributes = {
                key: value for key, value in all_protocol_attributes.iteritems() \
                if key in _PROTOCOL_SPECIFIC_FIELDS_.get(protocol)
            }
            d['protocol_attributes'] = protocol_attributes
            if destination not in routes.keys():
                routes[destination] = list()
            routes[destination].append(d)

        return routes

    def get_snmp_information(self):

        snmp_information = dict()

        _AUTHORIZATION_MODE_MAP_ = {
            'read-only': u'ro',
            'read-write': u'rw'
        }

        snmp_config = junos_views.junos_snmp_config_table(self.device)
        snmp_config.get()
        snmp_items = snmp_config.items()

        if not snmp_items:
            return snmp_information

        communities = list()
        for snmp_config_out in snmp_items:
            community_name = snmp_config_out[0]
            community_details = snmp_config_out[1]
            communities.append({
                c[0]: c[1] for c in community_details
            })

        snmp_information = {
            'contact': self._convert(unicode, communities[0].get('contact')),
            'location': self._convert(unicode, communities[0].get('location')),
            'chassis_id': self._convert(unicode, communities[0].get('chassis')),
            'community': {}
        }

        for snmp_entry in communities:
            name = self._convert(unicode, snmp_entry.get('name'))
            authorization = self._convert(unicode, snmp_entry.get('authorization'))
            snmp_information['community'][name] = {
                'mode': _AUTHORIZATION_MODE_MAP_.get(authorization, u''),
                'acl': u''
            }

        return snmp_information


    def get_probes_config(self):

        probes = dict()

        probes_table = junos_views.junos_rpm_probes_config_table(self.device)
        probes_table.get()
        probes_table_items = probes_table.items()

        for probe_test in probes_table_items:
            test_name = unicode(probe_test[0])
            test_details = {
                p[0]: p[1] for p in probe_test[1]
            }
            probe_name = self._convert(unicode, test_details.pop('probe_name'))
            target = self._convert(unicode, test_details.pop('target', ''))
            test_interval = self._convert(int, test_details.pop('test_interval', '0'))
            probe_count = self._convert(int, test_details.pop('probe_count', '0'))
            probe_type = self._convert(unicode, test_details.pop('probe_type', ''))
            source = self._convert(unicode, test_details.pop('source_address', ''))
            if probe_name not in probes.keys():
                probes[probe_name] = dict()
            probes[probe_name][test_name] = {
                'probe_type'    : probe_type,
                'target'        : target,
                'source'        : source,
                'probe_count'   : probe_count,
                'test_interval' : test_interval
            }

        return probes


    def get_probes_results(self):

        probes_results = dict()

        probes_results_table = junos_views.junos_rpm_probes_results_table(self.device)
        probes_results_table.get()
        probes_results_items = probes_results_table.items()

        for probe_result in probes_results_items:
            probe_name = unicode(probe_result[0])
            test_results = {
                p[0]: p[1] for p in probe_result[1]
            }
            for test_param_name, test_param_value in test_results.iteritems():
                if isinstance(test_param_value, float):
                    test_results[test_param_name] = test_param_value * 1e-3 # convert from useconds to mseconds
            test_name = test_results.pop('test_name', '')
            source = test_results.get('source', u'')
            if source is None:
                test_results['source'] = u''
            if probe_name not in probes_results.keys():
                probes_results[probe_name] = dict()
            probes_results[probe_name][test_name] = test_results

        return probes_results

    def traceroute(self, destination, source='', ttl=0, timeout=0):

        traceroute_result = dict()

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
        rpc_reply = self.device._conn.rpc(traceroute_rpc)._NCElement__doc # make direct RPC call via NETCONF
        traceroute_results = rpc_reply.find('.//traceroute-results')

        traceroute_success = traceroute_results.find('traceroute-success')
        traceroute_failure = self._find_txt(traceroute_results, 'traceroute-failure', '')
        error_message = self._find_txt(traceroute_results, 'rpc-error/error-message', '')

        error = ''

        if traceroute_failure and error_message:
            return {'error': '{}: {}'.format(traceroute_failure, error_message)}

        traceroute_result['success'] = dict()
        for hop in traceroute_results.findall('hop'):
            ttl_value = self._convert(int, self._find_txt(hop, 'ttl-value'), 1)
            if ttl_value not in traceroute_result['success']:
                traceroute_result['success'][ttl_value] = {'probes': {}}
            for probe in hop.findall('probe-result'):
                probe_index = self._convert(int, self._find_txt(probe, 'probe-index'), 0)
                ip_address = unicode(self._find_txt(probe, 'ip-address', u'*'))
                host_name = unicode(self._find_txt(probe, 'host-name', u'*'))
                rtt = self._convert(float, self._find_txt(probe, 'rtt'), 0) * 1e-3 # ms
                traceroute_result['success'][ttl_value]['probes'][probe_index] = {
                    'ip_address': ip_address,
                    'host_name': host_name,
                    'rtt': rtt
                }

        return traceroute_result

    def get_users(self):

        users = dict()

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
            level = _JUNOS_CLASS_CISCO_PRIVILEGE_LEVEL_MAP.get(user_class, 0)
            user_details.update({
                'level': level
            })
            user_details['sshkeys'] = [
                user_details.pop(key) for key in ['ssh_rsa', 'ssh_dsa', 'ssh_ecdsa'] if user_details.get(key, '')
            ]
            users[username] = user_details

        return users
