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
            bgp_neigbor_data[instance] = dict(peers=dict())
            for neighbor, neighbor_data in bgp_neigbors.get(instance=instance).items():
                structured_neighbor_data = {k: v for k, v in neighbor_data}
                peer = neighbor.split('+')[0]
                bgp_neigbor_data[instance]['peers'][peer] = dict()
                for key in ['local_as', 'remote_as', 'is_up', 'is_enabled', 'description', 'remote_id']:
                    bgp_neigbor_data[instance]['peers'][peer][key] = structured_neighbor_data[key]
                if 'router_id' not in bgp_neigbor_data[instance].keys():
                    # we only need to set this once
                    bgp_neigbor_data[instance]['router_id'] = structured_neighbor_data['local_id']
                if structured_neighbor_data['is_up'] is False:
                    # if the session is down there is no table data to parse
                    continue
                elif isinstance(structured_neighbor_data['tables'], list):
                    for idx, table in enumerate(structured_neighbor_data['tables']):
                        family = self._get_address_family(table)
                        bgp_neigbor_data[instance]['peers'][peer][family] = dict()
                        for metric in ['received_prefixes', 'accepted_prefixes', 'sent_prefixes']:
                            bgp_neigbor_data[instance]['peers'][peer][family][metric] = structured_neighbor_data[metric][idx]
                else:
                    family = self._get_address_family(structured_neighbor_data['tables'])
                    bgp_neigbor_data[instance]['peers'][peer][family] = dict()
                    bgp_neigbor_data[instance]['peers'][peer][family]['received_prefixes'] = structured_neighbor_data['received_prefixes']
                    bgp_neigbor_data[instance]['peers'][peer][family]['accepted_prefixes'] = structured_neighbor_data['accepted_prefixes']
                    bgp_neigbor_data[instance]['peers'][peer][family]['sent_prefixes'] = structured_neighbor_data['sent_prefixes']
            for neighbor, uptime in uptime_table.get(instance=instance).items():
                bgp_neigbor_data[instance]['peers'][neighbor]['uptime'] = uptime[0][1]
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
