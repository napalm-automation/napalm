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

from utils import junos_views
from base import NetworkDriver

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import ConfigLoadError
from exceptions import ReplaceConfigException, MergeConfigException

class JunOSDriver(NetworkDriver):

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.device = Device(hostname, user=username, password=password)
        self.config_replace = False

    def open(self):
        self.device.open()
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
            return diff

    def commit_config(self):
        self.device.cu.commit()

    def discard_config(self):
        self.device.cu.rollback(rb_id=0)

    def rollback(self):
        self.device.cu.rollback(rb_id=1)
        self.commit_config()

    def get_facts(self):

        output = self.device.facts

        uptime = None
        if 'RE0' in output:
          uptime = output['RE0']['up_time']

        interfaces = junos_views.junos_iface_table(self.device)
        interfaces.get()
        interface_list = interfaces.keys()

        return {
            'vendor': u'Juniper',
            'model': output['model'],
            'serial_number': output['serialnumber'],
            'os_version': output['version'],
            'hostname': output['hostname'],
            'fqdn': output['fqdn'],
            'uptime': uptime,
            'interface_list': interface_list
        }

    def get_interfaces(self):

        interfaces = junos_views.junos_iface_table(self.device)
        interfaces.get()

        # convert all the tuples to our dict structure
        # i don't know how to do this any better...
        result = {}
        [result.update({iface:dict(interfaces[iface])}) for iface in interfaces.keys()]

        return result

    def get_bgp_neighbors(self):

        # init result dict
        result = {}

        instances = junos_views.junos_route_instance_table(self.device)
        instances.get()
        vrfs = instances.keys()

        for vrf in vrfs:
            if not vrf.startswith('__'):

                # init result dict for this vrf
                result[vrf] = {
                    'peers': {},
                    'router_id': None,
                    'local_as': None,
                }

                # fetch sessions for vrf
                bgp = junos_views.junos_bgp_table(self.device)
                bgp.get(instance=vrf)

                # assemble result dict 
                bgp_result = {}
                [bgp_result.update({neigh:dict(bgp[neigh])}) for neigh in bgp.keys()]
                result[vrf]['peers'] = bgp_result

        return result

    def get_lldp_neighbors(self):

        lldp = junos_views.junos_lldp_table(self.device)
        lldp.get()

        result = lldp.items()

        return result
