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

import StringIO

from base import NetworkDriver
from utils import string_parsers

from pycsco.nxos.device import Device
from pycsco.nxos.utils.file_copy import FileCopy
from pycsco.nxos.utils import install_config
from pycsco.nxos.utils import nxapi_lib
from pycsco.nxos.error import DiffError, FileTransferError, CLIError

from exceptions import MergeConfigException, ReplaceConfigException

BACKUP_FILE = 'config_' + str(datetime.now()).replace(' ', '_')

class IOSXRDriver(NetworkDriver):

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.device = Device(username=username,
                             password=password,
                             ip=hostname)
        self.replace = True
        self.diff = None
        self.fc = None
        self.changed = False

    def open(self):
        pass

    def close(self):
        pass

    def _get_config_file(self, filename=None, config=None):
        if filename is None:
            config_file = StringIO.StringIO()
            config_file.write(config)
        else:
            config_file = open(filename, "r")

        return config_file

    def load_replace_candidate(self, filename=None, config=None):
        self.replace = True

        cfg_file_path = self._get_config_file(filename, config)
        self.fc = FileCopy(self.device, cfg_file_path)
        if not self.fc.file_already_exists():
            try:
                self.fc.transfer_file()
            except FileTransferError as fte:
                raise ReplaceConfigException(fte.message)

        try:
            self.diff = install_config.get_diff(self.device, self.fc.dst)
        except DiffError as de:
            raise ReplaceConfigException(de.message)

    def load_merge_candidate(self, filename=None, config=None):
        self.replace = False
        if filename is not None:
            with open(filename) as f:
                self.diff = f.read()
        else:
            self.diff = config

        ## doesn't check if there's an error

    def compare_config(self):
        return self.diff

    def _commit_merge(self):
        commands = self.merge_candidate.splitlines()
        for command in commands:
            if command:
                try:
                    self.device.config(command)
                except CLIError as ce:
                    raise MergeConfigException(ce.message)

    def commit_config(self):
        install_config.save_config(self.device, BACKUP_FILE)
        if not self.replace:
            self._commit_merge()
        else:
            install_config.rollback(self.device, self.fc.dst)

        self.changed = True

    def _delete_file(filename):
        self.device.config('terminal dont-ask')
        self.device.config('delete {}'.format(filename))
        self.device.config('no terminal dont-ask')

    def discard_config(self):
        if self.replace:
            self._delete_file(self.fc.dst)

        self.diff = None

    def rollback(self):
        if self.changed:
            install_config.rollback(self.device, BACKUP_FILE)

    def get_facts(self):
        results = {}
        facts_dict = nxapi_lib.get_facts(self.device)
        results['uptime'] = 'N/A'
        results['vendor'] = 'Cisco'
        results['os_version'] = facts_dict.get('os')
        results['serial_number'] = 'N/A'
        results['model'] = facts_dict.get('platform')
        results['hostname'] = facts_dict.get('hostname')
        results['fqdn'] = 'N/A'
        iface_list = results[interface_list] = []

        intf_dict = nxapi_lib.get_interfaces_dict(self.device)
        for intf_list in intf_dict.values():
            for intf in intf_list:
                iface_list.append(intf)

        return results

    def get_interfaces(self):
        results = {}
        intf_dict = nxapi_lib.get_interfaces_dict(self.device)
        for intf_list in intf_dict.values():
            for intf in intf_list:
                intf_info = nxapi.get_interface(self.device, intf)
                formatted_info = results[intf] = {}
                formatted_info['is_up'] = 'up' in intf_info.get('state', intf_info.get('admin_state', '')).lower()
                formatted_info['is_enabled'] = 'up' in intf_info.get('admin_state').lower()
                formatted_info['description'] = intf_info.get('description')
                formatted_info['last_flapped'] = 'N/A'
                formatted_info['speed'] = intf_info.get('speed', 'N/A')
                formatted_info['mac_address'] = intf_info.get('mac_address', 'N/A')

        return results

    def get_lldp_neighbors(self):
        results = {}
        neighbor_list = nxapi_lib.get_neighbors(self.device, 'lldp')
        for neighbor in neighbor_list:
            local_iface = neighbor.get('local_interface')
            if neighbor.get(local_iface) is None:
                results[local_iface] = {}

            neighbor_dict = results[local_iface]
            neighbor_dict['hostname'] = neighbor.get('neighbor')
            neighbor_dict['port'] = neighbor.get('neighbor_interface')

        return results
