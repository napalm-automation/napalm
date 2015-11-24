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

import tempfile
import re
from datetime import datetime


from base import NetworkDriver

from pycsco.nxos.device import Device as NXOSDevice
from pycsco.nxos.utils.file_copy import FileCopy
from pycsco.nxos.utils import install_config
from pycsco.nxos.utils import nxapi_lib
from pycsco.nxos.error import DiffError, FileTransferError, CLIError

from exceptions import MergeConfigException, ReplaceConfigException

def strip_trailing(string):
    lines = list(x.rstrip(' ') for x in string.splitlines())
    return '\n'.join(lines)


class NXOSDriver(NetworkDriver):

    def __init__(self, hostname, username, password, timeout=60):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.device = NXOSDevice(username=username,
                             password=password,
                             ip=hostname,
                             timeout=timeout)
        self.replace = True
        self.loaded = False
        self.fc = None
        self.changed = False

    def open(self):
        pass

    def close(self):
        if self.changed:
            self._delete_file(self.backup_file)

    def load_replace_candidate(self, filename=None, config=None):
        self.replace = True
        self.loaded = True

        if filename is None:
            temp_file = tempfile.NamedTemporaryFile()
            temp_file.write(config)
            temp_file.flush()
            cfg_file_path = temp_file.name
        else:
            cfg_file_path = filename

        self.fc = FileCopy(self.device, cfg_file_path)
        if not self.fc.file_already_exists():
            try:
                self.fc.transfer_file()
            except FileTransferError as fte:
                raise ReplaceConfigException(fte.message)

    def load_merge_candidate(self, filename=None, config=None):
        self.replace = False
        self.loaded = True
        if filename is not None:
            with open(filename, "r") as f:
                self.merge_candidate = f.read()
        else:
            self.merge_candidate = config

    def compare_config(self):
        if self.loaded:
            if not self.replace:
                return self.merge_candidate
            messy_diff = install_config.get_diff(self.device, self.fc.dst)
            clean_diff = strip_trailing(messy_diff)
            return clean_diff

        return ''

    def _commit_merge(self):
        commands = self.merge_candidate.splitlines()
        command_string = ';'.join(list(' %s ' % x.strip() for x in commands))
        self.device.config(command_string)

    def commit_config(self):
        if self.loaded:
            self.backup_file = 'config_' + str(datetime.now()).replace(' ', '_')
            install_config.save_config(self.device, self.backup_file)
            if self.replace:
                if install_config.rollback(self.device, self.fc.dst) is False:
                    raise ReplaceConfigException
            else:
                try:
                    self._commit_merge()
                except Exception as e:
                    raise MergeConfigException(str(e))

            self.changed = True
            self.loaded = False
        else:
            raise ReplaceConfigException('No config loaded.')

    def _delete_file(self, filename):
        self.device.show('terminal dont-ask', text=True)
        self.device.show('delete {}'.format(filename), text=True)
        self.device.show('no terminal dont-ask', text=True)

    def discard_config(self):
        if self.loaded and self.replace:
            try:
                self._delete_file(self.fc.dst)
            except CLIError:
                pass

        self.loaded = False

    def rollback(self):
        if self.changed:
            install_config.rollback(self.device, self.backup_file)
            self.changed = False

    def get_facts(self):
        results = {}
        facts_dict = nxapi_lib.get_facts(self.device)
        results['uptime'] = -1 # not implemented
        results['vendor'] = unicode('Cisco')
        results['os_version'] = facts_dict.get('os')
        results['serial_number'] = unicode('N/A')
        results['model'] = facts_dict.get('platform')
        results['hostname'] = facts_dict.get('hostname')
        results['fqdn'] = unicode('N/A')
        iface_list = results['interface_list'] = []

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
                intf_info = nxapi_lib.get_interface(self.device, intf)
                formatted_info = results[intf] = {}
                formatted_info['is_up'] = 'up' in intf_info.get('state', intf_info.get('admin_state', '')).lower()
                formatted_info['is_enabled'] = 'up' in intf_info.get('admin_state').lower()
                formatted_info['description'] = unicode(intf_info.get('description'))
                formatted_info['last_flapped'] = -1.0 #not implemented

                speed = intf_info.get('speed', '0')
                try:
                    speed = int(re.sub(r'[^\d]', '', speed).strip())
                except ValueError:
                    speed = -1

                formatted_info['speed'] = speed
                formatted_info['mac_address'] = unicode(intf_info.get('mac_address', 'N/A'))

        return results

    def get_lldp_neighbors(self):
        results = {}
        neighbor_list = nxapi_lib.get_neighbors(self.device, 'lldp')
        for neighbor in neighbor_list:
            local_iface = neighbor.get('local_interface')
            if neighbor.get(local_iface) is None:
                if local_iface not in results:
                    results[local_iface] = []

            neighbor_dict = {}
            neighbor_dict['hostname'] = unicode(neighbor.get('neighbor'))
            neighbor_dict['port'] = unicode(neighbor.get('neighbor_interface'))

            results[local_iface].append(neighbor_dict)

        return results

    def get_checkpoint_file(self):
        return install_config.get_checkpoint(self.device)
