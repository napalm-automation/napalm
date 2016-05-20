# Copyright 2016 Dravetech AB. All rights reserved.
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

# std libs
import xmltodict
import json
import pan.xapi
import os.path
import xml.etree
import requests
import requests_toolbelt
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime
import time

# local modules
import napalm_base.exceptions
import napalm_base.helpers
from napalm_base.utils.string_parsers import convert_uptime_string_seconds
from napalm_base.exceptions import ConnectionException, ReplaceConfigException,\
                                   MergeConfigException

from napalm_base.base import NetworkDriver
from netmiko import ConnectHandler


class PANOSDriver(NetworkDriver):

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.loaded = False
        self.changed = False
        self.device = None
        self.ssh_device = None
        self.ssh_connection = False
        self.merge_config = False

        if optional_args is None:
            optional_args = {}
        self.port = optional_args.get('port', 22)

    def open(self):
        try:
            self.device = pan.xapi.PanXapi(hostname=self.hostname,
                                           api_username=self.username,
                                           api_password=self.password)
        except ConnectionException, e:
            raise ConnectionException(e.message)

    def _open_ssh(self):
        try:
            self.ssh_device = ConnectHandler(device_type='paloalto_panos',
                                             ip=self.hostname,
                                             username=self.username,
                                             password=self.password,
                                             port=self.port)
        except ConnectionException, e:
            raise ConnectionException(e.message)

        self.ssh_connection = True

    def close(self):
        self.device = None
        if self.ssh_connection:
            self.ssh_device.disconnect()
            self.ssh_connection = False
            self.ssh_device = None

    def _import_file(self, filename):
        key = self.device.keygen()

        params = {
            'type': 'import',
            'category': 'configuration',
            'key': key
        }

        path = os.path.basename(filename)

        mef = requests_toolbelt.MultipartEncoder(
            fields={
                'file': (path, open(filename, 'rb'), 'application/octet-stream')
            }
        )

        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        url = 'https://{0}/api/'.format(self.hostname)
        request = requests.post(
            url,
            verify=False,
            params=params,
            headers={'Content-Type': mef.content_type},
            data=mef
        )

        # if something goes wrong just raise an exception
        request.raise_for_status()
        response = xml.etree.ElementTree.fromstring(request.content)

        if response.attrib['status'] == 'error':
            return False
        else:
            return path

    def load_replace_candidate(self, filename=None, config=None):
        if config:
            raise ReplaceConfigException("This method requires a config file.")

        elif filename:
            if self.loaded is False:
                if self._save_backup() is False:
                    raise ReplaceConfigException('Error while storing backup config')

            path = self._import_file(filename)
            if path is False:
                raise ReplaceConfigException("Error while trying to move the config file to the device.")

            # Let's load the config.
            cmd = '<load><config><from>{0}</from></config></load>'.format(path)
            self.device.op(cmd=cmd)

            if self.device.status == 'success':
                self.loaded = True
            else:
                raise ReplaceConfigException('Error while loading config from {0}').format(path)

        else:
            raise ReplaceConfigException("This method requires a config file.")

    def _get_file_content(self, filename):
        try:
            with open(filename, 'r') as f:
                content = f.read()
        except IOError:
            raise MergeConfigException('Error while opening {0}. Make sure '
                                       'filename is correct.'.format(filename))
        return content

    def _send_merge_commands(self, config, file_config):
        """
        Netmiko is being used to push set commands.
        """
        if self.loaded is False:
            if self._save_backup() is False:
                raise MergeConfigException('Error while storing backup '
                                           'config.')
        if self.ssh_connection is False:
            self._open_ssh()

        if file_config:
            if isinstance(config, str):
                config = config.splitlines()
        else:
            if isinstance(config, str):
                config = config.split()
            elif isinstance(config, unicode):
                config = str(config).split()

        self.ssh_device.send_config_set(config)
        self.loaded = True
        self.merge_config = True

    def load_merge_candidate(self, filename=None, config=None):
        if filename:
            file_config = True
            content = self._get_file_content(filename)
            config = content.splitlines()
            self._send_merge_commands(config, file_config)

        elif config:
            file_config = False
            self._send_merge_commands(config, file_config)

        else:
            raise MergeConfigException('You must provide either a file '
                                       'or a set-format string')

    def compare_config(self):
        """
        Netmiko is being used to obtain config diffs because pan-python
        doesn't support the needed command.
        """
        if self.ssh_connection is False:
            self._open_ssh()

        self.ssh_device.exit_config_mode()
        diff = self.ssh_device.send_command("show config diff")
        return diff.strip()

    def _save_backup(self):
        self.backup_file = 'config_{0}.xml'.format(str(datetime.now().date()).replace(' ', '_'))
        backup_command = '<save><config><to>{0}</to></config></save>'.format(self.backup_file)

        self.device.op(cmd=backup_command)
        if self.device.status == 'success':
            return True
        else:
            return False

    def commit_config(self):
        """
        Netmiko is being used to commit the configuration because it takes
        a better care of results compared to pan-python.
        """
        if self.loaded:
            if self.ssh_connection is False:
                self._open_ssh()
            try:
                self.ssh_device.commit()
                time.sleep(3)
                self.loaded = False
                self.changed = True
            except:
                if self.merge_config:
                    raise MergeConfigException('Error while commiting config')
                else:
                    raise ReplaceConfigException('Error while commiting config')
        else:
            raise ReplaceConfigException('No config loaded.')

    def discard_config(self):
        if self.loaded:
            discard_cmd = '<load><config><from>{0}</from></config></load>'.format(self.backup_file)
            self.device.op(cmd=discard_cmd)

            if self.device.status == 'success':
                self.loaded = False
                self.merge_config = False
            else:
                raise ReplaceConfigException("Error while loading backup config.")

    def rollback(self):
        """
        Netmiko is being used to commit the rollback configuration because
        it takes a better care of results compared to pan-python.
        """
        if self.changed:
            rollback_cmd = '<load><config><from>{0}</from></config></load>'.format(self.backup_file)
            self.device.op(cmd=rollback_cmd)
            time.sleep(5)

            if self.ssh_connection is False:
                self._open_ssh()
            try:
                self.ssh_device.commit()
                self.loaded = False
                self.changed = False
                self.merge_config = False
            except:
                ReplaceConfigException("Error while loading backup config")

    def get_facts(self):
        facts = {}

        try:
            self.device.op(cmd='<show><system><info></info></system></show>')
            system_info_xml = xmltodict.parse(self.device.xml_root())
            system_info_json = json.dumps(system_info_xml['response']['result']['system'])
            system_info = json.loads(system_info_json)
        except AttributeError:
            system_info = {}

        try:
            self.device.op(cmd='<show><interface>all</interface></show>')
            interfaces_xml = xmltodict.parse(self.device.xml_root())
            interfaces_json = json.dumps(interfaces_xml['response']['result'])
            interfaces = json.loads(interfaces_json)
        except AttributeError:
            interfaces = {}

        if system_info:
            facts['hostname'] = system_info['hostname']
            facts['vendor'] = unicode('Palo Alto Networks')
            facts['uptime'] = int(convert_uptime_string_seconds(system_info['uptime']))
            facts['os_version'] = system_info['sw-version']
            facts['serial_number'] = system_info['serial']
            facts['model'] = system_info['model']
            facts['fqdn'] = unicode('N/A')
            facts['interface_list'] = []

        for element in interfaces:
            for entry in interfaces[element]:
                for intf in interfaces[element][entry]:
                    if intf['name'] not in facts['interface_list']:
                        facts['interface_list'].append(intf['name'])
        return facts

    def get_interfaces(self):
        interface_dict = {}
        interface_list = self.get_facts()['interface_list']

        for intf in interface_list:
            interface = {}
            cmd = "<show><interface>{0}</interface></show>".format(intf)

            try:
                self.device.op(cmd=cmd)
                interface_info_xml = xmltodict.parse(self.device.xml_root())
                interface_info_json = json.dumps(interface_info_xml['response']['result']['hw'])
                interface_info = json.loads(interface_info_json)
            except AttributeError:
                interface_info = {}

            name = interface_info.get('name')
            state = interface_info.get('state')

            if state == 'up':
                interface['is_up'] = True
                interface['is_enabled'] = True
            else:
                interface['is_up'] = False
                interface['is_enabled'] = False

            interface['last_flapped'] = -1.0
            interface['speed'] = interface_info.get('speed')
            # Quick fix for loopback interfaces
            if interface['speed'] == '[n/a]':
                interface['speed'] = 0
            else:
                interface['speed'] = int(interface['speed'])
            interface['mac_address'] = interface_info.get('mac')
            interface['description'] = unicode('N/A')
            interface_dict[name] = interface

        return interface_dict
