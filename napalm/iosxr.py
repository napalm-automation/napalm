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
from base import NetworkDriver

from pyIOSXR import IOSXR
from pyIOSXR.exceptions import InvalidInputError, XMLCLIError

from exceptions import MergeConfigException, ReplaceConfigException


class IOSXRDriver(NetworkDriver):

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.device = IOSXR(hostname, username, password)
        self.pending_changes = False

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
            return self.device.compare_replace_config()
        else:
            return self.device.compare_config()

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
        match_sh_ver = re.search('Cisco IOS XR Software, Version (.*)\n.*\n(.*) uptime is (.*)\n.*\n(.*) Chassis .*\n', sh_ver)

        os_version = match_sh_ver.group(1)
        hostname = match_sh_ver.group(2)
        uptime = match_sh_ver.group(3)
        model = match_sh_ver.group(4)

        sh_admin_ver = self.device.show_admin_version()
        match_sh_admin_ver = re.search('SN: (.*)\n', sh_admin_ver)

        serial_number = match_sh_admin_ver.group(1)

        # todo 
        fqdn = None
        interface_list = []

        result = {
            'vendor': u'Cisco',
            'os_version': os_version,
            'hostname': hostname,
            'uptime': uptime,
            'model': model,
            'serial_number': serial_number,
            'fqdn': fqdn,
            'interface_list': [],
        }

        return result

