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
from utils import string_parsers

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
        match_sh_ver = re.search('Cisco IOS XR Software, Version (.*)\nCopyright .*\n(.*) uptime is (.*)\nSystem .*\n(.* Series) ', sh_ver, re.DOTALL)
        os_version = match_sh_ver.group(1)
        hostname = match_sh_ver.group(2)
        fqdn = match_sh_ver.group(2)
        uptime = string_parsers.convert_uptime_string_seconds(match_sh_ver.group(3))
        model = match_sh_ver.group(4)
        serial_number = None

        # todo
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

                match1 = re.search('(.*) is (.*), line protocol is (.*)',line)
                if match1 is not None:
                    interface_name = match1.group(1)
                    is_enabled = match1.group(2)
                    is_up = match1.group(3)

                match2 = re.search('\(bia (.*)\)',line)
                if match2 is not None:
                    mac_address = match2.group(1)

                match3 = re.search('Description: (.*)$', line)
                if match3 is not None:
                    description = match3.group(1)

                match4 = re.search('Full-duplex, (\d*)', line)
                if match4 is not None:
                    speed = match4.group(1)

            result[interface_name] = {
                'is_enabled': is_enabled,
                'is_up': is_up,
                'mac_address': mac_address,
                'description': description,
                'speed': speed,
                'last_flapped': None,
            }

        return result

    # def get_bgp_neighbors(self):
    #
    #     # init result dict
    #     result = {}
    #     # todo vrfs
    #     result['default'] = {}
    #     result['default']['peers'] = {}
    #
    #     # fetch sh ip bgp output
    #     sh_bgp = self.device.show_ip_bgp_neighbors()
    #     # split per bgp neighbor
    #     bgp_list = sh_bgp.rstrip().split('\n\nBGP')
    #     # for each neigh...
    #     for neighbor in bgp_list:
    #
    #         peer_lines = neighbor.split('\n')
    #
    #         # init variables
    #         is_up = None
    #         is_enabled = None
    #         uptime = None
    #         description = None
    #         received_prefixes = None
    #         sent_prefixes = None
    #         accepted_prefixes = None
    #         remote_as = None
    #
    #         for line in peer_lines:
    #
    #             match1 = re.search('(BGP)? neighbor is (.*)',line)
    #             if match1 is not None:
    #                 peer_ip = match1.group(2)
    #
    #             match2 = re.search('BGP state = (.*)',line)
    #             if match2 is not None:
    #                 if match2.group(1) == 'Active':
    #                     is_up = False
    #                     is_enabled = True
    #
    #             match3 = re.search('Description: (.*)$',line)
    #             if match3 is not None:
    #                 description = match3.group(1)
    #
    #             match4 = re.search('Remote AS (\d*)',line)
    #             if match4 is not None:
    #                 remote_as = int(match4.group(1))
    #
    #
    #         result['default']['peers'][peer_ip] = {
    #             'is_up': is_up,
    #             'is_enabled': is_enabled,
    #             'uptime': uptime,
    #             'description': description,
    #             'received_prefixes': received_prefixes,
    #             'sent_prefixes': sent_prefixes,
    #             'accepted_prefixes': accepted_prefixes,
    #             'remote_as': remote_as,
    #         }
    #
    #     return result

    def get_lldp_neighbors(self):

        # init result dict
        result = {}

        # fetch sh ip bgp output
        sh_lldp = self.device.show_lldp_neighbors()
        # remove everything before
        sh_lldp = sh_lldp.split('Hold-time  Capability     Port ID')[1]
        # remove everything after
        sh_lldp = sh_lldp.split('Total')[0]
        # remove newlines 
        sh_lldp = sh_lldp.strip()
        # split remaining lines (one per lldp neigh entry)
        lldp_line = sh_lldp.split('\n')

        for line in lldp_line:

            match1 = re.search('^([^\s]*)\s+([^\s]*)\s+(\d*)\s+\w\s+([^\s]*)$',line)
            if match1 is not None:
                local_port = match1.group(2)
                lldp_neigh = {
                    'hostname': match1.group(1),
                    'port': match1.group(4),
                }

                if local_port in result:
                    result[local_port].append( lldp_neigh )
                else:
                    result[local_port] = [ lldp_neigh ]

        return result

