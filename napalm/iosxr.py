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
        self.replace = False

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
            return self.device.compare_replace_config().strip()
        else:
            return self.device.compare_config().strip()

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

        for line in sh_ver.splitlines():
            if 'Cisco IOS XR Software' in line:
                os_version = line.split()[-1]
            elif 'uptime' in line:
                uptime = string_parsers.convert_uptime_string_seconds(line)
                hostname = line.split()[0]
                fqdn = line.split()[0]
            elif 'Series' in line:
                model = ' '.join(line.split()[1:3])

        interface_list = list()

        for x in self.device.show_interface_description().splitlines()[3:-1]:
            if '.' not in x:
                interface_list.append(x.split()[0])

        result = {
            'vendor': u'Cisco',
            'os_version': unicode(os_version),
            'hostname': unicode(hostname),
            'uptime': uptime,
            'model': unicode(model),
            'serial_number': u'',
            'fqdn': unicode(fqdn),
            'interface_list': interface_list,
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
                description = ''
                if 'line protocol' in line:
                    lp = line.split()
                    interface_name = lp[0]
                    is_enabled = lp[2] == 'up,'
                    is_up = lp[6] == 'up'
                elif 'bia' in line:
                    mac_address = line.split()[-1].replace(')', '')
                elif 'Description' in line:
                    description = ' '.join(line.split()[1:])
                elif 'BW' in line:
                    speed = int(line.split()[4])/1000
            result[interface_name] = {
                'is_enabled': is_enabled,
                'is_up': is_up,
                'mac_address': unicode(mac_address),
                'description': unicode(description),
                'speed': speed,
                'last_flapped': -1.0,
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
        lldp = {}

        # fetch sh ip bgp output
        sh_lldp = self.device.show_lldp_neighbors().splitlines()[5:-3]

        for n in sh_lldp:
            local_interface = n.split()[1]
            if local_interface not in lldp.keys():
                lldp[local_interface] = list()

            lldp[local_interface].append(
                {
                    'hostname': unicode(n.split()[0]),
                    'port': unicode(n.split()[4]),
                }
            )

        return lldp
