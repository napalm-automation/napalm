# Copyright 2014 Spotify AB. All rights reserved.
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

from pyEOS import EOS

from base import NetworkDriver
from objects.facts import Facts
from objects.bgp import BGPInstance, BGPNeighbor
from objects.interface import Interface, InterfaceStatus
from objects.lldp import LLDPNeighbor

def _process_interface(interface):
    name = interface['name']

    if interface['interfaceStatus'] == u'notconnect':
        status = InterfaceStatus.OPER_DOWN
    elif interface['interfaceStatus'] == u'connected':
        status = InterfaceStatus.UP
    elif interface['interfaceStatus'] == u'disabled':
        status = InterfaceStatus.ADMIN_DOWN
    else:
        raise Exception('Unknown interface status: %s, %s' % (name, interface['interfaceStatus']))

    return Interface(
        name,
        interface['bandwidth'],
        status
    )


class EOSDriver(NetworkDriver):

    def __init__(self, hostname, user, password):
        self.hostname = hostname
        self.user = user
        self.password = password
        self.device = EOS(hostname, user, password, use_ssl=True)

    def open(self):
        self.device.open()

    def close(self):
        self.device.close()

    def load_candidate_config(self, filename=None, config=None):
        self.device.load_candidate_config(filename=filename, config=config)

    def compare_config(self):
        return self.device.compare_config()

    def replace_config(self):
        self.device.replace_config()

    def rollback(self):
        self.device.rollback()

    def get_facts(self):
        hostname = self.device.show_hostname()
        sv = self.device.show_version()

        return Facts(
            vendor = 'Arista',
            hostname = hostname['hostname'],
            fqdn = hostname['fqdn'],
            hardware_model = sv['modelName'],
            serial_number = sv['serialNumber'],
            os_version = sv['version'],
            interfaces = self.device.show_interfaces()['interfaces'].keys(),
        )

    def get_bgp_neighbors(self):
        output = self.device.show_ip_bgp_summary_vrf_all()

        bgp_table = list()

        for vrf, bgp in output['vrfs'].iteritems():
            list_peers = list()

            for peer, values in bgp['peers'].iteritems():
                p = BGPNeighbor(
                    ip = peer,
                    remote_as = int(values['asn']),
                    state = values['peerState'],
                    time = int(values['upDownTime']),
                    prefixes_accepted = int(values['prefixAccepted']),
                )
                list_peers.append(p)

            bgp_instance = BGPInstance(
                vrf = vrf,
                asn = int(bgp['asn']),
                router_id = bgp['routerId'],
                bgp_neighbors = list_peers,
            )
            bgp_table.append(bgp_instance)
        return bgp_table

    def get_interface(self, name):
        interfaces = self.device.show_interfaces()
        interface = interfaces['interfaces'][name]
        return _process_interface(interface)

    def get_interfaces(self):
        interfaces = list()

        for interface in self.device.show_interfaces()['interfaces'].values():
            interfaces.append(_process_interface(interface))

        return interfaces

    def get_lldp_neighbors(self):
        neighbors = list()

        for n in self.device.show_lldp_neighbors()['lldpNeighbors']:
            neighbors.append(
                LLDPNeighbor(
                    n['neighborDevice'],
                    n['port'],
                    n['neighborPort']
                )
            )

        return neighbors