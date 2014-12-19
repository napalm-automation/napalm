from pyEOS import EOS

from base import NetworkDriver
from objects.facts import Facts
from objects.bgp import BGPInstance, BGPNeighbor

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