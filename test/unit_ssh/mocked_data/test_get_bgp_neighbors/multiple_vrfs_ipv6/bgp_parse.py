from __future__ import print_function, unicode_literals
import re

"""
        {
        "global": {
            "router_id": "1.1.1.103", 
            "peers": {
                "10.99.99.2": {
                    "is_enabled": true, 
                    "uptime": -1, 
                    "remote_as": 22, 
                    "address_family": {
                        "ipv4": {
                            "sent_prefixes": -1, 
                            "accepted_prefixes": -1, 
                            "received_prefixes": -1
                        }
                    }, 
                    "remote_id": "0.0.0.0", 
                    "local_as": 22, 
                    "is_up": false, 
                    "description": ""
                 }
            }
        }
"""

def bgp_summary_parser(bgp_summary):
    """
BGP summary information for VRF RED1, address family IPv4 Unicast
BGP router identifier 10.1.0.16, local AS number 65535
BGP table version is 361, IPv4 Unicast config peers 2, capable peers 2
13 network entries and 17 paths using 2224 bytes of memory
BGP attribute entries [4/576], BGP AS path entries [1/14]
BGP community entries [295/10792], BGP clusterlist entries [0/0]
13 received paths for inbound soft reconfiguration
4 identical, 9 modified, 0 filtered received paths using 72 bytes

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.2.1.14       4    10  472516  472238      361    0    0     3w1d 9
10.1.0.1        4 65535  242485  242487      361    0    0    23w2d 4
    """
    vrf_regex = r"^BGP summary information for VRF\s+(?P<vrf>\S+),"
    afi_regex = r"^BGP summary information.*address family (?P<afi>\S+ Unicast)"
    match = re.search(vrf_regex, bgp_summary)
    if match:
        print(match.groupdict(1))


f = open("show_bgp_all_summary_vrf_all.txt", "rt")

bgp_summary_output = f.read()
section_separator = r"BGP summary information for "
bgp_summary_sections = re.split(section_separator, bgp_summary_output)
if len(bgp_summary_sections):
    bgp_summary_sections.pop(0)

for bgp_section in bgp_summary_sections:
    bgp_section = section_separator + bgp_section
    bgp_summary_parser(bgp_section)
    break

#print(bgp_summary_sections[-3])

