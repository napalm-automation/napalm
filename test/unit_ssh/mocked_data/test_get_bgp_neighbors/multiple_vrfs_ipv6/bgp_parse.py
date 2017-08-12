from __future__ import print_function, unicode_literals
import re

# STD REGEX PATTERNS
IP_ADDR_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
IPV4_ADDR_REGEX = IP_ADDR_REGEX
IPV6_ADDR_REGEX_1 = r"::"
IPV6_ADDR_REGEX_2 = r"[0-9a-fA-F:]{1,39}::[0-9a-fA-F:]{1,39}"
IPV6_ADDR_REGEX_3 = r"[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:" \
                     "[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}"
# Should validate IPv6 address using an IP address library after matching with this regex
IPV6_ADDR_REGEX = "(?:{}|{}|{})".format(IPV6_ADDR_REGEX_1, IPV6_ADDR_REGEX_2, IPV6_ADDR_REGEX_3)
IPV4_OR_IPV6_REGEX = "(?:{}|{})".format(IPV4_ADDR_REGEX, IPV6_ADDR_REGEX)

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

def bgp_normalize_table_data(bgp_table):
    """The 'show bgp all summary vrf all' table can have entries that wrap multiple lines.

    2001:db8:4:701::2
                4 65535  163664  163693      145    0    0     3w2d 3
    2001:db8:e0:dd::1
                4    10  327491  327278      145    0    0     3w1d 4
    
    Normalize this so the line wrap doesn't exit.
    """
    bgp_table = bgp_table.strip()
    bgp_multiline_pattern = r"({})\s*\n".format(IPV4_OR_IPV6_REGEX)
    # Strip out the newline
    return re.sub(bgp_multiline_pattern, r'\1', bgp_table)


def bgp_table_parser(bgp_table):
    """Generator that parses a line of bgp summary table and returns a dict compatible with NAPALM
   
    Example line: 
    10.2.1.14       4    10  472516  472238      361    0    0     3w1d 9
    """
    bgp_dict = {}
    bgp_table = bgp_table.strip()
    for bgp_entry in bgp_table.splitlines():
        bgp_table_fields = bgp_entry.split()
        try:
            peer_ip, bgp_version, remote_as, msg_rcvd, msg_sent, _, _, _, uptime, state_pfxrcd = \
                bgp_table_fields
        except ValueError:
            raise ValueError("Unexpected entry ({}) in BGP summary table".format(bgp_table_fields))

        is_enabled = True
        try:
            received_prefixes = int(state_pfxrcd)
            is_up = True
        except ValueError:
            received_prefixes = -1
            is_up = False
            if re.search(r'Shut.*Admin', state_pfxrcd):
                is_enabled = False

        # FIX -- look up logical or behavior we did in Cisco IOS bgp parser (make consistent here)
        # FIX -- need to merge IPv6 and IPv4 AFI for same neighbor
        if is_up == False:
            uptime = -1

        yield {
            peer_ip: {
                "is_enabled": is_enabled,
                "uptime": is_up,
                "remote_as": remote_as,
                "is_up": is_up,
                "description": "",
                "received_prefixes": received_prefixes,
            }
        }

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

    bgp_summary_dict = {}
    # Check for BGP summary information lines that have no data
    if len(bgp_summary.strip().splitlines()) <= 1:
        return {}

    allowed_afi = ['ipv4', 'ipv6']
    vrf_regex = r"^BGP summary information for VRF\s+(?P<vrf>\S+),"
    afi_regex = r"^BGP summary information.*address family (?P<afi>\S+ Unicast)"
    local_router_id = r"^BGP router identifier\s+(?P<router_id>\S+),\s+"

    for pattern in [vrf_regex, afi_regex, local_router_id]:
        match = re.search(pattern, bgp_summary, flags=re.M)
        if match:
            bgp_summary_dict.update(match.groupdict(1))

    # Some post regex cleanup and validation
    afi = bgp_summary_dict['afi']
    afi = afi.split()[0].lower()
    if afi not in allowed_afi:
        raise ValueError("AFI ({}) is invalid and not supported.".format(afi))
    bgp_summary_dict['afi'] = afi

    match = re.search(IPV4_ADDR_REGEX, bgp_summary_dict['router_id'])
    if not match:
        raise ValueError("BGP router_id ({}) is not valid".format(bgp_summary_dict['router_id']))
    print(bgp_summary_dict)

    # Extract and process the tabular data
    tabular_divider = r"^Neighbor\s+.*PfxRcd$"
    tabular_data = re.split(tabular_divider, bgp_summary, flags=re.M)
    if len(tabular_data) != 2:
        raise ValueError("Unexpected data processing BGP summary information:\n\n{}".format(bgp_summary))
    tabular_data = tabular_data[1]
    bgp_table = bgp_normalize_table_data(tabular_data)
    print('-' * 80)
    print(bgp_table)
    print('-' * 80)
    for bgp_entry in bgp_table_parser(bgp_table):
        print(bgp_entry)

    #bgp_tablular_dict = bgp_summary_table_parser(bgp_table)


f = open("show_bgp_all_summary_vrf_all.txt", "rt")

bgp_summary_output = f.read()
section_separator = r"BGP summary information for "
bgp_summary_sections = re.split(section_separator, bgp_summary_output)
if len(bgp_summary_sections):
    bgp_summary_sections.pop(0)

for bgp_section in bgp_summary_sections:
    bgp_section = section_separator + bgp_section
    bgp_summary_parser(bgp_section)
#    break

#print(bgp_summary_sections[-3])

