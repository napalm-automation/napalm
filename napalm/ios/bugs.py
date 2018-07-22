import re
import napalm.ios.ios


show_vrf_detail_124 = '''
VRF ios-124; default RD 65000:1; default VPNID <not set>
  Interfaces:
    FastEthernet0/1
Address family ipv4 (Table ID = 0x4):
  No Export VPN route-target communities
  No Import VPN route-target communities
  No import route-map
  No export route-map
  VRF label distribution protocol: not configured
  VRF label allocation mode: per-prefix
Address family ipv6 not active.

'''
show_vrf_detail_150 = '''
VRF Mgmt-intf (VRF Id = 1); default RD <not set>; default VPNID <not set>
  New CLI format, supports multiple address-families
  Flags: 0x1808
  Interfaces:
    Gi0
Address family ipv4 unicast (Table ID = 0x1):
  Flags: 0x0
  No Export VPN route-target communities
  No Import VPN route-target communities
  No import route-map
  No global export route-map
  No export route-map
  VRF label distribution protocol: not configured
  VRF label allocation mode: per-prefix
Address family ipv6 unicast (Table ID = 0x1E000001):
  Flags: 0x0
  No Export VPN route-target communities
  No Import VPN route-target communities
  No import route-map
  No global export route-map
  No export route-map
  VRF label distribution protocol: not configured
  VRF label allocation mode: per-prefix
Address family ipv4 multicast not active

VRF opsnet (VRF Id = 2); default RD 10283:1021312690; default VPNID <not set>
  New CLI format, supports multiple address-families
  Flags: 0x180C
  No interfaces
Address family ipv4 unicast (Table ID = 0x2):
  Flags: 0x0
  Export VPN route-target communities
    RT:10283:50000
  Import VPN route-target communities
    RT:10283:50000
  No import route-map
  No global export route-map
  No export route-map
  VRF label distribution protocol: not configured
  VRF label allocation mode: per-prefix
Address family ipv6 unicast not active
Address family ipv4 multicast not active
'''

show_ip_int_br_124 = '''
Interface                  IP-Address      OK? Method Status                Protocol
FastEthernet0/0            192.168.3.1     YES NVRAM  up                    up
FastEthernet0/1            192.168.4.1     YES NVRAM  up                    up

'''
show_ip_int_br_150 = '''
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0/0   unassigned      YES NVRAM  up                    up
Gi0/0/0.152            192.168.241.21  YES NVRAM  up                    up
Gi0/0/0.154            192.168.241.30  YES NVRAM  up                    up
Gi0/0/0.600            192.168.241.141 YES NVRAM  up                    up
Gi0/0/0.1772           120.177.177.1   YES NVRAM  up                    up
Gi0/0/0.1774           101.177.177.1   YES NVRAM  up                    up
Gi0/0/0.1776           100.177.177.1   YES NVRAM  up                    up
GigabitEthernet0/0/1   unassigned      YES NVRAM  administratively down down
GigabitEthernet0/0/2   unassigned      YES NVRAM  administratively down down
GigabitEthernet0/0/3   unassigned      YES NVRAM  administratively down down
GigabitEthernet0/0/4   unassigned      YES NVRAM  administratively down dow
GigabitEthernet0       192.168.243.80  YES NVRAM  up                    up
Loopback2              192.168.242.152 YES NVRAM  up                    up
'''

print(IOSDriver.get_network_instances(show_vrf_detail=show_vrf_detail_124, show_ip_int_br=show_ip_int_br_124))
print(IOSDriver)get_network_instances(show_vrf_detail=show_vrf_detail_150, show_ip_int_br=show_ip_int_br_150))