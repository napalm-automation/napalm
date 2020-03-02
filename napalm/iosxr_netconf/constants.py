# -*- coding: utf-8 -*-
# Copyright 2020 CISCO. All rights reserved.
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

"""Constants for the IOS-XR NETCONF driver."""

from __future__ import unicode_literals

from napalm.base.constants import *  # noqa

# namespaces for XR native models
NS = {'int': 'http://cisco.com/ns/yang/Cisco-IOS-XR-pfi-im-cmd-oper',
      'suo': 'http://cisco.com/ns/yang/Cisco-IOS-XR-shellutil-oper',
      'imo': 'http://cisco.com/ns/yang/Cisco-IOS-XR-invmgr-oper',
      'ntpc': 'http://cisco.com/ns/yang/Cisco-IOS-XR-ip-ntp-cfg',
      'ntp': 'http://cisco.com/ns/yang/Cisco-IOS-XR-ip-ntp-oper',
      'lldp': 'http://cisco.com/ns/yang/Cisco-IOS-XR-ethernet-lldp-oper',
      'bgp': 'http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-oper',
      'bgpc': 'http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-cfg',
      'mac': 'http://cisco.com/ns/yang/Cisco-IOS-XR-l2vpn-oper',
      'int4': 'http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-io-oper',
      'int6': 'http://cisco.com/ns/yang/Cisco-IOS-XR-ipv6-ma-oper',
      }

# GET RPC to retrieve device facts
FACTS_RPC_REQ = '''<get xmlns="urn:ietf:params:xml:ns:netconf:base:1.1">
  <filter>
    <system-time xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-shellutil-oper"/>
    <interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-pfi-im-cmd-oper">
      <interfaces>
        <interface>
          <interface-name/>
        </interface>
      </interfaces>
    </interfaces>
    <inventory xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-invmgr-oper">
      <racks>
        <rack>
          <attributes>
            <inv-basic-bag>
              <software-revision/>
              <model-name/>
              <serial-number/>
            </inv-basic-bag>
          </attributes>
        </rack>
      </racks>
    </inventory>
  </filter>
</get>'''

# subtree filter to get interface state using GET RPC
INT_RPC_REQ_FILTER = '''
<interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-pfi-im-cmd-oper">
  <interfaces>
    <interface>
      <interface-name/>
      <description/>
    </interface>
  </interfaces>
  <interface-xr>
    <interface>
      <interface-name/>
      <line-state/>
      <state/>
      <mac-address>
        <address/>
      </mac-address>
      <bandwidth/>
      <mtu/>
    </interface>
  </interface-xr>
</interfaces>'''

# subtree filter to get interface counters using GET RPC
INT_COUNTERS_RPC_REQ_FILTER = '''
<interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-pfi-im-cmd-oper">
  <interface-xr>
    <interface>
      <interface-name/>
      <interface-statistics>
        <full-interface-stats>
          <multicast-packets-sent/>
          <output-drops/>
          <bytes-sent/>
          <output-errors/>
          <bytes-received/>
          <packets-sent/>
          <input-errors/>
          <broadcast-packets-sent/>
          <multicast-packets-received/>
          <broadcast-packets-received/>
          <input-drops/>
          <packets-received/>
        </full-interface-stats>
      </interface-statistics>
    </interface>
  </interface-xr>
</interfaces>'''

# subtree filter to get NTP peers and servers using GET CONFIG RPC
NTP_RPC_REQ_FILTER = '''
<ntp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ip-ntp-cfg">
  <peer-vrfs>
    <peer-vrf/>
  </peer-vrfs>
</ntp>'''

# subtree filter to get NTP statistics using GET RPC
NTP_STAT_RPC_REQ_FILTER = '''
<ntp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ip-ntp-oper">
  <nodes>
    <node>
      <associations>
        <peer-summary-info>
          <peer-info-common/>
        </peer-summary-info>
      </associations>
    </node>
  </nodes>
</ntp>'''

# subtree filter to get LLDP neighbors and neighbors detail using GET RPC
LLDP_RPC_REQ_FILTER = '''
<lldp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ethernet-lldp-oper">
  <nodes>
    <node>
      <neighbors>
        <details>
          <detail>
            <lldp-neighbor/>
          </detail>
        </details>
      </neighbors>
    </node>
  </nodes>
</lldp>'''

# subtree filter to get BGP neighbors and neighbors detail using GET RPC
BGP_NEIGHBOR_REQ_FILTER = '''
<bgp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-oper">
  <instances>
    <instance>
      <instance-name>default</instance-name>
      <instance-active>
        <default-vrf>
          <global-process-info/>
          <neighbors/>
        </default-vrf>
        <vrfs>
          <vrf>
            <vrf-name/>
            <global-process-info/>
            <neighbors/>
          </vrf>
        </vrfs>
      </instance-active>
    </instance>
  </instances>
</bgp>'''

# subtree filter to get BGP configuration using GET CONFIG RPC
BGP_CFG_RPC_REQ_FILTER = '''
<bgp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-cfg">
  <instance>
    <instance-name>default</instance-name>
  </instance>
</bgp>'''

# subtree filter to get MAC address table using GET RPC
MAC_TABLE_RPC_REQ_FILTER = '''
<l2vpn-forwarding xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-l2vpn-oper">
  <nodes>
    <node>
      <l2fibmac-details/>
    </node>
  </nodes>
</l2vpn-forwarding>'''

# GET RPC to retrieve ipv4 and ipv6 addresses
INT_IPV4_IPV6_RPC_REQ = '''
<get xmlns="urn:ietf:params:xml:ns:netconf:base:1.1">
  <filter>
    <ipv4-network xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-io-oper">
      <nodes>
        <node>
          <interface-data>
            <vrfs>
              <vrf>
                <details>
                  <detail/>
                </details>
              </vrf>
            </vrfs>
          </interface-data>
        </node>
      </nodes>
    </ipv4-network>
    <ipv6-network xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv6-ma-oper">
      <nodes>
        <node>
          <interface-data>
            <vrfs>
              <vrf>
                <global-details>
                  <global-detail/>
                </global-details>
              </vrf>
            </vrfs>
          </interface-data>
        </node>
      </nodes>
    </ipv6-network>
  </filter>
</get>'''
