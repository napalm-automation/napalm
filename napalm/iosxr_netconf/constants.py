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
NS = {
    "int": "http://cisco.com/ns/yang/Cisco-IOS-XR-pfi-im-cmd-oper",
    "suo": "http://cisco.com/ns/yang/Cisco-IOS-XR-shellutil-oper",
    "imo": "http://cisco.com/ns/yang/Cisco-IOS-XR-invmgr-oper",
    "ntpc": "http://cisco.com/ns/yang/Cisco-IOS-XR-ip-ntp-cfg",
    "ntp": "http://cisco.com/ns/yang/Cisco-IOS-XR-ip-ntp-oper",
    "lldp": "http://cisco.com/ns/yang/Cisco-IOS-XR-ethernet-lldp-oper",
    "bgp": "http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-oper",
    "bgpc": "http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-cfg",
    "mac": "http://cisco.com/ns/yang/Cisco-IOS-XR-l2vpn-oper",
    "int4": "http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-io-oper",
    "int6": "http://cisco.com/ns/yang/Cisco-IOS-XR-ipv6-ma-oper",
    "snmp": "http://cisco.com/ns/yang/Cisco-IOS-XR-snmp-agent-cfg",
    "usr": "http://cisco.com/ns/yang/Cisco-IOS-XR-aaa-locald-cfg",
    "aaa": "http://cisco.com/ns/yang/Cisco-IOS-XR-aaa-lib-cfg",
    "arp": "http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-arp-oper",
    "prbc": "http://cisco.com/ns/yang/Cisco-IOS-XR-man-ipsla-cfg",
    "prb": "http://cisco.com/ns/yang/Cisco-IOS-XR-man-ipsla-oper",
    "rib4": "http://cisco.com/ns/yang/Cisco-IOS-XR-ip-rib-ipv4-oper",
    "rib6": "http://cisco.com/ns/yang/Cisco-IOS-XR-ip-rib-ipv6-oper",
    "tr": "http://cisco.com/ns/yang/Cisco-IOS-XR-traceroute-act",
    "sys": "http://cisco.com/ns/yang/Cisco-IOS-XR-wdsysmon-fd-oper",
    "mem": "http://cisco.com/ns/yang/Cisco-IOS-XR-nto-misc-oper",
    "ylib": "urn:ietf:params:xml:ns:yang:ietf-yang-library",
}

# GET RPC to retrieve device facts
FACTS_RPC_REQ = """<get xmlns="urn:ietf:params:xml:ns:netconf:base:1.1">
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
      <entities>
        <entity>
          <name>Rack 0</name>
          <attributes>
            <inv-basic-bag>
              <software-revision/>
              <model-name/>
              <serial-number/>
            </inv-basic-bag>
          </attributes>
        </entity>
      </entities>
    </inventory>
  </filter>
</get>"""

# subtree filter to get interface state using GET RPC
INT_RPC_REQ_FILTER = """
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
</interfaces>"""

# subtree filter to get interface counters using GET RPC
INT_COUNTERS_RPC_REQ_FILTER = """
<interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-pfi-im-cmd-oper">
  <interface-xr>
    <interface>
      <interface-name/>
      <interface-statistics>
        <stats-type/>
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
</interfaces>"""

# subtree filter to get NTP peers and servers using GET CONFIG RPC
NTP_RPC_REQ_FILTER = """
<ntp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ip-ntp-cfg">
  <peer-vrfs>
    <peer-vrf/>
  </peer-vrfs>
</ntp>"""

# subtree filter to get NTP statistics using GET RPC
NTP_STAT_RPC_REQ_FILTER = """
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
</ntp>"""

# subtree filter to get LLDP neighbors and neighbors detail using GET RPC
LLDP_RPC_REQ_FILTER = """
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
</lldp>"""

# subtree filter to get BGP neighbors and neighbors detail using GET RPC
BGP_NEIGHBOR_REQ_FILTER = """
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
</bgp>"""

# subtree filter to get BGP configuration using GET CONFIG RPC
BGP_CFG_RPC_REQ_FILTER = """
<bgp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-bgp-cfg">
  <instance>
    <instance-name>default</instance-name>
  </instance>
</bgp>"""

# subtree filter to get MAC address table using GET RPC
MAC_TABLE_RPC_REQ_FILTER = """
<l2vpn-forwarding xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-l2vpn-oper">
  <nodes>
    <node>
      <l2fibmac-details/>
    </node>
  </nodes>
</l2vpn-forwarding>"""

# GET RPC to retrieve ipv4 and ipv6 addresses
INT_IPV4_IPV6_RPC_REQ = """
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
</get>"""

# subtree filter to get SNMP configuration using GET CONFIG RPC
SNMP_RPC_REQ_FILTER = """
<snmp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-snmp-agent-cfg">
  <administration/>
  <system/>
</snmp>"""

# subtree filter to get SNMP configuration using GET CONFIG RPC
USERS_RPC_REQ_FILTER = """
<aaa xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-aaa-lib-cfg">
  <usernames xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-aaa-locald-cfg">
    <username/>
  </usernames>
</aaa>"""

# RPC to rollback the last commit to the running configuration
ROLLBACK_RPC_REQ = """
<roll-back-configuration-last xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-cfgmgr-rollback-act">
  <count>1</count>
</roll-back-configuration-last>"""

# subtree filter to get ARP table using GET RPC
ARP_RPC_REQ_FILTER = """
<arp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-arp-oper">
  <nodes>
    <node>
      <entries>
        <entry/>
      </entries>
    </node>
  </nodes>
</arp>"""

# subtree filter to get probe configuration using GET CONFIG RPC
PROBE_CFG_RPC_REQ_FILTER = """
<ipsla xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-man-ipsla-cfg">
  <operation>
    <definitions/>
  </operation>
</ipsla>"""

# subtree filter to get probe results using GET RPC
PROBE_OPER_RPC_REQ_FILTER = """
<ipsla xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-man-ipsla-oper">
  <operation-data>
    <operations/>
  </operation-data>
</ipsla>"""

# subtree filter to get ipv6 address route using GET RPC
ROUTE_IPV6_RPC_REQ_FILTER = """
<ipv6-rib xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ip-rib-ipv6-oper">
  <vrfs>
    <vrf>
      <vrf-name>default</vrf-name>
      <afs>
        <af>
          <af-name>IPv6</af-name>
          <safs>
            <saf>
              <saf-name>Unicast</saf-name>
              <ip-rib-route-table-names>
                <ip-rib-route-table-name>
                  <route-table-name>default</route-table-name>
                  <routes>
                    <route>
                    <address>{network}</address>
                    <prefix-length>{prefix_length}</prefix-length>
                    </route>
                  </routes>
                </ip-rib-route-table-name>
              </ip-rib-route-table-names>
            </saf>
          </safs>
        </af>
      </afs>
    </vrf>
  </vrfs>
</ipv6-rib>"""

# subtree filter to get ipv4 address route using GET RPC
ROUTE_IPV4_RPC_REQ_FILTER = """
<rib xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ip-rib-ipv4-oper">
  <vrfs>
    <vrf>
      <vrf-name>default</vrf-name>
      <afs>
        <af>
          <af-name>IPv4</af-name>
          <safs>
            <saf>
              <saf-name>Unicast</saf-name>
              <ip-rib-route-table-names>
                <ip-rib-route-table-name>
                  <route-table-name>default</route-table-name>
                  <routes>
                    <route>
                     <address>{network}</address>
                     <prefix-length>{prefix_length}</prefix-length>
                    </route>
                  </routes>
                </ip-rib-route-table-name>
              </ip-rib-route-table-names>
            </saf>
          </safs>
        </af>
      </afs>
    </vrf>
  </vrfs>
</rib>"""

# GET RPC to retrieve trace route data
TRACEROUTE_RPC_REQ = """
<traceroute xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-traceroute-act">
  <ipv{version}>
    <destination>{destination}</destination>
    {vrf_tag}{source_tag}
    {ttl_tag}{timeout_tag}
  </ipv{version}>
</traceroute>"""

# namespaces for XR environment monitoring native models
ENVMON_NS_ASR9K = "http://www.cisco.com/ns/yang/Cisco-IOS-XR-sysadmin-asr9k-envmon-ui"
ENVMON_NS_XR = "http://www.cisco.com/ns/yang/Cisco-IOS-XR-sysadmin-envmon-ui"
ENVMON_NS_FRETTA = "http://www.cisco.com/ns/yang/Cisco-IOS-XR-sysadmin-fretta-envmon-ui"
ENVMON_NAMESPACES = {
    "sysadmin-asr9k-envmon-ui": f"{ENVMON_NS_ASR9K}",
    "sysadmin-envmon-ui": f"{ENVMON_NS_XR}",
    "sysadmin-fretta-envmon-ui": f"{ENVMON_NS_FRETTA}",
}

# subtree filters to get environment details using GET RPC
ENVMON_RPC_REQ_FILTER = {
    "sysadmin-asr9k-envmon-ui": f"""<environment xmlns="{ENVMON_NS_ASR9K}">
                               <oper>
                                <temperatures/>
                                <fan/>
                                <power/>
                               </oper>
                            </environment>""",
    "sysadmin-envmon-ui": f"""<environment xmlns="{ENVMON_NS_XR}">
                               <oper>
                                <temperatures/>
                                <fan/>
                                <power/>
                               </oper>
                            </environment>""",
    "sysadmin-fretta-envmon-ui": f"""<environment xmlns="{ENVMON_NS_FRETTA}">
                               <oper>
                                <temperatures/>
                                <fan/>
                                <power/>
                               </oper>
                            </environment>""",
}

# platform models without environment monitoring
PLAT_NO_ENVMON = ["R-IOSXRV9000-CC"]

# subtree filter to get memory summary details using GET RPC
ENV_MEM_RPC_REQ_FILTER = """
<memory-summary xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-nto-misc-oper"/>"""

# subtree filter to get system monitoring details using GET RPC
ENV_SYS_MON_RPC_REQ_FILTER = """
<system-monitoring xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-wdsysmon-fd-oper">
 <cpu-utilization/>
</system-monitoring>"""

# subtree filter to get CLI configuration using GET-CONFIG RPC
CLI_CONFIG_RPC_REQ_FILTER = """
<cli xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-cli-cfg"/>"""

# RPC to get CLI configuration differences
CLI_DIFF_RPC_REQ = """
<get-cli-config-diff xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-cli-diff-act"/>"""

# RPC filter to get module namespaces for a module-set using GET RPC
YANG_LIB_RPC_REQ_FILTER = """
<yang-library xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
  <module-set>
    <name>{module_set}</name>
    <module>
       <namespace/>
    </module>
  </module-set>
</yang-library>"""

# possible encoding values for optional argument "config_encoding"
CONFIG_ENCODINGS = ["cli", "xml"]

# module-set to be used by configuration methods
MODULE_SET = "XR-only"

# Exception Messages
INVALID_MODEL_REFERENCE = "Unexpected YANG model reference in config"
