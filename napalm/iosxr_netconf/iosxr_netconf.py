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

"""NETCONF Driver for IOSXR devices."""

from __future__ import unicode_literals

# import third party lib
from ncclient import manager

# import NAPALM base
from napalm.iosxr_netconf import constants as C
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionException


class IOSXRNETCONFDriver(NetworkDriver):
    """IOS-XR NETCONF driver class: inherits NetworkDriver from napalm.base."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialize IOSXR driver.

        optional_args:
            * config_lock (True/False): lock configuration DB after the
                connection is established.
            * port (int): custom port
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.pending_changes = False
        self.replace = False
        self.locked = False
        if optional_args is None:
            optional_args = {}

        self.port = optional_args.get("port", 830)
        self.lock_on_connect = optional_args.get("config_lock", False)

        self.platform = "iosxr"
        self.netconf_ssh = None

    def open(self):
        """Open the connection with the device."""
        try:
            self.netconf_ssh = manager.connect(
                           host=self.hostname,
                           port=self.port,
                           username=self.username,
                           password=self.password,
                           timeout=self.timeout,
                           device_params={'name': 'iosxr'})
            if not self.lock_on_connect:
                self._lock()
        except Exception as conn_err:
            raise ConnectionException(conn_err.args[0])

    def close(self):
        """Close the connection."""
        return NotImplementedError

    def _lock(self):
        """Lock the config DB."""
        if not self.locked:
            self.netconf_ssh.lock()
            self.locked = True

    def _unlock(self):
        """Unlock the config DB."""
        if self.locked:
            self.netconf_ssh.unlock()
            self.locked = False

    def _load_candidate_config(self, filename, config, default_operation):
        """Edit Configuration."""
        pass

    def is_alive(self):
        """Return flag with the state of the connection."""
        return NotImplementedError

    def load_replace_candidate(self, filename=None, config=None):
        """Open the candidate config and replace."""
        return NotImplementedError

    def load_merge_candidate(self, filename=None, config=None):
        """Open the candidate config and merge."""
        return NotImplementedError

    def compare_config(self):
        """Compare candidate config with running."""
        return NotImplementedError

    def commit_config(self, message=""):
        """Commit configuration."""
        return NotImplementedError

    def discard_config(self):
        """Discard changes."""
        return NotImplementedError

    def rollback(self):
        """Rollback to previous commit."""
        return NotImplementedError

    def _find_txt(self, xml_tree, path, default="", namespace=""):
        """
        Extract the text value from an XML tree, using XPath.

        In case of error, will return a default value.
        :param xml_tree:the XML Tree object. <type'lxml.etree._Element'>.
        :param path:XPath to be applied, in order to extract the desired data.
        :param default:  Value to be returned in case of error.
        :param ns: namespace dict
        :return: a str value.
        """
        pass

    def get_facts(self):
        """Return facts of the device."""
        return NotImplementedError

    def get_interfaces(self):
        """Return interfaces details."""
        return NotImplementedError

    def get_interfaces_counters(self):
        """Return interfaces counters."""
        return NotImplementedError

    def get_bgp_neighbors(self):
        """Return BGP neighbors details."""
        return NotImplementedError

    def get_environment(self):
        """Return environment details."""
        return NotImplementedError

    def get_lldp_neighbors(self):
        """Return LLDP neighbors details."""
        return NotImplementedError

    def get_lldp_neighbors_detail(self, interface=""):
        """Detailed view of the LLDP neighbors."""
        return NotImplementedError

    def cli(self, commands):
        """Execute raw CLI commands and returns their output."""
        return NotImplementedError

    def get_bgp_config(self, group="", neighbor=""):
        """Return BGP configuration."""
        return NotImplementedError

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        """Detailed view of the BGP neighbors operational data."""
        return NotImplementedError

    def get_arp_table(self, vrf=""):
        """Return the ARP table."""
        return NotImplementedError

    def get_ntp_peers(self):
        """Return the NTP peers configured on the device."""
        return NotImplementedError

    def get_ntp_servers(self):
        """Return the NTP servers configured on the device."""
        return NotImplementedError

    def get_ntp_stats(self):
        """Return NTP stats (associations)."""
        return NotImplementedError

    def get_interfaces_ip(self):
        """Return the configured IP addresses."""
        return NotImplementedError

    def get_mac_address_table(self):
        """Return the MAC address table."""
        return NotImplementedError

    def get_route_to(self, destination="", protocol=""):
        """Return route details to a specific destination."""
        return NotImplementedError

    def get_snmp_information(self):
        """Return the SNMP configuration."""
        return NotImplementedError

    def get_probes_config(self):
        """Return the configuration of the probes."""
        return NotImplementedError

    def get_probes_results(self):
        """Return the results of the probes."""
        return NotImplementedError

    def traceroute(
        self,
        destination,
        source=C.TRACEROUTE_SOURCE,
        ttl=C.TRACEROUTE_TTL,
        timeout=C.TRACEROUTE_TIMEOUT,
        vrf=C.TRACEROUTE_VRF,
    ):
        """Execute traceroute and return results."""
        return NotImplementedError

    def get_users(self):
        """Return user configuration."""
        return NotImplementedError

    def get_config(self, retrieve="all", full=False):
        """Return device configuration."""
        return NotImplementedError
