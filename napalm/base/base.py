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

import sys
from types import TracebackType
from typing import Optional, Dict, Type, Any, List, Union

from typing_extensions import Literal

from netmiko import ConnectHandler, NetMikoTimeoutException
from netutils.interface import canonical_interface_name

# local modules
import napalm.base.exceptions
import napalm.base.helpers
from napalm.base import constants as c
from napalm.base import validate
from napalm.base.exceptions import ConnectionException
from napalm.base import models


class NetworkDriver(object):
    hostname: str
    username: str
    password: str
    timeout: int
    force_no_enable: bool
    use_canonical_interface: bool

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        timeout: int = 60,
        optional_args: Optional[Dict] = None,
    ) -> None:
        """
        This is the base class you have to inherit from when writing your own Network Driver to
        manage any device. You will, in addition, have to override all the methods specified on
        this class. Make sure you follow the guidelines for every method and that you return the
        correct data.

        :param hostname: IP or FQDN of the device you want to connect to.
        :param username: Username you want to use
        :param password: Password
        :param timeout: Time in seconds to wait for the device to respond.
        :param optional_args: Pass additional arguments to underlying driver
        :return:
        """
        raise NotImplementedError

    def __enter__(self) -> "NetworkDriver":  # type: ignore
        try:
            self.open()
            return self
        except:  # noqa: E722
            # Swallow exception if __exit__ returns a True value
            if self.__exit__(*sys.exc_info()):
                pass
            else:
                raise

    def __exit__(  # type: ignore
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        exc_traceback: Optional[TracebackType],
    ) -> Optional[Literal[False]]:
        self.close()
        if exc_type is not None and (
            exc_type.__name__ not in dir(napalm.base.exceptions)
            and exc_type.__name__ not in __builtins__.keys()  # type: ignore
        ):
            epilog = (
                "NAPALM didn't catch this exception. Please, fill a bugfix on "
                "https://github.com/napalm-automation/napalm/issues\n"
                "Don't forget to include this traceback."
            )
            print(epilog)
            return False
        return None

    def __del__(self) -> None:
        """
        This method is used to cleanup when the program is terminated suddenly.
        We need to make sure the connection is closed properly and the configuration DB
        is released (unlocked).
        """
        try:
            if self.is_alive()["is_alive"]:
                self.close()
        except Exception:
            pass

    def _netmiko_open(
        self, device_type: str, netmiko_optional_args: Optional[Dict] = None
    ) -> ConnectHandler:
        """Standardized method of creating a Netmiko connection using napalm attributes."""
        if netmiko_optional_args is None:
            netmiko_optional_args = {}
        try:
            self._netmiko_device = ConnectHandler(
                device_type=device_type,
                host=self.hostname,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                **netmiko_optional_args
            )
        except NetMikoTimeoutException:
            raise ConnectionException("Cannot connect to {}".format(self.hostname))

        # Disable enable mode if force_no_enable is true (for NAPALM drivers
        # that support force_no_enable)
        try:
            if not self.force_no_enable:
                self._netmiko_device.enable()
        except AttributeError:
            self._netmiko_device.enable()

        return self._netmiko_device

    def _netmiko_close(self) -> None:
        """Standardized method of closing a Netmiko connection."""
        if getattr(self, "_netmiko_device", None):
            self._netmiko_device.disconnect()
            self._netmiko_device = None
        self.device: Optional[ConnectHandler] = None

    def open(self) -> None:
        """
        Opens a connection to the device.
        """
        raise NotImplementedError

    def close(self) -> None:
        """
        Closes the connection to the device.
        """
        raise NotImplementedError

    def is_alive(self) -> models.AliveDict:
        """
        Returns a flag with the connection state.
        Depends on the nature of API used by each driver.
        The state does not reflect only on the connection status (when SSH), it must also take into
        consideration other parameters, e.g.: NETCONF session might not be usable, althought the
        underlying SSH session is still open etc.
        """
        raise NotImplementedError

    def pre_connection_tests(self) -> None:
        """
        This is a helper function used by the cli tool cl_napalm_show_tech. Drivers
        can override this method to do some tests, show information, enable debugging, etc.
        before a connection with the device is attempted.
        """
        raise NotImplementedError

    def connection_tests(self) -> None:
        """
        This is a helper function used by the cli tool cl_napalm_show_tech. Drivers
        can override this method to do some tests, show information, enable debugging, etc.
        before a connection with the device has been successful.
        """
        raise NotImplementedError

    def post_connection_tests(self) -> None:
        """
        This is a helper function used by the cli tool cl_napalm_show_tech. Drivers
        can override this method to do some tests, show information, enable debugging, etc.
        after a connection with the device has been closed successfully.
        """
        raise NotImplementedError

    def load_template(
        self,
        template_name: str,
        template_source: Optional[str] = None,
        template_path: Optional[str] = None,
        **template_vars: Any
    ) -> None:
        """
        Will load a templated configuration on the device.

        :param cls: Instance of the driver class.
        :param template_name: Identifies the template name.
        :param template_source: Custom config template rendered and loaded on device
        :type template_source: optional
        :param template_path: Absolute path to directory for the configuration templates
        :type template_path: optional
        :param template_vars: Dictionary with arguments to be used when the template is rendered.
        :raise DriverTemplateNotImplemented: No template defined for the device type.
        :raise TemplateNotImplemented: The template specified in template_name does not exist in \
        the default path or in the custom path if any specified using parameter `template_path`.
        :raise TemplateRenderException: The template could not be rendered. Either the template \
        source does not have the right format, either the arguments in `template_vars` are not \
        properly specified.
        """
        return napalm.base.helpers.load_template(
            self,
            template_name,
            template_source=template_source,
            template_path=template_path,
            **template_vars
        )

    def load_replace_candidate(
        self, filename: Optional[str] = None, config: Optional[str] = None
    ) -> None:
        """
        Populates the candidate configuration. You can populate it from a file or from a string.
        If you send both a filename and a string containing the configuration, the file takes
        precedence.

        If you use this method the existing configuration will be replaced entirely by the
        candidate configuration once you commit the changes. This method will not change the
        configuration by itself.

        :param filename: Path to the file containing the desired configuration. By default is None.
        :param config: String containing the desired configuration.
        :raise ReplaceConfigException: If there is an error on the configuration sent.
        """
        raise NotImplementedError

    def load_merge_candidate(
        self, filename: Optional[str] = None, config: Optional[str] = None
    ) -> None:
        """
        Populates the candidate configuration. You can populate it from a file or from a string.
        If you send both a filename and a string containing the configuration, the file takes
        precedence.

        If you use this method the existing configuration will be merged with the candidate
        configuration once you commit the changes. This method will not change the configuration
        by itself.

        :param filename: Path to the file containing the desired configuration. By default is None.
        :param config: String containing the desired configuration.
        :raise MergeConfigException: If there is an error on the configuration sent.
        """
        raise NotImplementedError

    def compare_config(self) -> str:
        """
        :return: A string showing the difference between the running configuration and the \
        candidate configuration. The running_config is loaded automatically just before doing the \
        comparison so there is no need for you to do it.
        """
        raise NotImplementedError

    def commit_config(self, message: str = "", revert_in: Optional[int] = None) -> None:
        """
        Commits the changes requested by the method load_replace_candidate or load_merge_candidate.

        NAPALM drivers that support 'commit confirm' should cause self.has_pending_commit
        to return True when a 'commit confirm' is in progress.

        Implementations should raise an exception if commit_config is called multiple times while a
        'commit confirm' is pending.

        :param message: Optional - configuration session commit message
        :type message: str
        :param revert_in: Optional - number of seconds before the configuration will be reverted
        :type revert_in: int|None
        """
        raise NotImplementedError

    def confirm_commit(self) -> None:
        """
        Confirm the changes requested via commit_config when commit_confirm=True.

        Should cause self.has_pending_commit to return False when done.
        """
        raise NotImplementedError

    def has_pending_commit(self) -> bool:
        """
        :return Boolean indicating if a commit_config that needs confirmed is in process.
        """
        raise NotImplementedError

    def discard_config(self) -> None:
        """
        Discards the configuration loaded into the candidate.
        """
        raise NotImplementedError

    def rollback(self) -> None:
        """
        If changes were made, revert changes to the original state.

        If commit confirm is in process, rollback changes and clear has_pending_commit.
        """
        raise NotImplementedError

    def get_facts(self) -> models.FactsDict:
        """
        Returns a dictionary containing the following information:
         * uptime - Uptime of the device in seconds.
         * vendor - Manufacturer of the device.
         * model - Device model.
         * hostname - Hostname of the device
         * fqdn - Fqdn of the device
         * os_version - String with the OS version running on the device.
         * serial_number - Serial number of the device
         * interface_list - List of the interfaces of the device

        Example::

            {
            'uptime': 151005.57332897186,
            'vendor': u'Arista',
            'os_version': u'4.14.3-2329074.gaatlantarel',
            'serial_number': u'SN0123A34AS',
            'model': u'vEOS',
            'hostname': u'eos-router',
            'fqdn': u'eos-router',
            'interface_list': [u'Ethernet2', u'Management1', u'Ethernet1', u'Ethernet3']
            }

        """
        raise NotImplementedError

    def get_interfaces(self) -> Dict[str, models.InterfaceDict]:
        """
        Returns a dictionary of dictionaries. The keys for the first dictionary will be the \
        interfaces in the devices. The inner dictionary will containing the following data for \
        each interface:

         * is_up (True/False)
         * is_enabled (True/False)
         * description (string)
         * last_flapped (float in seconds)
         * speed (float in Mbit)
         * MTU (in Bytes)
         * mac_address (string)

        Example::

            {
            u'Management1':
                {
                'is_up': False,
                'is_enabled': False,
                'description': '',
                'last_flapped': -1.0,
                'speed': 1000.0,
                'mtu': 1500,
                'mac_address': 'FA:16:3E:57:33:61',
                },
            u'Ethernet1':
                {
                'is_up': True,
                'is_enabled': True,
                'description': 'foo',
                'last_flapped': 1429978575.1554043,
                'speed': 1000.0,
                'mtu': 1500,
                'mac_address': 'FA:16:3E:57:33:62',
                },
            u'Ethernet2':
                {
                'is_up': True,
                'is_enabled': True,
                'description': 'bla',
                'last_flapped': 1429978575.1555667,
                'speed': 1000.0,
                'mtu': 1500,
                'mac_address': 'FA:16:3E:57:33:63',
                },
            u'Ethernet3':
                {
                'is_up': False,
                'is_enabled': True,
                'description': 'bar',
                'last_flapped': -1.0,
                'speed': 1000.0,
                'mtu': 1500,
                'mac_address': 'FA:16:3E:57:33:64',
                }
            }
        """
        raise NotImplementedError

    def get_lldp_neighbors(self) -> Dict[str, List[models.LLDPNeighborDict]]:
        """
        Returns a dictionary where the keys are local ports and the value is a list of \
        dictionaries with the following information:
            * hostname
            * port

        Example::

            {
            u'Ethernet2':
                [
                    {
                    'hostname': u'junos-unittest',
                    'port': u'520',
                    }
                ],
            u'Ethernet3':
                [
                    {
                    'hostname': u'junos-unittest',
                    'port': u'522',
                    }
                ],
            u'Ethernet1':
                [
                    {
                    'hostname': u'junos-unittest',
                    'port': u'519',
                    },
                    {
                    'hostname': u'ios-xrv-unittest',
                    'port': u'Gi0/0/0/0',
                    }
                ],
            u'Management1':
                [
                    {
                    'hostname': u'junos-unittest',
                    'port': u'508',
                    }
                ]
            }
        """
        raise NotImplementedError

    def get_bgp_neighbors(self) -> Dict[str, models.BGPStateNeighborsPerVRFDict]:
        """
        Returns a dictionary of dictionaries. The keys for the first dictionary will be the vrf
        (global if no vrf). The inner dictionary will contain the following data for each vrf:

          * router_id
          * peers - another dictionary of dictionaries. Outer keys are the IPs of the neighbors. \
            The inner keys are:
             * local_as (int)
             * remote_as (int)
             * remote_id - peer router id
             * is_up (True/False)
             * is_enabled (True/False)
             * description (string)
             * uptime (int in seconds)
             * address_family (dictionary) - A dictionary of address families available for the \
               neighbor. So far it can be 'ipv4' or 'ipv6'
                * received_prefixes (int)
                * accepted_prefixes (int)
                * sent_prefixes (int)

            Note, if is_up is False and uptime has a positive value then this indicates the
            uptime of the last active BGP session.

            Example::

                {
                  "global": {
                    "router_id": "10.0.1.1",
                    "peers": {
                      "10.0.0.2": {
                        "local_as": 65000,
                        "remote_as": 65000,
                        "remote_id": "10.0.1.2",
                        "is_up": True,
                        "is_enabled": True,
                        "description": "internal-2",
                        "uptime": 4838400,
                        "address_family": {
                          "ipv4": {
                            "sent_prefixes": 637213,
                            "accepted_prefixes": 3142,
                            "received_prefixes": 3142
                          },
                          "ipv6": {
                            "sent_prefixes": 36714,
                            "accepted_prefixes": 148,
                            "received_prefixes": 148
                          }
                        }
                      }
                    }
                  }
                }
        """
        raise NotImplementedError

    def get_environment(self) -> models.EnvironmentDict:
        """
        Returns a dictionary where:

            * fans is a dictionary of dictionaries where the key is the location and the values:
                 * status (True/False) - True if it's ok, false if it's broken
            * temperature is a dict of dictionaries where the key is the location and the values:
                 * temperature (float) - Temperature in celsius the sensor is reporting.
                 * is_alert (True/False) - True if the temperature is above the alert threshold
                 * is_critical (True/False) - True if the temp is above the critical threshold
            * power is a dictionary of dictionaries where the key is the PSU id and the values:
                 * status (True/False) - True if it's ok, false if it's broken
                 * capacity (float) - Capacity in W that the power supply can support
                 * output (float) - Watts drawn by the system
            * cpu is a dictionary of dictionaries where the key is the ID and the values
                 * %usage
            * memory is a dictionary with:
                 * available_ram (int) - Total amount of RAM installed in the device
                 * used_ram (int) - RAM in use in the device
        """
        raise NotImplementedError

    def get_interfaces_counters(self) -> Dict[str, models.InterfaceCounterDict]:
        """
        Returns a dictionary of dictionaries where the first key is an interface name and the
        inner dictionary contains the following keys:

            * tx_errors (int)
            * rx_errors (int)
            * tx_discards (int)
            * rx_discards (int)
            * tx_octets (int)
            * rx_octets (int)
            * tx_unicast_packets (int)
            * rx_unicast_packets (int)
            * tx_multicast_packets (int)
            * rx_multicast_packets (int)
            * tx_broadcast_packets (int)
            * rx_broadcast_packets (int)

        Example::

            {
                u'Ethernet2': {
                    'tx_multicast_packets': 699,
                    'tx_discards': 0,
                    'tx_octets': 88577,
                    'tx_errors': 0,
                    'rx_octets': 0,
                    'tx_unicast_packets': 0,
                    'rx_errors': 0,
                    'tx_broadcast_packets': 0,
                    'rx_multicast_packets': 0,
                    'rx_broadcast_packets': 0,
                    'rx_discards': 0,
                    'rx_unicast_packets': 0
                },
                u'Management1': {
                     'tx_multicast_packets': 0,
                     'tx_discards': 0,
                     'tx_octets': 159159,
                     'tx_errors': 0,
                     'rx_octets': 167644,
                     'tx_unicast_packets': 1241,
                     'rx_errors': 0,
                     'tx_broadcast_packets': 0,
                     'rx_multicast_packets': 0,
                     'rx_broadcast_packets': 80,
                     'rx_discards': 0,
                     'rx_unicast_packets': 0
                },
                u'Ethernet1': {
                     'tx_multicast_packets': 293,
                     'tx_discards': 0,
                     'tx_octets': 38639,
                     'tx_errors': 0,
                     'rx_octets': 0,
                     'tx_unicast_packets': 0,
                     'rx_errors': 0,
                     'tx_broadcast_packets': 0,
                     'rx_multicast_packets': 0,
                     'rx_broadcast_packets': 0,
                     'rx_discards': 0,
                     'rx_unicast_packets': 0
                }
            }
        """
        raise NotImplementedError

    def get_lldp_neighbors_detail(
        self, interface: str = ""
    ) -> models.LLDPNeighborsDetailDict:
        """
        Returns a detailed view of the LLDP neighbors as a dictionary
        containing lists of dictionaries for each interface.

        Empty entries are returned as an empty string (e.g. '') or list where applicable.

        Inner dictionaries contain fields:

            * parent_interface (string)
            * remote_port (string)
            * remote_port_description (string)
            * remote_chassis_id (string)
            * remote_system_name (string)
            * remote_system_description (string)
            * remote_system_capab (list) with any of these values
                * other
                * repeater
                * bridge
                * wlan-access-point
                * router
                * telephone
                * docsis-cable-device
                * station
            * remote_system_enabled_capab (list)

        Example::

            {
                'TenGigE0/0/0/8': [
                    {
                        'parent_interface': u'Bundle-Ether8',
                        'remote_chassis_id': u'8c60.4f69.e96c',
                        'remote_system_name': u'switch',
                        'remote_port': u'Eth2/2/1',
                        'remote_port_description': u'Ethernet2/2/1',
                        'remote_system_description': u'''Cisco Nexus Operating System (NX-OS)
                              Software 7.1(0)N1(1a)
                              TAC support: http://www.cisco.com/tac
                              Copyright (c) 2002-2015, Cisco Systems, Inc. All rights reserved.''',
                        'remote_system_capab': ['bridge', 'repeater'],
                        'remote_system_enable_capab': ['bridge']
                    }
                ]
            }
        """
        raise NotImplementedError

    def get_bgp_config(
        self, group: str = "", neighbor: str = ""
    ) -> models.BGPConfigGroupDict:
        """
        Returns a dictionary containing the BGP configuration.
        Can return either the whole config, either the config only for a group or neighbor.

        :param group: Returns the configuration of a specific BGP group.
        :param neighbor: Returns the configuration of a specific BGP neighbor.

        Main dictionary keys represent the group name and the values represent a dictionary having
        the keys below.  A default group named "_" will contain information regarding global
        settings and any neighbors that are not members of a group.

            * type (string)
            * description (string)
            * apply_groups (string list)
            * multihop_ttl (int)
            * multipath (True/False)
            * local_address (string)
            * local_as (int)
            * remote_as (int)
            * import_policy (string)
            * export_policy (string)
            * remove_private_as (True/False)
            * prefix_limit (dictionary)
            * neighbors (dictionary)

        Neighbors is a dictionary of dictionaries with the following keys:

            * description (string)
            * import_policy (string)
            * export_policy (string)
            * local_address (string)
            * local_as (int)
            * remote_as (int)
            * authentication_key (string)
            * prefix_limit (dictionary)
            * route_reflector_client (True/False)
            * nhs (True/False)

        The inner dictionary prefix_limit has the same structure for both layers::

            {
                [FAMILY_NAME]: {
                    [FAMILY_TYPE]: {
                        'limit': [LIMIT],
                        ... other options
                    }
                }
            }

        Example::

            {
                'PEERS-GROUP-NAME':{
                    'type'              : u'external',
                    'description'       : u'Here we should have a nice description',
                    'apply_groups'      : [u'BGP-PREFIX-LIMIT'],
                    'import_policy'     : u'PUBLIC-PEER-IN',
                    'export_policy'     : u'PUBLIC-PEER-OUT',
                    'remove_private_as' : True,
                    'multipath'         : True,
                    'multihop_ttl'      : 30,
                    'neighbors'         : {
                        '192.168.0.1': {
                            'description'   : 'Facebook [CDN]',
                            'prefix_limit'  : {
                                'inet': {
                                    'unicast': {
                                        'limit': 100,
                                        'teardown': {
                                            'threshold' : 95,
                                            'timeout'   : 5
                                        }
                                    }
                                }
                            }
                            'remote_as'             : 32934,
                            'route_reflector_client': False,
                            'nhs'                   : True
                        },
                        '172.17.17.1': {
                            'description'   : 'Twitter [CDN]',
                            'prefix_limit'  : {
                                'inet': {
                                    'unicast': {
                                        'limit': 500,
                                        'no-validate': 'IMPORT-FLOW-ROUTES'
                                    }
                                }
                            }
                            'remote_as'               : 13414
                            'route_reflector_client': False,
                            'nhs'                   : False
                        }
                    }
                }
            }
        """
        raise NotImplementedError

    def cli(
        self, commands: List[str], encoding: str = "text"
    ) -> Dict[str, Union[str, Dict[str, Any]]]:
        """
        Will execute a list of commands and return the output in a dictionary format.

        Example::

            {
                u'show version and haiku':  u'''Hostname: re0.edge01.arn01
                                                Model: mx480
                                                Junos: 13.3R6.5

                                                        Help me, Obi-Wan
                                                        I just saw Episode Two
                                                        You're my only hope
                                            ''',
                u'show chassis fan'     :   u'''
                    Item               Status  RPM     Measurement
                    Top Rear Fan       OK      3840    Spinning at intermediate-speed
                    Bottom Rear Fan    OK      3840    Spinning at intermediate-speed
                    Top Middle Fan     OK      3900    Spinning at intermediate-speed
                    Bottom Middle Fan  OK      3840    Spinning at intermediate-speed
                    Top Front Fan      OK      3810    Spinning at intermediate-speed
                    Bottom Front Fan   OK      3840    Spinning at intermediate-speed'''
            }
        """
        raise NotImplementedError

    def get_bgp_neighbors_detail(
        self, neighbor_address: str = ""
    ) -> Dict[str, models.PeerDetailsDict]:
        """
        Returns a detailed view of the BGP neighbors as a dictionary of lists.

        :param neighbor_address: Retuns the statistics for a spcific BGP neighbor.

        Returns a dictionary of dictionaries. The keys for the first dictionary will be the vrf
        (global if no vrf).
        The keys of the inner dictionary represent the AS number of the neighbors.
        Leaf dictionaries contain the following fields:

            * up (True/False)
            * local_as (int)
            * remote_as (int)
            * router_id (string)
            * local_address (string)
            * routing_table (string)
            * local_address_configured (True/False)
            * local_port (int)
            * remote_address (string)
            * remote_port (int)
            * multihop (True/False)
            * multipath (True/False)
            * remove_private_as (True/False)
            * import_policy (string)
            * export_policy (string)
            * input_messages (int)
            * output_messages (int)
            * input_updates (int)
            * output_updates (int)
            * messages_queued_out (int)
            * connection_state (string)
            * previous_connection_state (string)
            * last_event (string)
            * suppress_4byte_as (True/False)
            * local_as_prepend (True/False)
            * holdtime (int)
            * configured_holdtime (int)
            * keepalive (int)
            * configured_keepalive (int)
            * active_prefix_count (int)
            * received_prefix_count (int)
            * accepted_prefix_count (int)
            * suppressed_prefix_count (int)
            * advertised_prefix_count (int)
            * flap_count (int)

        Example::

            {
                'global': {
                    8121: [
                        {
                            'up'                        : True,
                            'local_as'                  : 13335,
                            'remote_as'                 : 8121,
                            'local_address'             : u'172.101.76.1',
                            'local_address_configured'  : True,
                            'local_port'                : 179,
                            'routing_table'             : u'inet.0',
                            'remote_address'            : u'192.247.78.0',
                            'remote_port'               : 58380,
                            'multihop'                  : False,
                            'multipath'                 : True,
                            'remove_private_as'         : True,
                            'import_policy'             : u'4-NTT-TRANSIT-IN',
                            'export_policy'             : u'4-NTT-TRANSIT-OUT',
                            'input_messages'            : 123,
                            'output_messages'           : 13,
                            'input_updates'             : 123,
                            'output_updates'            : 5,
                            'messages_queued_out'       : 23,
                            'connection_state'          : u'Established',
                            'previous_connection_state' : u'EstabSync',
                            'last_event'                : u'RecvKeepAlive',
                            'suppress_4byte_as'         : False,
                            'local_as_prepend'          : False,
                            'holdtime'                  : 90,
                            'configured_holdtime'       : 90,
                            'keepalive'                 : 30,
                            'configured_keepalive'      : 30,
                            'active_prefix_count'       : 132808,
                            'received_prefix_count'     : 566739,
                            'accepted_prefix_count'     : 566479,
                            'suppressed_prefix_count'   : 0,
                            'advertised_prefix_count'   : 0,
                            'flap_count'                : 27
                        }
                    ]
                }
            }
        """
        raise NotImplementedError

    def get_arp_table(self, vrf: str = "") -> List[models.ARPTableDict]:
        """
        Returns a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float)

        'vrf' of null-string will default to all VRFs. Specific 'vrf' will return the ARP table
        entries for that VRFs (including potentially 'default' or 'global').

        In all cases the same data structure is returned and no reference to the VRF that was used
        is included in the output.

        Example::

            [
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '5C:5E:AB:DA:3C:F0',
                    'ip'        : '172.17.17.1',
                    'age'       : 1454496274.84
                },
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '5C:5E:AB:DA:3C:FF',
                    'ip'        : '172.17.17.2',
                    'age'       : 1435641582.49
                }
            ]

        """
        raise NotImplementedError

    def get_ntp_peers(self) -> Dict[str, models.NTPPeerDict]:
        """
        Returns the NTP peers configuration as dictionary.
        The keys of the dictionary represent the IP Addresses of the peers.
        Inner dictionaries do not have yet any available keys.

        Example::

            {
                '192.168.0.1': {},
                '17.72.148.53': {},
                '37.187.56.220': {},
                '162.158.20.18': {}
            }

        """

        raise NotImplementedError

    def get_ntp_servers(self) -> Dict[str, models.NTPServerDict]:
        """
        Returns the NTP servers configuration as dictionary.
        The keys of the dictionary represent the IP Addresses of the servers.
        Inner dictionaries MAY contain information regarding per-server configuration.

        Example::

            {
                '192.168.0.1':
                {
                    'address': '192.168.0.1',
                    'port': 123,
                    'version': 4,
                    'association_type': 'SERVER',
                    'iburst': False,
                    'prefer': False,
                    'network_instance': 'default',
                    'source_address': '192.0.2.1',
                    'key_id': -1,
                },
                '17.72.148.53': {},
                '37.187.56.220': {},
                '162.158.20.18': {}
            }

        """

        raise NotImplementedError

    def get_ntp_stats(self) -> List[models.NTPStats]:
        """
        Returns a list of NTP synchronization statistics.

            * remote (string)
            * referenceid (string)
            * synchronized (True/False)
            * stratum (int)
            * type (string)
            * when (string)
            * hostpoll (int)
            * reachability (int)
            * delay (float)
            * offset (float)
            * jitter (float)

        Example::

            [
                {
                    'remote'        : u'188.114.101.4',
                    'referenceid'   : u'188.114.100.1',
                    'synchronized'  : True,
                    'stratum'       : 4,
                    'type'          : u'-',
                    'when'          : u'107',
                    'hostpoll'      : 256,
                    'reachability'  : 377,
                    'delay'         : 164.228,
                    'offset'        : -13.866,
                    'jitter'        : 2.695
                }
            ]
        """
        raise NotImplementedError

    def get_interfaces_ip(self) -> Dict[str, models.InterfacesIPDict]:
        """
        Returns all configured IP addresses on all interfaces as a dictionary of dictionaries.
        Keys of the main dictionary represent the name of the interface.
        Values of the main dictionary represent are dictionaries that may consist of two keys
        'ipv4' and 'ipv6' (one, both or none) which are themselves dictionaries with the IP
        addresses as keys.
        Each IP Address dictionary has the following keys:

            * prefix_length (int)

        Example::

            {
                u'FastEthernet8': {
                    u'ipv4': {
                        u'10.66.43.169': {
                            'prefix_length': 22
                        }
                    }
                },
                u'Loopback555': {
                    u'ipv4': {
                        u'192.168.1.1': {
                            'prefix_length': 24
                        }
                    },
                    u'ipv6': {
                        u'1::1': {
                            'prefix_length': 64
                        },
                        u'2001:DB8:1::1': {
                            'prefix_length': 64
                        },
                        u'2::': {
                            'prefix_length': 64
                        },
                        u'FE80::3': {
                            'prefix_length': u'N/A'
                        }
                    }
                },
                u'Tunnel0': {
                    u'ipv4': {
                        u'10.63.100.9': {
                            'prefix_length': 24
                        }
                    }
                }
            }
        """
        raise NotImplementedError

    def get_mac_address_table(self) -> List[models.MACAdressTable]:
        """
        Returns a lists of dictionaries. Each dictionary represents an entry in the MAC Address
        Table, having the following keys:

            * mac (string)
            * interface (string)
            * vlan (int)
            * active (boolean)
            * static (boolean)
            * moves (int)
            * last_move (float)

        However, please note that not all vendors provide all these details.
        E.g.: field last_move is not available on JUNOS devices etc.

        Example::

            [
                {
                    'mac'       : '00:1C:58:29:4A:71',
                    'interface' : 'Ethernet47',
                    'vlan'      : 100,
                    'static'    : False,
                    'active'    : True,
                    'moves'     : 1,
                    'last_move' : 1454417742.58
                },
                {
                    'mac'       : '00:1C:58:29:4A:C1',
                    'interface' : 'xe-1/0/1',
                    'vlan'       : 100,
                    'static'    : False,
                    'active'    : True,
                    'moves'     : 2,
                    'last_move' : 1453191948.11
                },
                {
                    'mac'       : '00:1C:58:29:4A:C2',
                    'interface' : 'ae7.900',
                    'vlan'      : 900,
                    'static'    : False,
                    'active'    : True,
                    'moves'     : None,
                    'last_move' : None
                }
            ]
        """
        raise NotImplementedError

    def get_route_to(
        self, destination: str = "", protocol: str = "", longer: bool = False
    ) -> Dict[str, models.RouteDict]:
        """
        Returns a dictionary of dictionaries containing details of all available routes to a
        destination.

        :param destination: The destination prefix to be used when filtering the routes.
        :param protocol: Retrieve the routes only for a specific protocol.
        :type protocol: optional
        :param longer: Retrieve more specific routes as well.
        :type longer: optional

        Each inner dictionary contains the following fields:

            * protocol (string)
            * current_active (True/False)
            * last_active (True/False)
            * age (int)
            * next_hop (string)
            * outgoing_interface (string)
            * selected_next_hop (True/False)
            * preference (int)
            * inactive_reason (string)
            * routing_table (string)
            * protocol_attributes (dictionary)

        protocol_attributes is a dictionary with protocol-specific information, as follows:

        - BGP
            * local_as (int)
            * remote_as (int)
            * peer_id (string)
            * as_path (string)
            * communities (list)
            * local_preference (int)
            * preference2 (int)
            * metric (int)
            * metric2 (int)
        - ISIS:
            * level (int)

        Example::

            {
                "1.0.0.0/24": [
                    {
                        "protocol"          : u"BGP",
                        "inactive_reason"   : u"Local Preference",
                        "last_active"       : False,
                        "age"               : 105219,
                        "next_hop"          : u"172.17.17.17",
                        "selected_next_hop" : True,
                        "preference"        : 170,
                        "current_active"    : False,
                        "outgoing_interface": u"ae9.0",
                        "routing_table"     : "inet.0",
                        "protocol_attributes": {
                            "local_as"          : 13335,
                            "as_path"           : u"2914 8403 54113 I",
                            "communities"       : [
                                u"2914:1234",
                                u"2914:5678",
                                u"8403:1717",
                                u"54113:9999"
                            ],
                            "preference2"       : -101,
                            "remote_as"         : 2914,
                            "local_preference"  : 100
                        }
                    }
                ]
            }
        """
        raise NotImplementedError

    def get_snmp_information(self) -> models.SNMPDict:
        """
        Returns a dict of dicts containing SNMP configuration.
        Each inner dictionary contains these fields

            * chassis_id (string)
            * community (dictionary)
            * contact (string)
            * location (string)

        'community' is a dictionary with community string specific information, as follows:

            * acl (string) # acl number or name
            * mode (string) # read-write (rw), read-only (ro)

        Example::

            {
                'chassis_id': u'Asset Tag 54670',
                'community': {
                    u'private': {
                        'acl': u'12',
                        'mode': u'rw'
                    },
                    u'public': {
                        'acl': u'11',
                        'mode': u'ro'
                    },
                    u'public_named_acl': {
                        'acl': u'ALLOW-SNMP-ACL',
                        'mode': u'ro'
                    },
                    u'public_no_acl': {
                        'acl': u'N/A',
                        'mode': u'ro'
                    }
                },
                'contact' : u'Joe Smith',
                'location': u'123 Anytown USA Rack 404'
            }
        """
        raise NotImplementedError

    def get_probes_config(self) -> Dict[str, models.ProbeTestDict]:
        """
        Returns a dictionary with the probes configured on the device.
        Probes can be either RPM on JunOS devices, either SLA on IOS-XR. Other vendors do not
        support probes.
        The keys of the main dictionary represent the name of the probes.
        Each probe consists on multiple tests, each test name being a key in the probe dictionary.
        A test has the following keys:

            * probe_type (str)
            * target (str)
            * source (str)
            * probe_count (int)
            * test_interval (int)

        Example::

            {
                'probe1':{
                    'test1': {
                        'probe_type'   : 'icmp-ping',
                        'target'       : '192.168.0.1',
                        'source'       : '192.168.0.2',
                        'probe_count'  : 13,
                        'test_interval': 3
                    },
                    'test2': {
                        'probe_type'   : 'http-ping',
                        'target'       : '172.17.17.1',
                        'source'       : '192.17.17.2',
                        'probe_count'  : 5,
                        'test_interval': 60
                    }
                }
            }
        """
        raise NotImplementedError

    def get_probes_results(self) -> Dict[str, models.ProbeTestResultDict]:
        """
        Returns a dictionary with the results of the probes.
        The keys of the main dictionary represent the name of the probes.
        Each probe consists on multiple tests, each test name being a key in the probe dictionary.
        A test has the following keys:

            * target (str)
            * source (str)
            * probe_type (str)
            * probe_count (int)
            * rtt (float)
            * round_trip_jitter (float)
            * current_test_loss (float)
            * current_test_min_delay (float)
            * current_test_max_delay (float)
            * current_test_avg_delay (float)
            * last_test_min_delay (float)
            * last_test_max_delay (float)
            * last_test_avg_delay (float)
            * global_test_min_delay (float)
            * global_test_max_delay (float)
            * global_test_avg_delay (float)

        Example::

            {
                'probe1':  {
                    'test1': {
                        'last_test_min_delay'   : 63.120,
                        'global_test_min_delay' : 62.912,
                        'current_test_avg_delay': 63.190,
                        'global_test_max_delay' : 177.349,
                        'current_test_max_delay': 63.302,
                        'global_test_avg_delay' : 63.802,
                        'last_test_avg_delay'   : 63.438,
                        'last_test_max_delay'   : 65.356,
                        'probe_type'            : 'icmp-ping',
                        'rtt'                   : 63.138,
                        'current_test_loss'     : 0,
                        'round_trip_jitter'     : -59.0,
                        'target'                : '192.168.0.1',
                        'source'                : '192.168.0.2'
                        'probe_count'           : 15,
                        'current_test_min_delay': 63.138
                    },
                    'test2': {
                        'last_test_min_delay'   : 176.384,
                        'global_test_min_delay' : 169.226,
                        'current_test_avg_delay': 177.098,
                        'global_test_max_delay' : 292.628,
                        'current_test_max_delay': 180.055,
                        'global_test_avg_delay' : 177.959,
                        'last_test_avg_delay'   : 177.178,
                        'last_test_max_delay'   : 184.671,
                        'probe_type'            : 'icmp-ping',
                        'rtt'                   : 176.449,
                        'current_test_loss'     : 0,
                        'round_trip_jitter'     : -34.0,
                        'target'                : '172.17.17.1',
                        'source'                : '172.17.17.2'
                        'probe_count'           : 15,
                        'current_test_min_delay': 176.402
                    }
                }
            }
        """
        raise NotImplementedError

    def ping(
        self,
        destination: str,
        source: str = c.PING_SOURCE,
        ttl: int = c.PING_TTL,
        timeout: int = c.PING_TIMEOUT,
        size: int = c.PING_SIZE,
        count: int = c.PING_COUNT,
        vrf: str = c.PING_VRF,
        source_interface: str = c.PING_SOURCE_INTERFACE,
    ) -> models.PingResultDict:
        """
        Executes ping on the device and returns a dictionary with the result

        :param destination: Host or IP Address of the destination
        :param source: Source address of echo request
        :type source: optional
        :param ttl: Maximum number of hops
        :type ttl: optional
        :param timeout: Maximum seconds to wait after sending final packet
        :type timeout: optional
        :param size: Size of request (bytes)
        :type size: optional
        :param count: Number of ping request to send
        :type count: optional
        :param vrf: Use a specific VRF to execute the ping
        :type vrf: optional
        :param source_interface: Use an IP from a source interface as source address of echo request
        :type source_interface: optional

        Output dictionary has one of following keys:

            * success
            * error

        In case of success, inner dictionary will have the following keys:

            * probes_sent (int)
            * packet_loss (int)
            * rtt_min (float)
            * rtt_max (float)
            * rtt_avg (float)
            * rtt_stddev (float)
            * results (list)

        'results' is a list of dictionaries with the following keys:

            * ip_address (str)
            * rtt (float)

        Example::

            {
                'success': {
                    'probes_sent': 5,
                    'packet_loss': 0,
                    'rtt_min': 72.158,
                    'rtt_max': 72.433,
                    'rtt_avg': 72.268,
                    'rtt_stddev': 0.094,
                    'results': [
                        {
                            'ip_address': u'1.1.1.1',
                            'rtt': 72.248
                        },
                        {
                            'ip_address': '2.2.2.2',
                            'rtt': 72.299
                        }
                    ]
                }
            }

            OR

            {
                'error': 'unknown host 8.8.8.8'
            }

        """
        raise NotImplementedError

    def traceroute(
        self,
        destination: str,
        source: str = c.TRACEROUTE_SOURCE,
        ttl: int = c.TRACEROUTE_TTL,
        timeout: int = c.TRACEROUTE_TIMEOUT,
        vrf: str = c.TRACEROUTE_VRF,
    ) -> models.TracerouteResultDict:
        """
        Executes traceroute on the device and returns a dictionary with the result.

        :param destination: Host or IP Address of the destination
        :param source: Use a specific IP Address to execute the traceroute
        :type source: optional
        :param ttl: Maximum number of hops
        :type ttl: optional
        :param timeout: Number of seconds to wait for response
        :type timeout: optional
        :param vrf: Use a specific VRF to execute the traceroute
        :type vrf: optional

        Output dictionary has one of the following keys:

            * success
            * error

        In case of success, the keys of the dictionary represent the hop ID, while values are
        dictionaries containing the probes results:

            * rtt (float)
            * ip_address (str)
            * host_name (str)

        Example::

            {
                'success': {
                    1: {
                        'probes': {
                            1: {
                                'rtt': 1.123,
                                'ip_address': u'206.223.116.21',
                                'host_name': u'eqixsj-google-gige.google.com'
                            },
                            2: {
                                'rtt': 1.9100000000000001,
                                'ip_address': u'206.223.116.21',
                                'host_name': u'eqixsj-google-gige.google.com'
                            },
                            3: {
                                'rtt': 3.347,
                                'ip_address': u'198.32.176.31',
                                'host_name': u'core2-1-1-0.pao.net.google.com'}
                            }
                        },
                        2: {
                            'probes': {
                                1: {
                                    'rtt': 1.586,
                                    'ip_address': u'209.85.241.171',
                                    'host_name': u'209.85.241.171'
                                    },
                                2: {
                                    'rtt': 1.6300000000000001,
                                    'ip_address': u'209.85.241.171',
                                    'host_name': u'209.85.241.171'
                                },
                                3: {
                                    'rtt': 1.6480000000000001,
                                    'ip_address': u'209.85.241.171',
                                    'host_name': u'209.85.241.171'}
                                }
                            },
                        3: {
                            'probes': {
                                1: {
                                    'rtt': 2.529,
                                    'ip_address': u'216.239.49.123',
                                    'host_name': u'216.239.49.123'},
                                2: {
                                    'rtt': 2.474,
                                    'ip_address': u'209.85.255.255',
                                    'host_name': u'209.85.255.255'
                                },
                                3: {
                                    'rtt': 7.813,
                                    'ip_address': u'216.239.58.193',
                                    'host_name': u'216.239.58.193'}
                                }
                            },
                        4: {
                            'probes': {
                                1: {
                                    'rtt': 1.361,
                                    'ip_address': u'8.8.8.8',
                                    'host_name': u'google-public-dns-a.google.com'
                                },
                                2: {
                                    'rtt': 1.605,
                                    'ip_address': u'8.8.8.8',
                                    'host_name': u'google-public-dns-a.google.com'
                                },
                                3: {
                                    'rtt': 0.989,
                                    'ip_address': u'8.8.8.8',
                                    'host_name': u'google-public-dns-a.google.com'}
                                }
                            }
                        }
                    }

            OR

            {
                'error': 'unknown host 8.8.8.8'
            }
        """
        raise NotImplementedError

    def get_users(self) -> Dict[str, models.UsersDict]:
        """
        Returns a dictionary with the configured users.
        The keys of the main dictionary represents the username. The values represent the details
        of the user, represented by the following keys:

            * level (int)
            * password (str)
            * sshkeys (list)

        The level is an integer between 0 and 15, where 0 is the lowest access and 15 represents
        full access to the device.

        Example::

            {
                'mircea': {
                    'level': 15,
                    'password': '$1$0P70xKPa$z46fewjo/10cBTckk6I/w/',
                    'sshkeys': [
                        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4pFn+shPwTb2yELO4L7NtQrKOJXNeCl1je\
                         l9STXVaGnRAnuc2PXl35vnWmcUq6YbUEcgUTRzzXfmelJKuVJTJIlMXii7h2xkbQp0YZIEs4P\
                         8ipwnRBAxFfk/ZcDsN3mjep4/yjN56eorF5xs7zP9HbqbJ1dsqk1p3A/9LIL7l6YewLBCwJj6\
                         D+fWSJ0/YW+7oH17Fk2HH+tw0L5PcWLHkwA4t60iXn16qDbIk/ze6jv2hDGdCdz7oYQeCE55C\
                         CHOHMJWYfN3jcL4s0qv8/u6Ka1FVkV7iMmro7ChThoV/5snI4Ljf2wKqgHH7TfNaCfpU0WvHA\
                         nTs8zhOrGScSrtb mircea@master-roshi'
                    ]
                }
            }
        """
        raise NotImplementedError

    def get_optics(self) -> Dict[str, models.OpticsDict]:
        """Fetches the power usage on the various transceivers installed
        on the switch (in dbm), and returns a view that conforms with the
        openconfig model openconfig-platform-transceiver.yang

        Returns a dictionary where the keys are as listed below:

            * intf_name (unicode)
                * physical_channels
                    * channels (list of dicts)
                        * index (int)
                        * state
                            * input_power
                                * instant (float)
                                * avg (float)
                                * min (float)
                                * max (float)
                            * output_power
                                * instant (float)
                                * avg (float)
                                * min (float)
                                * max (float)
                            * laser_bias_current
                                * instant (float)
                                * avg (float)
                                * min (float)
                                * max (float)

        Example::

            {
                'et1': {
                    'physical_channels': {
                        'channel': [
                            {
                                'index': 0,
                                'state': {
                                    'input_power': {
                                        'instant': 0.0,
                                        'avg': 0.0,
                                        'min': 0.0,
                                        'max': 0.0,
                                    },
                                    'output_power': {
                                        'instant': 0.0,
                                        'avg': 0.0,
                                        'min': 0.0,
                                        'max': 0.0,
                                    },
                                    'laser_bias_current': {
                                        'instant': 0.0,
                                        'avg': 0.0,
                                        'min': 0.0,
                                        'max': 0.0,
                                    },
                                }
                            }
                        ]
                    }
                }
            }
        """
        raise NotImplementedError

    def get_config(
        self,
        retrieve: str = "all",
        full: bool = False,
        sanitized: bool = False,
        format: str = "text",
    ) -> models.ConfigDict:
        """
        Return the configuration of a device.

        Args:
            retrieve(string): Which configuration type you want to populate, default is all of them.
                              The rest will be set to "".
            full(bool): Retrieve all the configuration. For instance, on ios, "sh run all".
            sanitized(bool): Remove secret data. Default: ``False``.
            format(string): The configuration format style to be retrieved.

        Returns:
          The object returned is a dictionary with a key for each configuration store:

            - running(string) - Representation of the native running configuration
            - candidate(string) - Representation of the native candidate configuration. If the
              device doesnt differentiate between running and startup configuration this will an
              empty string
            - startup(string) - Representation of the native startup configuration. If the
              device doesnt differentiate between running and startup configuration this will an
              empty string
        """
        raise NotImplementedError

    def get_network_instances(
        self, name: str = ""
    ) -> Dict[str, models.NetworkInstanceDict]:
        """
        Return a dictionary of network instances (VRFs) configured, including default/global

        Args:
            name(string) - Name of the network instance to return, default is all.

        Returns:
            A dictionary of network instances in OC format:
            * name (dict)
                * name (unicode)
                * type (unicode)
                * state (dict)
                    * route_distinguisher (unicode)
                * interfaces (dict)
                    * interface (dict)
                        * interface name: (dict)

        Example::

            {
                u'MGMT': {
                    u'name': u'MGMT',
                    u'type': u'L3VRF',
                    u'state': {
                        u'route_distinguisher': u'123:456',
                    },
                    u'interfaces': {
                        u'interface': {
                            u'Management1': {}
                        }
                    }
                },
                u'default': {
                    u'name': u'default',
                    u'type': u'DEFAULT_INSTANCE',
                    u'state': {
                        u'route_distinguisher': None,
                    },
                    u'interfaces: {
                        u'interface': {
                            u'Ethernet1': {}
                            u'Ethernet2': {}
                            u'Ethernet3': {}
                            u'Ethernet4': {}
                        }
                    }
                }
            }
        """
        raise NotImplementedError

    def get_firewall_policies(self) -> Dict[str, List[models.FirewallPolicyDict]]:
        """
        Returns a dictionary of lists of dictionaries where the first key is an unique policy
        name and the inner dictionary contains the following keys:

        * position (int)
        * packet_hits (int)
        * byte_hits (int)
        * id (text_type)
        * enabled (bool)
        * schedule (text_type)
        * log (text_type)
        * l3_src (text_type)
        * l3_dst (text_type)
        * service (text_type)
        * src_zone (text_type)
        * dst_zone (text_type)
        * action (text_type)

        Example::

            {
                'policy_name': [{
                    'position': 1,
                    'packet_hits': 200,
                    'byte_hits': 83883,
                    'id': '230',
                    'enabled': True,
                    'schedule': 'Always',
                    'log': 'all',
                    'l3_src': 'any',
                    'l3_dst': 'any',
                    'service': 'HTTP',
                    'src_zone': 'port2',
                    'dst_zone': 'port3',
                    'action': 'Permit'
                }]
            }
        """
        raise NotImplementedError

    def get_ipv6_neighbors_table(self) -> List[models.IPV6NeighborDict]:
        """
        Get IPv6 neighbors table information.

        Return a list of dictionaries having the following set of keys:

            * interface (string)
            * mac (string)
            * ip (string)
            * age (float) in seconds
            * state (string)

        For example::

            [
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '5c:5e:ab:da:3c:f0',
                    'ip'        : '2001:db8:1:1::1',
                    'age'       : 1454496274.84,
                    'state'     : 'REACH'
                },
                {
                    'interface': 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '66:0e:94:96:e0:ff',
                    'ip'        : '2001:db8:1:1::2',
                    'age'       : 1435641582.49,
                    'state'     : 'STALE'
                }
            ]
        """
        raise NotImplementedError

    def get_vlans(self) -> Dict[str, models.VlanDict]:
        """
        Return structure being spit balled is as follows.
            * vlan_id (int)
                * name (text_type)
                * interfaces (list)

        Example::

            {
                1: {
                    "name": "default",
                    "interfaces": ["GigabitEthernet0/0/1", "GigabitEthernet0/0/2"]
                },
                2: {
                    "name": "vlan2",
                    "interfaces": []
                }
            }
        """
        raise NotImplementedError

    def compliance_report(
        self,
        validation_file: Optional[str] = None,
        validation_source: Optional[str] = None,
    ) -> models.ReportResult:
        """
        Return a compliance report.

        Verify that the device complies with the given validation file and writes a compliance
        report file. See https://napalm.readthedocs.io/en/latest/validate/index.html.

        :param validation_file: Path to the file containing compliance definition. Default is None.
        :param validation_source: Dictionary containing compliance rules.
        :raise ValidationException: File is not valid.
        :raise NotImplementedError: Method not implemented.
        """
        return validate.compliance_report(
            self, validation_file=validation_file, validation_source=validation_source
        )

    def _canonical_int(self, interface: str) -> str:
        """Expose the helper function within this class."""
        if self.use_canonical_interface is True:
            return canonical_interface_name(interface, addl_name_map=None)
        else:
            return interface
