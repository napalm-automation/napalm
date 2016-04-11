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

import os
import sys
import jinja2

import textfsm

import napalm.exceptions


class NetworkDriver:

    def __init__(self, hostname, username, password, timeout, optional_args):
        """
        This is the base class you have to inherit from when writing your own Network Driver to manage any device. You
        will, in addition, have to override all the methods specified on this class. Make sure you follow the guidelines
        for every method and that you return the correct data.

        :param hostname: (str) IP or FQDN of the device you want to connect to.
        :param username: (str) Username you want to use
        :param password: (str) Password
        :param timeout: (int) Time in seconds to wait for the device to respond.
        :param optional_args: (dict) Pass additional arguments to underlying driver
        :return:
        """
        raise NotImplementedError

    def __enter__(self):
        try:
            self.open()
        except:
            exc_info = sys.exc_info()
            self.__raise_clean_exception(exc_info[0], exc_info[1], exc_info[2])
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.close()
        if exc_type is not None:
            self.__raise_clean_exception(exc_type, exc_value, exc_traceback)

    @staticmethod
    def __raise_clean_exception(exc_type, exc_value, exc_traceback):
        """
        This method is going to check if the exception exc_type is part of the builtins exceptions or part of the
        napalm exceptions. If it is not, it will print a message on the screen giving instructions to fill a bug.
        Finally it will raise the original exception.

        :param exc_type: Exception class.
        :param exc_value: Exception object.
        :param exc_traceback: Traceback.
        """
        if exc_type.__name__ not in dir(napalm.exceptions) and \
                        exc_type.__name__ not in __builtins__.keys():
            epilog = ("NAPALM didn't catch this exception. Please, fill a bugfix on "
                      "https://github.com/napalm-automation/napalm/issues\n"
                      "Don't forget to include this traceback.")
            print(epilog)
        raise exc_type, exc_value, exc_traceback

    def open(self):
        """
        Opens a connection to the device.
        """
        raise NotImplementedError

    def close(self):
        """
        Closes the connection to the device.
        """
        raise NotImplementedError

    def load_replace_candidate(self, filename=None, config=None):
        """
        Populates the candidate configuration. You can populate it from a file or from a string. If you send both a
        filename and a string containing the configuration, the file takes precedence.

        If you use this method the existing configuration will be replaced entirely by the candidate configuration once
        you commit the changes. This method will not change the configuration by itself.

        :param filename: Path to the file containing the desired configuration. By default is None.
        :param config: String containing the desired configuration.
        :raise ReplaceConfigException: If there is an error on the configuration sent.
        """
        raise NotImplementedError

    def load_merge_candidate(self, filename=None, config=None):
        """
        Populates the candidate configuration. You can populate it from a file or from a string. If you send both a
        filename and a string containing the configuration, the file takes precedence.

        If you use this method the existing configuration will be merged with the candidate configuration once
        you commit the changes. This method will not change the configuration by itself.

        :param filename: Path to the file containing the desired configuration. By default is None.
        :param config: String containing the desired configuration.
        :raise MergeConfigException: If there is an error on the configuration sent.
        """
        raise NotImplementedError

    def compare_config(self):
        """
        :return: A string showing the difference between the running configuration and the candidate configuration. The\
        running_config is loaded automatically just before doing the comparison so there is no need for you to do it.
        """
        raise NotImplementedError

    def commit_config(self):
        """
        Commits the changes requested by the method load_replace_candidate or load_merge_candidate.
        """
        raise NotImplementedError

    def discard_config(self):
        """
        Discards the configuration loaded into the candidate.
        """
        raise NotImplementedError

    def rollback(self):
        """
        If changes were made, revert changes to the original state.
        """
        raise NotImplementedError

    def load_template(self, template_name, template_vars):
        """
        Will load a templated configuration on the device.

        :param template_name (str) identifies the template name
        :param template_vars (obj) represents the object to be used by the Jinja template to create the configuration
        Can be any object type but must respect the constraints defined in the template file.

        :raise DriverTemplateNotImplemented if no template defined for the device type
        :raise TemplateNotImplemented if the template specified in template_name is not defined
        :raise TemplateRenderException if the user passed wrong arguments to the template
        """
        try:
            driver_name = self.__class__.__name__.replace('Driver', '')
            current_dir = os.path.dirname(os.path.abspath(__file__))
            template_dir_path = '{current_dir}/templates/{driver}'.format(
                current_dir=current_dir,
                driver=driver_name.lower()
            )
            if not os.path.isdir(template_dir_path):
                raise napalm.exceptions.DriverTemplateNotImplemented(
                    "There's no config template defined for {driver_name}.".format(
                        driver_name=driver_name
                    )
                )
            loader = jinja2.FileSystemLoader(template_dir_path)
            environment = jinja2.Environment(loader=loader)
            template = environment.get_template('{template_name}.j2'.format(
                template_name=template_name
            ))
            configuration = template.render(template_vars=template_vars)
        except jinja2.exceptions.TemplateNotFound:
            raise napalm.exceptions.TemplateNotImplemented(
                "Template {template_name}.j2 not defined under {path}".format(
                    template_name=template_name,
                    path=template_dir_path
                )
            )
        except jinja2.exceptions.UndefinedError as ue:
            raise napalm.exceptions.TemplateRenderException(
                "Unable to render the template: {}".format(ue.message)
            )

        self.load_merge_candidate(config=configuration)

    def _textfsm_extractor(self, template_name, raw_text):

        """
        Will apply a TextFSM template over a raw text and return the matching table.
        Main usage of this method will be to extract data form a non-structured output
        from a network device and return the values in a table format.

        :param template_name: Specifies the name of the template to be used
        :param raw_text: Text output as the devices prompts on the CLI
        """

        textfsm_data = list()

        driver_name = self.__class__.__name__.replace('Driver', '')
        current_dir = os.path.dirname(os.path.abspath(__file__))
        template_path = '{current_dir}/utils/textfsm_templates/{driver_name}/{template_name}.tpl'.format(
            current_dir=current_dir,
            driver_name=driver_name.lower(),
            template_name=template_name
        )

        try:
             fsm_handler = textfsm.TextFSM(open(template_path))
        except IOError:
            raise napalm.exceptions.TemplateNotImplemented(
                "TextFSM template {template_name} not defined!".format(
                    template_name=template_name
                )
            )
        except textfsm.textfsm.TextFSMTemplateError:
            raise napalm.exceptions.TemplateRenderException(
                "Wrong format of template {template_name}".format(
                    template_name=template_name
                )
            )

        objects = fsm_handler.ParseText(raw_text)

        for obj in objects:
            index = 0
            entry = {}
            for entry_value in obj:
                entry[fsm_handler.header[index].lower()] = str(entry_value)
                index += 1
            textfsm_data.append(entry)

        return textfsm_data

    def get_facts(self):
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

        For example::

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

    def get_interfaces(self):
        """
        Returns a dictionary of dictionaries. The keys for the first dictionary will be the interfaces in the devices.\
        The inner dictionary will containing the following data for each interface:
         * is_up (True/False)
         * is_enabled (True/False)
         * description (string)
         * last_flapped (int in seconds)
         * speed (int in Mbit)
         * mac_address (string)

        For example::

            {
            u'Management1':
                {
                'is_up': False,
                'is_enabled': False,
                'description': u'',
                'last_flapped': -1,
                'speed': 1000,
                'mac_address': u'dead:beef:dead',
                },
            u'Ethernet1':
                {
                'is_up': True,
                'is_enabled': True,
                'description': u'foo',
                'last_flapped': 1429978575.1554043,
                'speed': 1000,
                'mac_address': u'beef:dead:beef',
                },
            u'Ethernet2':
                {
                'is_up': True,
                'is_enabled': True,
                'description': u'bla',
                'last_flapped': 1429978575.1555667,
                'speed': 1000,
                'mac_address': u'beef:beef:beef',
                },
            u'Ethernet3':
                {
                'is_up': False,
                'is_enabled': True,
                'description': u'bar',
                'last_flapped': -1,
                'speed': 1000,
                'mac_address': u'dead:dead:dead',
                }
            }
        """
        raise NotImplementedError

    def get_interface_optics_levels(self):
        """
        Returns a dictionary where the keys are interface names and the values are a dict with the following keys

        * tx power (dbm)
        * rx power (dbm)
        * rx_critical boolean
        * tx_critical boolean
        * rx_warning boolean
        * tx_warning boolean

        For example::

            {
                u'xe-0/0/0': {
                    tx_power: -1.20
                    rx_power: +2.0
                    tx_warning: False
                    rx_warning: False
                    tx_critical: False
                    rx_critical: False
                },
                u'xe-0/0/1': {
                    tx_power: -1.3
                    rx_power: +3.4
                    tx_warning: False
                    rx_warning: False
                    tx_critical: False
                    rx_critical: False
                }
            }
        """
        raise NotImplementedError

    def get_lldp_neighbors(self):
        """
        Returns a dictionary where the keys are local ports and the value is a list of dictionaries with the following \
        information:
            * hostname
            * port

        For example::

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

    def get_bgp_neighbors(self):
        """
        Returns a dictionary of dictionaries. The keys for the first dictionary will be the vrf (global if no vrf).
        The inner dictionary will contain the following data for each vrf:

          * router_id
          * peers - another dictionary of dictionaries. Outer keys are the IPs of the neighbors. The inner keys are:
             * local_as (int)
             * remote_as (int)
             * remote_id - peer router id
             * is_up (True/False)
             * is_enabled (True/False)
             * description (string)
             * uptime (int in seconds)
             * address_family (dictionary) - A dictionary of address families available for the neighbor. So far it can\
               be 'ipv4' or 'ipv6'
                * received_prefixes (int)
                * accepted_prefixes (int)
                * sent_prefixes (int)
        """
        raise NotImplementedError

    def get_environment(self):
        """
        Returns a dictionary where:

            * fans is a dictionary of dictionaries where the key is the location and the values:
                 * status (True/False) - True if it's ok, false if it's broken
            * temperature is a dictionary of dictionaries where the key is the location and the values:
                 * temperature (float) - Temperature in celsius the sensor is reporting.
                 * is_alert (True/False) - True if the temperature is above the alert threshold
                 * is_critical (True/False) - True if the temperature is above the critical threshold
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

    def get_interfaces_counters(self):
        """
        Returns a dictionary of dictionaries where the first key is an interface name and the inner dictionary contains
        the following keys:

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

    def get_lldp_neighbors_detail(self, interface = ''):
        """
        Returns a detailed view of the LLDP neighbors as a dictionary
        containing lists of dictionaries for each interface.

        Inner dictionaries contain fields:
            * parent_interface (string)
            * remote_port (string)
            * remote_port_description (string)
            * remote_chassis_id (string)
            * remote_system_name (string)
            * remote_system_description (string)
            * remote_system_capab (string)
            * remote_system_enabled_capab (string)

        For example::

            {
                'TenGigE0/0/0/8': [
                    {
                        'parent_interface': u'Bundle-Ether8',
                        'remote_chassis_id': u'8c60.4f69.e96c',
                        'remote_system_name': u'switch',
                        'remote_port': u'Eth2/2/1',
                        'remote_port_description': u'Ethernet2/2/1',
                        'remote_system_description': u'''Cisco Nexus Operating System (NX-OS) Software 7.1(0)N1(1a)
                              TAC support: http://www.cisco.com/tac
                              Copyright (c) 2002-2015, Cisco Systems, Inc. All rights reserved.''',
                        'remote_system_capab': u'B, R',
                        'remote_system_enable_capab': u'B'
                    }
                ]
            }
        """
        raise NotImplementedError

    def get_bgp_config(self, group = '', neighbor = ''):
        """
        Returns a dictionary containing the BGP configuration.
        Can return either the whole config, either the config only for a group or neighbor.
        Main dictionary keys represent the group name and the values represent a dictionary having the following keys:
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
        The inner dictionary prefix_limit has the same structure for both layers:
            {
                [FAMILY_NAME]: {
                    [FAMILY_TYPE]: {
                        'limit': [LIMIT],
                        ... other options
                    }
                }

        For example::

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

    def cli(self, *commands):

        """
        Will execute a list of commands and return the output in a dictionary format.

        For example::

            {
                u'show version and haiku':  u'''Hostname: re0.edge01.arn01
                                                Model: mx480
                                                Junos: 13.3R6.5

                                                        Help me, Obi-Wan
                                                        I just saw Episode Two
                                                        You're my only hope
                                            ''',
                u'show chassis fan'     :   u'''Item                      Status   RPM     Measurement
                                                Top Rear Fan              OK       3840    Spinning at intermediate-speed
                                                Bottom Rear Fan           OK       3840    Spinning at intermediate-speed
                                                Top Middle Fan            OK       3900    Spinning at intermediate-speed
                                                Bottom Middle Fan         OK       3840    Spinning at intermediate-speed
                                                Top Front Fan             OK       3810    Spinning at intermediate-speed
                                                Bottom Front Fan          OK       3840    Spinning at intermediate-speed
                                            '''
            }
        """
        raise NotImplementedError

    def get_bgp_neighbors_detail(self, neighbor_address = ''):

        """
        Returns a detailed view of the BGP neighbors as a dictionary of lists.
        The keys of the dictionary represent the AS number of the neighbors.
        Inner dictionaries contain the following fields:
            * up (True/False)
            * local_as (int)
            * remote_as (int)
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

        For example::

            {
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
                        'advertise_prefix_count'    : 0,
                        'flap_count'                : 27
                    }
                ]
            }
        """
        raise NotImplementedError

    def get_arp_table(self):

        """
        Returns a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float)

        For example::

            [
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '5c:5e:ab:da:3c:f0',
                    'ip'        : '172.17.17.1',
                    'age'       : 1454496274.84
                },
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '66:0e:94:96:e0:ff',
                    'ip'        : '172.17.17.2',
                    'age'       : 1435641582.49
                }
            ]

        """
        raise NotImplementedError

    def get_ntp_peers(self):

        """
        Returns a dictionary of dictionaries with the details of each NTP peer.
        Each key of the dictionary is the IP Address of the NTP peer.
        Details of the peer are represented by the following fields:

            * referenceid (string)
            * stratum (int)
            * type (string)
            * when (string)
            * hostpoll (int)
            * reachability (int)
            * delay (float)
            * offset (float)
            * jitter (float)

        For example::

            {
                u'188.114.101.4': {
                    'referenceid'   : u'188.114.100.1',
                    'stratum'       : 4,
                    'type'          : u'-',
                    'when'          : u'107',
                    'hostpoll'      : 256,
                    'reachability'  : 377,
                    'delay'         : 164.228,
                    'offset'        : -13.866,
                    'jitter'        : 2.695
                }
            }
        """
        raise NotImplementedError

    def get_interfaces_ip(self):

        """
        Returns all configured IP addresses on all interfaces as a dictionary of dictionaries.
        Keys of the main dictionary represent the name of the interface.
        Values of the main dictionary represent are dictionaries that may consist of two keys
        'ipv4' and 'ipv6' (one, both or none) which are themselvs dictionaries witht the IP addresses as keys.
        Each IP Address dictionary has the following keys:
            * prefix_length (int)

        For example::

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

    def get_mac_address_table(self):

        """
        Returns a lists of dictionaries. Each dictionary represents an entry in the MAC Address Table,
        having the following keys
            * mac (string)
            * interface (string)
            * vlan (int)
            * active (boolean)
            * static (boolean)
            * moves (int)
            * last_move (float)

        For example::

            [
                {
                    'mac'       : '00:1c:58:29:4a:71',
                    'interface' : 'Ethernet47',
                    'vlan'      : 100,
                    'static'    : False,
                    'active'    : True,
                    'moves'     : 1,
                    'last_move' : 1454417742.58
                },
                {
                    'mac'       : '8c:60:4f:58:e1:c1',
                    'interface' : 'xe-1/0/1',
                    'vlan'       : 100,
                    'static'    : False,
                    'active'    : True,
                    'moves'     : 2,
                    'last_move' : 1453191948.11
                },
                {
                    'mac'       : 'f4:b5:2f:56:72:01',
                    'interface' : 'ae7.900',
                    'vlan'      : 900,
                    'static'    : False,
                    'active'    : True,
                    'moves'     : None,
                    'last_move' : None
                }
            ]

            However, please note that not all vendors provide all these informations.
            E.g.: field last_move is not available on JUNOS devices etc.
        """
        raise NotImplementedError

    def get_route_to(self, destination = '', protocol = ''):

        """
        Returns a dictionary of dictionaries containing details of all available routes to a destination.
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

        For example::

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

    def get_snmp_information(self):

        """
        Returns a dict of dicts containing SNMP configuration
        Each inner dictionary contains these fields

            * chassis_id (string)
            * community (dictionary)
            * contact (string)
            * location (string)

        'community' is a dictionary with community string specific information, as follows:

            * acl (string) # acl number or name
            * mode (string) # read-write (rw), read-only (ro)

        Example Output:

        {   'chassis_id': u'Asset Tag 54670',
        'community': {   u'private': {   'acl': u'12', 'mode': u'rw'},
                         u'public': {   'acl': u'11', 'mode': u'ro'},
                         u'public_named_acl': {   'acl': u'ALLOW-SNMP-ACL',
                                                  'mode': u'ro'},
                         u'public_no_acl': {   'acl': u'N/A', 'mode': u'ro'}},
        'contact': u'Joe Smith',
        'location': u'123 Anytown USA Rack 404'}

        """
        raise NotImplementedError