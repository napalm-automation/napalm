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


class NetworkDriver:

    def __init__(self, hostname, username, password):
        """
        This is the base class you have to inherit from when writing your own Network Driver to manage any device. You
        will, in addition, have to override all the methods specified on this class. Make sure you follow the guidelines
        for every method and that you return the correct data.

        :param hostname: (str) IP or FQDN of the device you want to connect to.
        :param username: (str) Username you want to use
        :param password: (str) Password
        :return:
        """
        raise NotImplementedError

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

        :return: A string showing the difference between the running configuration and the candidate configuration. The
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

        For example:

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
         * oper_status (up/down)
         * admin_status (enabled/disabled)
         * description (string)
         * last_flapped (in seconds)
         * mode (bridged/routed)
         * speed (in Mbit)
         * macaddress (string)

        For example:

        {
        u'Management1':
            {
            'oper_status': 'down',
            'admin_staus': 'disabled',
            'description': u'',
            'last_flapped': -1,
            'mode': u'routed',
            'speed': 1000,
            'macaddress': u'dead:beef:dead',
            },
        u'Ethernet1':
            {
            'oper_status': 'up',
            'admin_staus': 'enabled',
            'description': u'foo',
            'last_flapped': 1429978575.1554043,
            'mode': u'routed',
            'speed': 1000,
            'macaddress': u'beef:dead:beef',
            },
        u'Ethernet2':
            {
            'oper_status': 'up',
            'admin_staus': 'enabled',
            'description': u'bla',
            'last_flapped': 1429978575.1555667,
            'mode': u'bridged',
            'speed': 1000,
            'macaddress': u'beef:beef:beef',
            }
        }
        """
        raise NotImplementedError

    def get_bgp_neighbors(self):
        """
        Returns a dictionary of dictionaries. The keys for the first dictionary will be the vrf (global if no vrf).\
        The inner dictionary will containg the following data for each vrf:
         * local_as
         * router_id
         * peers - another dictionary of dictionaries. Outer keys are the IPs of the neighbors. The inner keys are:
           * remote_as
           * status (up/down)
           * uptime
           * rcvd_prefixes
           * sent_prefixes

        For example:

            {
            u'default':
                {
                'router_id': u'192.168.0.1',
                'local_as': 65000
                'peers':
                    {
                    u'10.0.0.11':
                        {
                        'status': 'up',
                        'sent_prefixes': 3,
                        'uptime': 1429978587.950959,
                        'rcvd_prefixes': 2,
                        'remote_as': 65001
                        },
                    u'1.1.1.1':
                        {
                        'status': 'down',
                        'sent_prefixes': 0,
                        'uptime': 1429978579.950053,
                        'rcvd_prefixes': 0,
                        'remote_as': 1
                        },
                    u'10.0.0.13':
                        {
                        'status': 'up',
                        'sent_prefixes': 1,
                        'uptime': 1429978581.953695,
                        'rcvd_prefixes': 2,
                        'remote_as': 65003
                        },
                    u'10.0.0.12':
                        {
                        'status': 'up',
                        'sent_prefixes': 3,
                        'uptime': 1429978585.952992,
                        'rcvd_prefixes': 2,
                        'remote_as': 65002
                        }
                    },
                },
            u'vrfA':
                {
                'router_id': u'10.0.1.10',
                'local_as': 65010
                'peers':
                    {
                    u'10.0.1.12':
                        {
                        'status': 'down',
                        'sent_prefixes': 0,
                        'uptime': 1429978582.967222,
                        'rcvd_prefixes': 0,
                        'remote_as': 65012
                        },
                    u'10.0.1.13':
                        {
                        'status': 'down',
                        'sent_prefixes': 0,
                        'uptime': 1429978582.967445,
                        'rcvd_prefixes': 0,
                        'remote_as': 65013
                        },
                    u'10.0.1.11':
                        {
                        'status': 'up',
                        'sent_prefixes': 0,
                        'uptime': 1429978708.9621,
                        'rcvd_prefixes': 0,
                        'remote_as': 65011
                        }
                    },
                }
            }


        """
        raise NotImplementedError

    def get_lldp_neighbors(self):
        """
        Returns a dictionary where the keys are local ports and the value is a list of dictionaries with the following
        information:
            * hostname
            * port
            * ttl

        For example:

        {
        u'Ethernet2':
            [
                {
                'hostname': u'junos-unittest',
                'port': u'520',
                'ttl': 120
                }
            ],
        u'Ethernet3':
            [
                {
                'hostname': u'junos-unittest',
                'port': u'522',
                'ttl': 120
                }
            ],
        u'Ethernet1':
            [
                {
                'hostname': u'junos-unittest',
                'port': u'519',
                'ttl': 120
                },
                {
                'hostname': u'ios-xrv-unittest',
                'port': u'Gi0/0/0/0',
                'ttl': 120
                }
            ],
        u'Management1':
            [
                {
                'hostname': u'junos-unittest',
                'port': u'508',
                'ttl': 120
                }
            ]
        }
        """
        raise NotImplementedError
