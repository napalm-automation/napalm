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
        'interface_list': [u'Ethernet2', u'Management1', u'Ethernet1', u'Ethernet3']
        }

        """


        raise NotImplementedError

    def get_interfaces(self):
        """
        Returns a dictionary of dictionaries. The keys for the first dictionary will be the interfaces in the devices.\
        The inner dictionary will containing the following data for each interface:
         * status (up/down/disabled)
         * last_flapped (in seconds)
         * tx_packets
         * rx_packets
         * tx_errors
         * rx_errors
         * tx_discards
         * rx_discards

        For example:

        {
            u'Management1':
            {
                'status': u'up',
                'rx_packets': 0,
                'tx_discards': 0,
                'tx_errors': 0,
                'last_flapped': -1,
                'rx_errors': 0,
                'rx_discards': 0,
                'tx_packets': 0
            },
            u'Ethernet1':
            {
                'status': u'up',
                'rx_packets': 1224,
                'tx_discards': 0,
                'tx_errors': 0,
                'last_flapped': 1429734681.6860142,
                'rx_errors': 0,
                'rx_discards': 0,
                'tx_packets': 7371
            },
            u'Ethernet2':
            {
                'status': u'up',
                'rx_packets': 1189,
                'tx_discards': 0,
                'tx_errors': 0,
                'last_flapped': 1429734681.686348,
                'rx_errors': 0,
                'rx_discards': 0,
                'tx_packets': 7390
            },
            u'Ethernet3':
            {
                'status': u'down',
                'rx_packets': 1185,
                'tx_discards': 0,
                'tx_errors': 0,
                'last_flapped': 1429734681.686616,
                'rx_errors': 0,
                'rx_discards': 0,
                'tx_packets': 7386
            }
        }


        """
        raise NotImplementedError

    def get_bgp_neighbors(self):
        """
        Returns a dictionary of dictionaries. The keys for the first dictionary will be the vrf (global if no vrf).\
        The inner dictionary will containg the following data for each vrf:
         * local_as
         * neighbor - another dictionary of dictionaries. Outer keys are the IPs of the neighbors. The inner keys are:
           * remote_as
           * status (up/down)
           * uptime
           * pfxRcvd
           * pfcAcc


        """
        raise NotImplementedError
