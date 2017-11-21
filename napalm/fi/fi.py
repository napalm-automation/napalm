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

# Python3 support
from __future__ import print_function
from __future__ import unicode_literals

# std libs
import sys
from netmiko import ConnectHandler
import socket
import re

# local modules
import napalm.base.exceptions
import napalm.base.helpers
from napalm.base.exceptions import (ConnectionException, ConnectionClosedException)
import napalm.base.constants as c
from napalm.base import validate
from napalm.base import NetworkDriver


class FastIronDriver(NetworkDriver):
    """Napalm driver for FastIron."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""

        if optional_args is None:
            optional_args = {}

        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.port = optional_args.get('port', 22)

    def __del__(self):
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

    def open(self):
        """
        Opens a connection to the device.
        """
        try:
            self.device = ConnectHandler(device_type='ruckus_fastiron',
                                         ip=self.hostname,
                                         port=self.port,
                                         username=self.username,
                                         password=self.password,
                                         timeout=self.timeout,
                                         verbose=True)
            self.device.session_preparation()
        except Exception:
            raise ConnectionException("Cannot connect to switch: %s:%s" % (self.hostname, self.port))

    def close(self):
        """
        Closes the connection to the device.
        """
        self.device.disconnect()

    def is_alive(self):
        """
        Returns a flag with the connection state.
        Depends on the nature of API used by each driver.
        The state does not reflect only on the connection status (when SSH), it must also take into
        consideration other parameters, e.g.: NETCONF session might not be usable, althought the
        underlying SSH session is still open etc.
        """
        null = chr(0)
        try:
            # Try sending ASCII null byte to maintain
            #   the connection alive
            self.device.send_command(null)
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure
            #   that the connection is unusable,
            #   hence return False.
            return {
                'is_alive': False
            }
        return {
            'is_alive': self.device.remote_conn.transport.is_active()
        }

    # def _send_command(self, command):
    #    """Wrapper for self.device.send.command().
    #
    #    If command is a list will iterate through commands until valid command.
    #   """
    #    try:
    #        if isinstance(command, list):
    #            for cmd in command:
    #                output = self.device.send_command(cmd)
    #                # TODO Check exception handling
    #                if "% Invalid" not in output:
    #                    break
    #        else:
    #            output = self.device.send_command(command)
    #        return output
    #    except (socket.error, EOFError) as e:
    #        raise ConnectionClosedException(str(e))

    @staticmethod
    def retrieve_all_locations(long_string, word, pos):
        """Finds a word of a long_string and returns the value in the nth position"""
        count = 0                                           # counter
        split_string = long_string.split()                  # breaks long string into string of substring
        values = []                                         # creates a list
        for m in split_string:                              # goes through substrings one by one
            count += 1                                      # increments counter
            if m == word:                                   #
                values.append(split_string[count + pos])    #
        return values

    @staticmethod
    def find_words(output, word_list, pos_list):
        """   """
        dictionary = {}
        if len(word_list) != len(pos_list):                             # checks word, pos pair exist
            return None

        if len(word_list) == 0 or len(pos_list) == 0:                   # returns NONE if list is empty
            return None

        size = len(word_list)
        print(size)
        sentence = output.split()                                       # breaks long string into separate strings

        for m in range(0, size):                                        # Iterates through size of word list
            pos = int(pos_list.pop())                                   # pops element position and word pair in list
            word = word_list.pop()
            if sentence.__contains__(word):                             # checks if word is contained in text
                indx = sentence.index(word)                             # records the index of word
                dictionary[word] = sentence[indx + pos]                 # word is obtain as key, index used as reference

        return dictionary

    @staticmethod
    def creates_list_of_nlines(my_string):
        """ Breaks a long string into separated substring"""
        temp = ""  # sets empty string, will add char respectively
        my_list = list()  # creates list
        for val in range(0, len(my_string)):  # iterates through the length of input
            if my_string[val] != '\n':
                temp += my_string[val]
            if my_string[val] == '\n' and temp == "":
                continue
            if my_string[val] == '\n' or val == len(my_string) - 1:
                my_list.append(temp)
                temp = ""
        return my_list

    @staticmethod
    def delete_if_contains(nline_list, del_word):
        temp_list = list()
        for a_string in nline_list:
            if a_string .__contains__(del_word):
                continue
            else:
                temp_list.append(a_string.split())
        return temp_list

    @staticmethod
    def facts_uptime(my_string):  # TODO check for hours its missing....
        my_list = ["day(s)", "hour(s)", "minute(s)", "second(s)"]
        my_pos = [-1, -1, -1, -1]
        total_seconds = 0; multiplier = 0
        t_dictionary = FastIronDriver.find_words(my_string, my_list, my_pos)

        for m in t_dictionary.keys():
            if m == "second(s)":
                multiplier = 1
            elif m == "minute(s)":
                multiplier = 60
            elif m == "hour(s)":
                multiplier = 3600
            elif m == "day(s)":
                multiplier = 86400
            total_seconds = int(t_dictionary.get(m))*multiplier + total_seconds
        return total_seconds

    @staticmethod
    def facts_model(string):
        model = FastIronDriver.retrieve_all_locations(string, "Stackable", 0)[0]
        return model                                            # returns the model of the switch

    @staticmethod
    def facts_hostname(string):
        if string.__contains__("hostname"):
            hostname = FastIronDriver.retrieve_all_locations(string, "hostname", 0)[0]
            return hostname                                     # returns the hostname if configured
        else:
            return None

    @staticmethod
    def facts_os_version(string):
        os_version = FastIronDriver.retrieve_all_locations(string, "SW:", 1)[0]
        return os_version                                       # returns the os_version of switch

    @staticmethod
    def facts_serial(string):
        serial = FastIronDriver.retrieve_all_locations(string, "Serial", 0)[0]
        serial = serial.replace('#:', '')
        return serial                                           # returns serial number

    @staticmethod
    def facts_interface_list(shw_int_brief, pos=0, del_word="Port", trigger=0):  # TODO Unicode
        interfaces_list = list()                                                        # Creates a list
        n_line_output = FastIronDriver.creates_list_of_nlines(shw_int_brief)            #
        interface_details = FastIronDriver.delete_if_contains(n_line_output, del_word)  #

        for port_det in interface_details:                                              #

            if trigger == 0:
                interfaces_list.append(port_det[pos])                                   #
            else:
                if port_det[pos].__contains__("ve") or port_det[pos].__contains__("lb") or \
                        port_det[pos].__contains__("tunnel"):
                    continue
                else:
                    interfaces_list.append(port_det[pos])
        return interfaces_list

    @staticmethod
    def port_time(shw_int_port):
        t_port = list()
        new_lines = FastIronDriver.creates_list_of_nlines(shw_int_port)

        for val in new_lines:
            if val .__contains__("name"):
                continue
            t_port.append(FastIronDriver.facts_uptime(val))

        return t_port

    @staticmethod
    def get_interface_speed(shw_int_speed):
        speed = list()
        for val in shw_int_speed:
            if val == 'auto,' or val == '1Gbit,':
                speed.append(1000)
            elif val == '10Mbit,':
                speed.append(10)
            elif val == '100Mbit,':
                speed.append(100)
            elif val == '2.5Gbit,':
                speed.append(2500)
            elif val == '5Gbit,':
                speed.append(5000)
            elif val == '10Gbit,':
                speed.append(10000)
            elif val == '40Gbit,':
                speed.append(40000)
            else:
                speed.append(100000)
        return speed

    @staticmethod
    def get_interface_up(shw_int_brief):
        port_stat = list()
        for line in shw_int_brief:
            if line == "Up":
                port_stat.append(True)
            else:
                port_stat.append(False)
        return port_stat

    @staticmethod
    def get_interfaces_en(shw_int_brief):
        port_status = list()
        for line in shw_int_brief:
            if line == "None" or line == "N/A":
                port_status.append(False)
            else:
                port_status.append(True)
        return port_status

    @staticmethod
    def get_interface_flap(shw_int_up, shw_int_flapped):
        port_status = list()

        for val in range(0, len(shw_int_up)):
            if shw_int_up[val] == "Down":
                port_status.append(-1)
            else:
                if val < len(shw_int_flapped):
                    port_status.append(shw_int_flapped[val])
                else:
                    port_status.append(-1)
        return port_status

    @staticmethod
    def get_interface_name(shw_int_name, size):
        port_status = list()
        shw_int_name = FastIronDriver.creates_list_of_nlines(shw_int_name)
        for val in shw_int_name:
            if val .__contains__("No port name"):
                port_status.append("")
            else:
                port_status.append(val.replace("Port name is", ""))

        for temp in range(0, size - len(port_status)):
            port_status.append("")

        return port_status

    @staticmethod
    def is_greater(value, threshold):  # compares two values returns true if value
        if float(value) >= float(threshold):  # is greater or equal to threshold
            return True
        return False

    @staticmethod
    def get_interfaces_speed(shw_int_speed, size):
        port_status = list()
        for val in range(0, size):
            if val < len(shw_int_speed):
                port_status.append(shw_int_speed[val])
            else:
                port_status.append(0)
        return port_status

    @staticmethod
    def matrix_format(my_input):
        my_list = list()
        newline = FastIronDriver.creates_list_of_nlines(my_input)
        for text in newline:
            text = text.split()
            if len(text) < 1:
                continue
            else:
                my_list.append(text)

        return my_list

    @staticmethod
    def environment_temperature(string):
        # temp = max(FastIronDriver.retrieve_all_locations(string, "(Sensor", -3))#Grabs all temp sensor and returns max
        dic = dict()
        temp = FastIronDriver.retrieve_all_locations(string, "(Sensor", -3)
        warning = FastIronDriver.retrieve_all_locations(string, "Warning", 1)    # returns the current warning threshold
        shutdown = FastIronDriver.retrieve_all_locations(string, "Shutdown", 1)  # returns the shutdown threshold
        for val in range(0, len(temp)):

            dic.update({'sensor ' + str(val + 1): {'temperature': float(temp[val]),
                        'is_alert': FastIronDriver.is_greater(temp[val], warning[0]),
                                                   'is_critical': FastIronDriver.is_greater(temp[val], shutdown[0])}})

        return {'temperature': dic}                                             # returns temperature of type dictionary

    @staticmethod
    def environment_cpu(string):
        cpu = max(FastIronDriver.retrieve_all_locations(string, "percent", -2))     # Grabs the max cpu value
        dic = {'%usage': cpu}
        return {'cpu': dic}                                                         # returns dictionary with key cpu

    @staticmethod
    def environment_power(chassis_string, inline_string):
        status = FastIronDriver.retrieve_all_locations(chassis_string, "Power", 4)  # checks failed after string found
        potential_values = FastIronDriver.retrieve_all_locations(chassis_string, "Power", 1)    # numerical PSU value
        norm_stat = FastIronDriver.retrieve_all_locations(chassis_string, "Power", 7)           # checks working PSU
        capacity = float(FastIronDriver.retrieve_all_locations(inline_string, "Free", -4)[0]) / 1000
        pwr_used = capacity - float(FastIronDriver.retrieve_all_locations(inline_string, "Free", 1)[0]) / 1000

        my_dic = {}  # creates new list
        for val in range(0, len(status)):                               # if power supply has failed will return
            if status[val] == 'failed':                                 # false, if working will return true
                my_dic["PSU" + potential_values[val]] = {'status': False, 'capacity': 0.0, 'output': 0.0}
            elif norm_stat[val] == "ok":
                my_dic["PS" + potential_values[val]] = {'status': True, 'capacity': capacity, 'output': pwr_used}

        return {'power': my_dic}                                                # returns dictionary containing pwr info

    @staticmethod
    def environment_fan(string):
        fan = FastIronDriver.retrieve_all_locations(string, "Fan", 1)           # finds all instances of fan in output
        unit = FastIronDriver.retrieve_all_locations(string, "Fan", 0)          # finds all instances of fan ID
        my_dict = {}  # creates list

        if string.__contains__("Fanless"):                                      # If string input contains word fanless
            return {"fan": {None}}                                              # no fans are in unit and returns None

        for val in range(0, len(fan)):                                          #
            if fan[val] == "ok,":                                               # checks if output is failed or ok
                my_dict["fan" + unit[val]] = {'status': True}                   # if fan is functional will return true
            elif fan[val] == "failed":                                          # if fan fails, will return false
                my_dict["fan" + unit[val]] = {'status': False}

        return {'fan': my_dict}                                                 # returns dictionary containing fan info

    @staticmethod
    def environment_memory(string):
        mem_total = FastIronDriver.retrieve_all_locations(string, "Dynamic", 1)     # total amount of memory (bytes)
        mem_used = FastIronDriver.retrieve_all_locations(string, "Dynamic", 4)      # amount of memory used (bytes)
        dic = {'available_ram': int(mem_total[0]), 'used_ram': int(mem_used[0])}    # dictionary of memory info

        return {'memory': dic}

    @staticmethod
    def interface_counters(my_port, stat):
        my_dict = {}
        for val in range(len(stat)):
            # port_info = char_to_words(new_line_segment(stat[val]))
            port_info = FastIronDriver.creates_list_of_nlines(stat[val])
            print(port_info)
            sys.exit(0)
            tx_err = int(port_info[7][3]);
            rx_err = int(port_info[9][1]);
            tx_discard = int(port_info[12][3])
            rx_discard = int(port_info[7][1]);
            tx_oct = int(port_info[0][3]);
            rx_oct = int(port_info[0][1])
            tx_uni = int(port_info[4][3]);
            rx_uni = int(port_info[4][1]);
            tx_mul = int(port_info[3][3])
            rx_mul = int(port_info[3][1]);
            tx_bro = int(port_info[2][3]);
            rx_bro = int(port_info[2][1])

            my_dict.update(
                {my_port[val]: {'tx_multicast_packets': tx_mul, 'tx_discard': tx_discard, 'tx_octets': tx_oct,
                                'tx_errors': tx_err, 'rx_octets': rx_oct, 'tx_unicast_packets': tx_uni,
                                'rx_errors': rx_err,
                                'tx_broadcast_packets': tx_bro, 'rx_multicast_packets': rx_mul,
                                'rx_broadcast_packets': rx_bro,
                                'rx_discards': rx_discard, 'rx_unicast_packets': rx_uni}})

        return my_dict

    def load_template(self, template_name, template_source=None,
                      template_path=None, **template_vars):
        """
        Will load a templated configuration on the device.

        :param cls: Instance of the driver class.
        :param template_name: Identifies the template name.
        :param template_source (optional): Custom config template rendered and loaded on device
        :param template_path (optional): Absolute path to directory for the configuration templates
        :param template_vars: Dictionary with arguments to be used when the template is rendered.
        :raise DriverTemplateNotImplemented: No template defined for the device type.
        :raise TemplateNotImplemented: The template specified in template_name does not exist in \
        the default path or in the custom path if any specified using parameter `template_path`.
        :raise TemplateRenderException: The template could not be rendered. Either the template \
        source does not have the right format, either the arguments in `template_vars` are not \
        properly specified.
        """
        return napalm.base.helpers.load_template(self,
                                                 template_name,
                                                 template_source=template_source,
                                                 template_path=template_path,
                                                 **template_vars)

    def load_replace_candidate(self, filename=None, config=None):
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

    def load_merge_candidate(self, filename=None, config=None):
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

    def compare_config(self):
        """
        :return: A string showing the difference between the running configuration and the \
        candidate configuration. The running_config is loaded automatically just before doing the \
        comparison so there is no need for you to do it.
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

    def get_facts(self):    # TODO check os_version as it returns general not switch or router
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
        """
        version_output = self.device.send_command('show version')                   # show version output
        interfaces_up = self.device.send_command('show int brief')                  # show int brief output
        host_name = self.device.send_command('show running | i hostname')           # show running output

        return{
            'uptime': FastIronDriver.facts_uptime(version_output),                  # Returns up time of device in sec
            'vendor': u'Ruckus',                                                    # Vendor of ICX switches
            'model':  FastIronDriver.facts_model(version_output),                   # Model type of switch 12/24/24P etc
            'hostname':  FastIronDriver.facts_hostname(host_name),                  # Host name if configured
            'fqdn': None,
            'os_version':  FastIronDriver.facts_os_version(version_output),         # Returns image version
            'serial_number':  FastIronDriver.facts_serial(version_output),          # Returns Serial number of switch
            'interface_list':  FastIronDriver.facts_interface_list(interfaces_up)   # Returns interfaces that are up
        }

    def get_interfaces(self):
        """
        Returns a dictionary of dictionaries. The keys for the first dictionary will be the \
        interfaces in the devices. The inner dictionary will containing the following data for \
        each interface:
         * is_up (True/False)
         * is_enabled (True/False)
         * description (string)
         * last_flapped (int in seconds)
         * speed (int in Mbit)
         * mac_address (string)
        """
        my_dict = {}
        int_brief = self.device.send_command('show int brief')
        flap_output = self.device.send_command('show interface | i Port')
        speed_output = self.device.send_command('show interface | i speed')
        nombre = self.device.send_command('show interface | i name')
        interfaces = FastIronDriver.facts_interface_list(int_brief)             # obtains interfaces of the switch
        int_up = FastIronDriver.facts_interface_list(int_brief, pos=1, del_word="Link")     # obtains link status
        mac_ad = FastIronDriver.facts_interface_list(int_brief, pos=9, del_word="MAC")      # obtains mac address
        flapped = FastIronDriver.port_time(flap_output)                                     # obtains flapped info
        size = len(interfaces)

        is_en = FastIronDriver.facts_interface_list(int_brief, pos=2, del_word="State")     # obtains the states of all
        int_speed = FastIronDriver.facts_interface_list(speed_output, pos=2)                # obtains the speed in FI
        actual_spd = FastIronDriver.get_interface_speed(int_speed)                          # converts speeds to ints

        flapped = FastIronDriver.get_interfaces_speed(flapped, size)
        actual_spd = FastIronDriver.get_interfaces_speed(actual_spd, size)
        nombre = FastIronDriver.get_interface_name(nombre, size)

        for val in range(0, len(interfaces)):   # TODO check size and converto to napalm format
            my_dict.update({interfaces[val]: {
                'is up': int_up[val],
                'is enabled': is_en[val],
                'description': nombre[val],     # TODO check VE,VLAN,LOPBACK NAME
                'last flapped': flapped[val],
                'speed': actual_spd[val],
                'mac address': mac_ad[val]
            }})
        return my_dict

    def get_lldp_neighbors(self):
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
        my_dict = {}
        shw_int_neg = self.device.send_command('show lldp neighbors')
        token = shw_int_neg.find('System Name') + len('System Name') + 1
        my_input = shw_int_neg[token:len(shw_int_neg)]
        my_test = FastIronDriver.matrix_format(my_input)

        for seq in range(0, len(my_test)):
            my_dict.update({my_test[seq][0]: {
                'hostname': my_test[seq][len(my_test[seq])-1],
                'port': my_test[seq][3],
            }})

        return my_dict

    def get_bgp_neighbors(self):
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

            Example response:
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

    def get_environment(self):
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
        main_dictionary = {}                                            #
        chassis_output = self.device.send_command('show chassis')       #
        cpu_output = self.device.send_command('show cpu')               #
        mem_output = self.device.send_command('show memory')            #
        pwr_output = self.device.send_command('show inline power')      #
        main_dictionary.update(FastIronDriver.environment_fan(chassis_output))                 #
        main_dictionary.update(FastIronDriver.environment_temperature(chassis_output))         #
        main_dictionary.update(FastIronDriver.environment_power(chassis_output, pwr_output))   #
        main_dictionary.update(FastIronDriver.environment_cpu(cpu_output))                     #
        main_dictionary.update(FastIronDriver.environment_memory(mem_output))                  #

        return main_dictionary

    def get_interfaces_counters(self):
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
        """
        int_output = self.device.send_command('show interface brief')       # Returns the show int brief output
        ports = FastIronDriver.facts_interface_list(int_output, trigger=1)  # returns the amount of physical ports
        interface_counters = dict()
        stats = self.device.send_command('show interface')

        mul = [m.start() for m in re.finditer("multicasts,", stats)]
        uni = [m.start() for m in re.finditer("unicasts", stats)]
        bro = [m.start() for m in re.finditer("broadcasts,", stats)]
        ier = [m.start() for m in re.finditer("input errors,", stats)]
        oer = [m.start() for m in re.finditer("output errors,", stats)]
        # dis = None
        # odis = None

        for val in range(len(ports)):
            interface_counters.update({ports[val]: {
                'tx_errors': stats[oer[val] - 2],
                'rx_errors': stats[ier[val] - 2],
                'tx_discards': None,                    # discard is not put in output of current show int
                'rx_discards': None,                    # alternative is to make individual calls which break
                'tx_octets': None,                      # this function, must be taken with software to incorporate
                'rx_octets': None,
                'tx_unicast_packets': stats[uni[(val*2)+1] - 2],
                'rx_unicast_packets': stats[uni[val*2] - 2],
                'tx_multicast_packets': stats[mul[(val*2)+1] - 2],
                'rx_multicast_packets': stats[mul[val*2] - 2],
                'tx_broadcast_packets': stats[bro[(val*2)+1] - 2],
                'rx_broadcast_packets': stats[bro[val*2] - 2]
            }})

        return interface_counters

    def get_lldp_neighbors_detail(self, interface=''):
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
                        'remote_system_capab': u'B, R',
                        'remote_system_enable_capab': u'B'
                    }
                ]
            }
        """
        raise NotImplementedError

    def get_bgp_config(self, group='', neighbor=''):
        """
        Returns a dictionary containing the BGP configuration.
        Can return either the whole config, either the config only for a group or neighbor.

        :param group: Returns the configuration of a specific BGP group.
        :param neighbor: Returns the configuration of a specific BGP neighbor.

        Main dictionary keys represent the group name and the values represent a dictionary having
        the keys below. Neighbors which aren't members of a group will be stored in a key named "_":
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

    def cli(self, commands):

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

    def get_bgp_neighbors_detail(self, neighbor_address=''):

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

    def get_arp_table(self):

        """
        Returns a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float)
        """
        output = self.device.send_command('show arp')
        token = output.find('Status') + len('Status') + 1
        output = FastIronDriver.creates_list_of_nlines(output[token:len(output)])
        arp_counters = dict()

        for val in output:
            val = val.split()
            arp_counters.update({
                'interfaces': val[5],
                'mac': val[2],
                'ip': val[1],
                'age': val[4],
            })

        return arp_counters

    def get_ntp_peers(self):

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
        output = self.device.send_command('show ntp associations')      # obtains peers and servers output
        token = output.find('disp') + len('disp') + 1                   # notes where to start parsing
        output = output[token:len(output)]                              # using token to find first place of interest
        nline = FastIronDriver.creates_list_of_nlines(output)           # splits strings when new line is found
        ntp_peers = dict()                                              # creates a dictionary
        for val in range(len(nline)-1):                                   # iterates through outputs
            val = nline[val].replace("~", " ")                          # removes special character found in output
            val = val.split()                                           # segregates words also, char to string
            ntp_peers.update({
                val[1]: {}
            })

        return ntp_peers

    def get_ntp_servers(self):

        """
        Returns the NTP servers configuration as dictionary.
        The keys of the dictionary represent the IP Addresses of the servers.
        Inner dictionaries do not have yet any available keys.
        """
        output = self.device.send_command('show ntp associations')      # obtains peers and servers output
        token = output.find('disp') + len('disp') + 1                   # notes where to start parsing
        output = output[token:len(output)]                              # using token to find first place of interest
        nline = FastIronDriver.creates_list_of_nlines(output)           # splits strings when new line is found
        ntp_servers = dict()                                            # creates a dictionary
        for val in range(len(nline)-1):                                 # iterates through outputs
            val = nline[val].replace("~", " ")                          # removes special character found in output
            val = val.split()                                           # segregates words also, char to string
            ntp_servers.update({
                val[2]: {}
            })

        return ntp_servers

    def get_ntp_stats(self):

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

    def get_interfaces_ip(self):

        """
        Returns all configured IP addresses on all interfaces as a dictionary of dictionaries.
        Keys of the main dictionary represent the name of the interface.
        Values of the main dictionary represent are dictionaries that may consist of two keys
        'ipv4' and 'ipv6' (one, both or none) which are themselvs dictionaries witht the IP
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

    def get_mac_address_table(self):

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
        """
        mac_tbl = list()
        output = self.device.send_command('show mac-address all')
        token = output.find('Action') + len('Action') + 1
        new_out = FastIronDriver.creates_list_of_nlines(output[token: len(output)])
        for words in new_out:
            sentence = words.split()

            if sentence[2] == 'Dynamic':
                is_dynamic = True
            else:
                is_dynamic = False

            if sentence[4] == 'forward':
                is_active = True
            else:
                is_active = False

            mac_tbl.append({
                'mac': sentence[0],
                'interface': sentence[1],
                'vlan': sentence[3],
                'static': is_dynamic,
                'active': is_active,
                'moves': None,
                'last_move': None
            })

    def get_route_to(self, destination='', protocol=''):

        """
        Returns a dictionary of dictionaries containing details of all available routes to a
        destination.

        :param destination: The destination prefix to be used when filtering the routes.
        :param protocol (optional): Retrieve the routes only for a specific protocol.

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

    def get_snmp_information(self):

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

    def ping(self, destination, source=c.PING_SOURCE, ttl=c.PING_TTL, timeout=c.PING_TIMEOUT,
             size=c.PING_SIZE, count=c.PING_COUNT, vrf=c.PING_VRF):
        """
        Executes ping on the device and returns a dictionary with the result

        :param destination: Host or IP Address of the destination
        :param source (optional): Source address of echo request
        :param ttl (optional): Maximum number of hops
        :param timeout (optional): Maximum seconds to wait after sending final packet
        :param size (optional): Size of request (bytes)
        :param count (optional): Number of ping request to send

        Output dictionary has one of following keys:

            * success
            * error

        In case of success, inner dictionary will have the followin keys:

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
                'error': 'unknown host 8.8.8.8.8'
            }

        """
        raise NotImplementedError

    def traceroute(self,
                   destination,
                   source=c.TRACEROUTE_SOURCE,
                   ttl=c.TRACEROUTE_TTL,
                   timeout=c.TRACEROUTE_TIMEOUT,
                   vrf=c.TRACEROUTE_VRF):
        """
        Executes traceroute on the device and returns a dictionary with the result.

        :param destination: Host or IP Address of the destination
        :param source (optional): Use a specific IP Address to execute the traceroute
        :param ttl (optional): Maimum number of hops
        :param timeout (optional): Number of seconds to wait for response

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
                'error': 'unknown host 8.8.8.8.8'
            }
            """
        raise NotImplementedError

    def get_users(self):
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

    def get_optics(self):
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

        Example:

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

    def get_config(self, retrieve='all'):
        """
        Return the configuration of a device.

        Args:
            retrieve(string): Which configuration type you want to populate, default is all of them.
                The rest will be set to "".

        Returns:
          The object returned is a dictionary with the following keys:
            - running(string) - Representation of the native running configuration
            - candidate(string) - Representation of the native candidate configuration. If the
              device doesnt differentiate between running and startup configuration this will an
              empty string
            - startup(string) - Representation of the native startup configuration. If the
              device doesnt differentiate between running and startup configuration this will an
              empty string
        """
        raise NotImplementedError

    def get_network_instances(self, name=''):
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

        Example:
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
            }
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

    def get_firewall_policies(self):
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

    def compliance_report(self, validation_file=None, validation_source=None):
        """
        Return a compliance report.

        Verify that the device complies with the given validation file and writes a compliance
        report file. See https://napalm.readthedocs.io/en/latest/validate/index.html.

        :param validation_file: Path to the file containing compliance definition. Default is None.
        :param validation_source: Dictionary containing compliance rules.
        :raise ValidationException: File is not valid.
        :raise NotImplementedError: Method not implemented.
        """
        return validate.compliance_report(self, validation_file=validation_file,
                                          validation_source=validation_source)
