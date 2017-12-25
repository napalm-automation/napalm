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

    def _send_command(self, command):
        """Wrapper for self.device.send.command().

        If command is a list will iterate through commands until valid command.
        """
        output = ""

        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd)
                    if "% Invalid" not in output:
                        break
            else:
                output = self.device.send_command(command)
            return output
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

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
        temp = ""                                               # sets empty string, will add char respectively
        my_list = list()                                        # creates list
        for val in range(0, len(my_string)):                    # iterates through the length of input
            if my_string[val] != '\n':
                temp += my_string[val]
            if my_string[val] == '\n' and temp == "":
                continue
            if my_string[val] == '\n' or val == len(my_string) - 1:
                my_list.append(temp)
                temp = ""
        return my_list

    @staticmethod
    def delete_if_contains(nline_list, del_word):               #
        temp_list = list()
        for a_string in nline_list:                             #
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
    def unite_strings(output):
        """ removes all the new line and excess spacing in a string"""
        my_string = ""                                              # empty string

        for index in range(len(output)):                            # iterates through all characters of output

            if output[index] != '\n' and output[index] != ' ':      # skips newline and spaces
                my_string += output[index]

            if index != len(output) - 1:
                if output[index] == ' ' and output[index+1] != ' ':     # only adds space to existing string if the
                    my_string += ' '                                    # next char of string is not another space

        return my_string                                            # returns stored string

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
    def fast_find(input_string, word):
        index_list = list()
        input_string = input_string.split()
        for val in range(len(input_string)):
            if input_string[val] == word:
                index_list.append(val)
        return index_list

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
    def output_parser(output, word):
        """If the word is found in the output, it will return the ip address until a new interface is found
        for example."""
        token = output.find(word) + len(word)
        count = 0
        output = output[token:len(output)].replace('/', ' ')
        nline = FastIronDriver.creates_list_of_nlines(output)
        ip6_dict = dict()

        for sentence in nline:
            sentence = sentence.split()

            if len(sentence) > 2:
                count += 1
                if count > 1:
                    break
                ip6_dict.update({
                        sentence[2]: {'prefix_length': sentence[3]}
                })
            if len(sentence) == 2:
                ip6_dict.update({
                        sentence[0]: {'prefix_length': sentence[1]}
                })

        return ip6_dict

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
            'vendor': 'Ruckus',                                                    # Vendor of ICX switches
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

        mul = FastIronDriver.retrieve_all_locations(stats, 'multicasts,', -2)
        uni = FastIronDriver.retrieve_all_locations(stats, 'unicasts', -2)
        bro = FastIronDriver.retrieve_all_locations(stats, 'broadcasts,', -2)
        ier = FastIronDriver.retrieve_all_locations(stats, "errors,", -3)

        for val in range(len(ports)):
            interface_counters.update({ports[val]: {
                'rx_errors': int(ier.pop(0)),
                'tx_errors': int(ier.pop(0)),
                'tx_discards': None,                    # discard is not put in output of current show int
                'rx_discards': None,                    # alternative is to make individual calls which break
                'tx_octets': None,                      # this function, must be taken with software to incorporate
                'rx_octets': None,
                'rx_unicast_packets': int(uni.pop(0)),
                'tx_unicast_packets': int(uni.pop(0)),
                'rx_multicast_packets': int(mul.pop(0)),
                'tx_multicast_packets': int(mul.pop(0)),
                'rx_broadcast_packets': int(bro.pop(0)),
                'tx_broadcast_packets': int(bro.pop(0))
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
        """
        if interface == '':                         # no interface was entered
            print("please enter an interface")
            return None

        output = self.device.send_command('show lldp neighbor detail port ' + interface)
        output = output.replace(':', ' ')
        output = output.replace('"', '')
        output = (output.replace('+', ' '))

        if output.__contains__("No neighbors"):     # no neighbors found on this interface
            return None

        par_int = FastIronDriver.retrieve_all_locations(output, "Local", 1)[0]
        chas_id = FastIronDriver.retrieve_all_locations(output, "Chassis", 3)[0]
        sys_nam = FastIronDriver.retrieve_all_locations(output, "name", 0)[0]

        e_token_sd = output.find("System description") + len("System description")      # token used as parser
        s_token_sc = output.find("System capabilities")                                 # limits of interest
        e_token_sc = output.find("System capabilities") + len("System capabilities")
        s_token_ma = output.find("Management address")
        s_token_la = output.find("Link aggregation")
        e_token_pd = output.find("Port description") + len("Port description")

        sys_des = output[e_token_sd:s_token_sc]                 # grabs system description
        sys_cap = output[e_token_sc:s_token_ma]                 # grabs system capability
        port_de = output[e_token_pd:s_token_la]                 # grabs ports description

        sys_des = FastIronDriver.unite_strings(sys_des)         # removes excess spaces and n lines
        sys_cap = FastIronDriver.unite_strings(sys_cap)
        port_de = FastIronDriver.unite_strings(port_de)

        return {interface: [{
            'parent_interface': par_int,
            'remote_chassis_id': chas_id,
            'remote_system_name': sys_nam,
            'remote_port': port_de,
            'remote_port_description': '',
            'remote_system_description': sys_des,
            'remote_system_capab': sys_cap,
            'remote_system_enable_capab': None
        }]}

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

        cli_output = dict()
        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            output = self.device._send_command(command)
            if 'Invalid input detected' in output:
                raise ValueError('Unable to execute command "{}"'.format(command))
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

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
                            'remote_addressg'            : u'192.247.78.0',
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
        """
        my_list = list()
        output = self.device.send_command('show ntp associations')
        token = output.find('disp') + len('disp') + 1
        end_token = output.find('synced,') - 3
        output = output[token:end_token]
        nline = FastIronDriver.creates_list_of_nlines(output)

        for sentence in nline:
            isbool = False
            sentence = sentence.split()

            if sentence .__contains__('*'):
                isbool = True

            sentence[0] = sentence[0].replace('*', '')
            sentence[0] = sentence[0].replace('+', '')
            sentence[0] = sentence[0].replace('~', '')

            my_list.append({
                'remote': sentence[0],
                'referenceid': sentence[1],
                'synchronized': isbool,
                'stratum': int(sentence[2]),
                'type': u'-',
                'when': int(sentence[3]),
                'hostpoll': int(sentence[4]),
                'reachability': float(sentence[5]),
                'delay': float(sentence[6]),
                'offset': float(sentence[7]),
                'jitter': float(sentence[8])
            })
        return my_list

    def get_interfaces_ip(self):

        """
        Returns all configured IP addresses on all interfaces as a dictionary of dictionaries.
        Keys of the main dictionary represent the name of the interface.
        Values of the main dictionary represent are dictionaries that may consist of two keys
        'ipv4' and 'ipv6' (one, both or none) which are themselvs dictionaries witht the IP
        addresses as keys.
        Each IP Address dictionary has the following keys:
            * prefix_length (int)
        """

        ip_interface = dict()                                   # Main dict, ip4/6 will be appended to this dict
        ip4_dict = dict()                                       # ip4 dict
        ip6_dict = dict()                                       # ip6 dict
        output = self.device.send_command('show ip interface')  # obtains ip4 information
        ipv6_output = self.device.send_command('show ipv6 interface')   # obtains ip6 information
        token = output.find('VRF') + len('VRF') + 4                 # finds when to start parsing
        output = output[token:len(output)]                          # grabs output within certain limits
        n_line = FastIronDriver.creates_list_of_nlines(output)      # separate long string into substrings
        last_port = ""                                          # saves last port information

        for index in range(len(n_line)):
            pos = 0                                             # if interface more than one IP, list is size 1
            sentence = n_line[index].split()                    # creates word list from string

            if len(sentence) == 0:                              # if empty skip
                continue

            if len(sentence) > 2:                               # parent interface, means not a list of size of 1
                last_port = sentence[0] + " " + sentence[1]     # grabs port description
                pos = 2                                         # New position of IP address

                if ipv6_output.__contains__(last_port):         # if interface has ipv6 address, will return
                    ip6_dict = FastIronDriver.output_parser(ipv6_output, last_port)     # all ipv6 add of interface

            ip4_dict.update({                                                       # updates ipv4 dictionary
                    sentence[pos]: {'prefix_length': None}
            })

            if index == (len(n_line) - 1) or len(n_line[index + 1].split()) > 2:
                ip_interface.update({                                               # if new parent interface is next
                    last_port: {                                                    # save all current interfaces
                        'ipv4': ip4_dict,
                        'ipv6': ip6_dict}
                })
                ip4_dict = dict()                                                   # resets dictionary
                ip6_dict = dict()

        return ip_interface

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
        mac_tbl = list()                                            # creates list
        output = self.device.send_command('show mac-address all')   # grabs mac address output
        token = output.find('Action') + len('Action') + 1           # word used for parser
        new_out = FastIronDriver.creates_list_of_nlines(output[token: len(output)])
        for words in new_out:                                       # loop goes sentence by sentence
            sentence = words.split()                                # breaks sentence into words

            if sentence[2] == 'Dynamic':                            # Checks word for dynamic or static
                is_dynamic = True
            else:
                is_dynamic = False

            if sentence[4] == 'forward':                            # Checks if forwarding and not block, discarding
                is_active = True
            else:
                is_active = False

            mac_tbl.append({                                        # appends data
                'mac': sentence[0],
                'interface': sentence[1],
                'vlan': sentence[3],
                'static': is_dynamic,
                'active': is_active,
                'moves': None,
                'last_move': None
            })

        return mac_tbl

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

    def ping(self, destination, source= c.PING_SOURCE, ttl=c.PING_TTL, timeout=c.PING_TIMEOUT,
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
        """

        output = self.device.send_command('show users')
        # ssh_out = self.device.send_command('show ip ssh')
        user_dict = dict()
        token = output.rfind('=') + 1

        n_line = FastIronDriver.creates_list_of_nlines(output[token:len(output)])
        for line in n_line:
            line = line.split()

            if int(line[3]) == 0:
                lv = 15
            elif int(line[3]) == 4:
                lv = 8
            else:
                lv = 3

            user_dict.update({line[0]: {
                'level': lv,
                'password': line[1],
                'sshkeys': []
            }})
        return user_dict

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
        """
        optics_output = list()
        output_m = self.device.send_command('show media validation | i BROCADE')
        n_line = FastIronDriver.creates_list_of_nlines(output_m)

        for sentence in n_line:
            sentence = sentence.split()
            output = self.device.send_command('show optic ' + sentence[0])
            optics_output.append(output)

        my_dict = {'inft_name': {
            'physical_channels': {
                'channel': [{
                    'index': "", 'state': {
                        'input_power': {
                            'instant': 0.0, 'avg': 0.0, 'min': 0.0, 'max': 0.0
                        },
                        'output_power': {
                            'instant': 0.0, 'avg': 0.0, 'min': 0.0, 'max': 0.0
                        },
                        'laser_bias_current': {
                                'instant': 0.0, 'avg': 0.0, 'min': 0.0, 'max': 0.0
                        }
                    }
                }]
            }

            }}

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
        config_list = list()
        config_dic = dict()
        if retrieve == 'running':
            config_list.append('show running-config')
        elif retrieve == 'startup':
            config_list.append('show config')
        elif retrieve == 'candidate':
            config_list.append('')
        elif retrieve == 'all':
            config_list.append('show running-config')
            config_list.append(None)
            config_list.append('show config')

        for cmd in config_list:

            if cmd is None:
                config_dic.update({'candidate': {}})
                continue

            output = self.device.send_command(cmd)
            n_line = FastIronDriver.creates_list_of_nlines(output)

            if cmd == 'show running-config':
                config_dic.update({'running': n_line})
            elif cmd == '':
                config_dic.update({'candidate': n_line})
            else:
                config_dic.update({'startup': n_line})

        return config_dic

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
        vrf_dict = dict()

        if name != '':
            output = self.device.send_command('show vrf ' + name)
        else:
            output = self.device.send_command('show vrf detail')

        s_output = output.split()
        vrf_name_i_list = FastIronDriver.fast_find(s_output, 'VRF-Name:')
        size = len(vrf_name_i_list)

        for val in range(size):
            vrf = vrf_name_i_list.pop()
            vrf_dict.update({
                vrf: {
                    u'name': vrf, u'type': '', u'state': {
                        u'route_distinguisher': ''
                    },
                    u'interfaces': {
                        u'interface': {
                            'forloopinterfaceshere': {}
                        }
                    }

                }
            })

        return vrf_dict

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
