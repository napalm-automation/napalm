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
# import sys
from netmiko import ConnectHandler
import socket
# import re

# local modules
import napalm.base.exceptions
# import napalm.base.helpers
from napalm.base.exceptions import ReplaceConfigException, \
    MergeConfigException, ConnectionException, ConnectionClosedException

# import napalm.base.constants as c
# from napalm.base import validate
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
        self.merge_config = False
        self.replace_config = False
        self.stored_config = None
        self.config_replace = None
        self.config_merge = None
        self.rollback_cfg = optional_args.get('rollback_cfg', 'rollback_config.txt')

    def __del__(self):
        """
        This method is used to cleanup when the program is terminated suddenly.
        We need to make sure the connection is closed properly and the configuration DB
        is released (unlocked).
        """
        try:
            if self.is_alive()["is_alive"]:
                self.close()
        except napalm.base.exceptions.CommandErrorException:
            pass

    def open(self):
        """
        Opens a connection to the device.
        """
        try:
            self.device = ConnectHandler(device_type='ruckus_fastiron',
                                         ip=self.hostname,      # saves device parameters
                                         port=self.port,
                                         username=self.username,
                                         password=self.password,
                                         timeout=self.timeout,
                                         verbose=True)
            self.device.session_preparation()

        except Exception:
            raise ConnectionException("Cannot connect to switch: %s:%s" % (self.hostname,
                                                                           self.port))

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
        consideration other parameters, e.g.: NETCONF session might not be usable, although the
        underlying SSH session is still open etc.
        """
        null = chr(0)
        try:
            self.device.send_command(null)
        except (socket.error, EOFError):
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
        count = 0                           # counter
        split_string = long_string.split()  # breaks long string into string of substring
        values = []                         # creates a list
        for m in split_string:              # goes through substrings one by one
            count += 1                      # increments counter
            if m == word:                   # if substring and word match then specific value
                values.append(split_string[count + pos])    # is added to list that is returned
        return values

    @staticmethod
    def find_words(output, word_list, pos_list):
        """   """
        dictionary = {}
        if len(word_list) != len(pos_list):             # checks word, pos pair exist
            return None

        if len(word_list) == 0 or len(pos_list) == 0:   # returns NONE if list is empty
            return None

        size = len(word_list)
        sentence = output.split()                   # breaks long string into separate strings

        for m in range(0, size):                    # Iterates through size of word list
            pos = int(pos_list.pop())               # pops element position and word pair in list
            word = word_list.pop()
            if sentence.__contains__(word):         # checks if word is contained in text
                indx = sentence.index(word)         # records the index of word
                dictionary[word] = sentence[indx + pos]

        return dictionary

    @staticmethod
    def creates_list_of_nlines(my_string):
        """ Breaks a long string into separated substring"""
        temp = ""                       # sets empty string, will add char respectively
        my_list = list()                # creates list
        for val in range(0, len(my_string)):    # iterates through the length of input
            if my_string[val] == '\n' and temp == "":
                continue
            elif my_string[val] == '\n' or val >= len(my_string):    # add what was found
                my_list.append(temp)
                temp = ""
            else:
                if my_string[val] == ' ' and my_string[val+1] == '\n':
                    continue
                temp += my_string[val]

        return my_list

    @staticmethod
    def delete_if_contains(nline_list, del_word):
        temp_list = list()                          # Creates a list to store variables
        for a_string in nline_list:                 # iterates through list
            if a_string .__contains__(del_word):    # if word matches, word is skipped
                continue
            else:
                temp_list.append(a_string.split())  # Word didn't match store in list
        return temp_list

    @staticmethod
    def facts_uptime(my_string):  # TODO check for hours its missing....
        my_list = ["day(s)", "hour(s)", "minute(s)", "second(s)"]   # list of words to find
        my_pos = [-1, -1, -1, -1]                   # relative position of interest
        total_seconds = 0                           # data variables
        multiplier = 0
        t_dictionary = FastIronDriver.find_words(my_string, my_list, my_pos)    # retrieves pos

        for m in t_dictionary.keys():               # Checks word found and its multiplier
            if m == "second(s)":                    # converts to seconds
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
        return model                                # returns the model of the switch

    @staticmethod
    def facts_hostname(string):
        if string.__contains__("hostname"):
            hostname = FastIronDriver.retrieve_all_locations(string, "hostname", 0)[0]
            return hostname                         # returns the hostname if configured
        else:
            return None

    @staticmethod
    def facts_os_version(string):
        os_version = FastIronDriver.retrieve_all_locations(string, "SW:", 1)[0]
        return os_version                           # returns the os_version of switch

    @staticmethod
    def facts_serial(string):
        serial = FastIronDriver.retrieve_all_locations(string, "Serial", 0)[0]
        serial = serial.replace('#:', '')
        return serial                               # returns serial number

    @staticmethod
    def facts_interface_list(shw_int_brief, pos=0, del_word="Port", trigger=0):
        interfaces_list = list()
        n_line_output = FastIronDriver.creates_list_of_nlines(shw_int_brief)
        interface_details = FastIronDriver.delete_if_contains(n_line_output, del_word)

        for port_det in interface_details:

            if trigger == 0:
                interfaces_list.append(port_det[pos])
            else:
                if port_det[pos].__contains__("ve") or port_det[pos].__contains__("lb") or \
                        port_det[pos].__contains__("tunnel"):   # removes non physical interface
                    continue
                else:
                    interfaces_list.append(port_det[pos])       # adds phys interface to list
        return interfaces_list

    @staticmethod
    def port_time(shw_int_port):
        t_port = list()                                         # Creates n lines of show int port
        new_lines = FastIronDriver.creates_list_of_nlines(shw_int_port)

        for val in new_lines:
            if val .__contains__("name"):           # If line contains "name" is skipped
                continue
            t_port.append(FastIronDriver.facts_uptime(val))     # adds time to ports

        return t_port

    @staticmethod
    def get_interface_speed(shw_int_speed):
        speed = list()                                          # creates list
        for val in shw_int_speed:                               # speed words contained and compared
            if val == 'auto,' or val == '1Gbit,':               # appends speed hat
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
        port_stat = list()                          # Creates list
        for line in shw_int_brief:                  # input has a n x 1 of words
            if line == "Up":
                port_stat.append(True)              # appends true if up false if port is down
            else:
                port_stat.append(False)
        return port_stat                            # returns list of port status "up/down"

    @staticmethod
    def get_interfaces_en(shw_int_brief):
        port_status = list()                        # creates list
        for line in shw_int_brief:                  # input is a n x 1 of words
            if line == "None" or line == "N/A":     # if either match is found reports false
                port_status.append(False)
            else:
                port_status.append(True)            # Otherwise true
        return port_status                          # return port status

    @staticmethod
    def unite_strings(output):
        """ removes all the new line and excess spacing in a string"""
        my_string = ""                              # empty string

        for index in range(len(output)):            # iterates through all characters of output

            if output[index] != '\n' and output[index] != ' ':  # skips newline and spaces
                my_string += output[index]

            if index != len(output) - 1:
                if output[index] == ' ' and output[index+1] != ' ':
                    my_string += ' '                # next char of string is not another space

        return my_string                            # returns stored string

    @staticmethod
    def get_interface_flap(shw_int_up, shw_int_flapped):
        port_status = list()                            # creates list

        for val in range(0, len(shw_int_up)):           # will use index iterate
            if shw_int_up[val] == "Down":               # checks if current value is "down"
                port_status.append(-1)
            else:
                if val < len(shw_int_flapped):
                    port_status.append(shw_int_flapped[val])
                else:
                    port_status.append(-1)              # error if both matrix not same size
        return port_status

    @staticmethod
    def get_interface_name(shw_int_name, size):
        port_status = list()                            # Creates list
        shw_int_name = FastIronDriver.creates_list_of_nlines(shw_int_name)
        for val in shw_int_name:                        # iterates through n lines
            if val .__contains__("No port name"):       # port does not have name
                port_status.append("")                  # appends nothing for port name
            else:
                port_status.append(val.replace("Port name is", ""))     # Removes fluff add name

        for temp in range(0, size - len(port_status)):  # adds no names to the remainder so that
            port_status.append("")                      # all matrix of data are the same size

        return port_status

    @staticmethod
    def is_greater(value, threshold):               # compares two values returns true if value
        if float(value) >= float(threshold):        # is greater or equal to threshold
            return True
        return False

    @staticmethod
    def get_interfaces_speed(shw_int_speed, size):
        port_status = list()                            # Create a list
        for val in range(0, size):
            if val < len(shw_int_speed):
                port_status.append(shw_int_speed[val])  # appends string index into port list
            else:
                port_status.append(0)
        return port_status                              # returns port list

    @staticmethod
    def matrix_format(my_input):
        my_list = list()
        newline = FastIronDriver.creates_list_of_nlines(my_input)
        for text in newline:                            # Goes through n lines by n lines
            text = text.split()                         # splits long string into words
            if len(text) < 1:                           # if more than a single word skip
                continue
            else:
                my_list.append(text)                    # appends single word

        return my_list                                  # returns list

    @staticmethod
    def environment_temperature(string):
        dic = dict()
        temp = FastIronDriver.retrieve_all_locations(string, "(Sensor", -3)
        warning = FastIronDriver.retrieve_all_locations(string, "Warning", 1)
        shutdown = FastIronDriver.retrieve_all_locations(string, "Shutdown", 1)
        for val in range(0, len(temp)):
            crit = FastIronDriver.is_greater(temp[val], shutdown[0])
            alert = FastIronDriver.is_greater(temp[val], warning[0])
            dic.update({'sensor ' + str(val + 1): {'temperature': float(temp[val]),
                                                   'is_alert': alert,
                                                   'is_critical': crit}})

        return {'temperature': dic}                     # returns temperature of type dictionary

    @staticmethod
    def environment_cpu(string):
        cpu = max(FastIronDriver.retrieve_all_locations(string, "percent", -2))
        dic = {'%usage': cpu}
        return {'cpu': dic}                             # returns dictionary with key cpu

    @staticmethod
    def environment_power(chassis_string, inline_string):
        status = FastIronDriver.retrieve_all_locations(chassis_string, "Power", 4)
        potential_values = FastIronDriver.retrieve_all_locations(chassis_string, "Power", 1)
        norm_stat = FastIronDriver.retrieve_all_locations(chassis_string, "Power", 7)
        capacity = float(FastIronDriver.retrieve_all_locations(inline_string,
                                                               "Free", -4)[0]) / 1000
        pwr_used = capacity - float(FastIronDriver.retrieve_all_locations(inline_string,
                                                                          "Free", 1)[0]) / 1000

        my_dic = {}  # creates new list
        for val in range(0, len(status)):               # if power supply has failed will return
            if status[val] == 'failed':                 # false, if working will return true
                my_dic["PSU" + potential_values[val]] = {'status': False,
                                                         'capacity': 0.0,
                                                         'output': 0.0}
            elif norm_stat[val] == "ok":
                my_dic["PS" + potential_values[val]] = {'status': True,
                                                        'capacity': capacity,
                                                        'output': pwr_used}

        return {'power': my_dic}                        # returns dictionary containing pwr info

    @staticmethod
    def fast_find(input_string, word):
        index_list = list()                             # creates a list
        input_string = input_string.split()             # breaks input into list of strings
        for val in range(len(input_string)):            # iterates depending on size
            if input_string[val] == word:               # if word is contained in list of words
                index_list.append(val)                  # append to index
        return index_list                               # returns list

    @staticmethod
    def environment_fan(string):
        fan = FastIronDriver.retrieve_all_locations(string, "Fan", 1)
        unit = FastIronDriver.retrieve_all_locations(string, "Fan", 0)
        my_dict = {}  # creates list

        if string.__contains__("Fanless"):              # If string input contains word fanless
            return {"fan": {None}}                      # no fans are in unit and returns None

        for val in range(0, len(fan)):
            if fan[val] == "ok,":                       # checks if output is failed or ok
                my_dict["fan" + unit[val]] = {'status': True}
            elif fan[val] == "failed":                  # if fan fails, will return false
                my_dict["fan" + unit[val]] = {'status': False}

        return {'fan': my_dict}                         # returns dictionary containing fan info

    @staticmethod
    def environment_memory(string):
        mem_total = FastIronDriver.retrieve_all_locations(string, "Dynamic", 1)
        mem_used = FastIronDriver.retrieve_all_locations(string, "Dynamic", 4)
        dic = {'available_ram': int(mem_total[0]), 'used_ram': int(mem_used[0])}

        return {'memory': dic}

    @staticmethod
    def output_parser(output, word):
        """If the word is found in the output, it will return the ip address until a new interface is found
        for example."""
        token = output.find(word) + len(word)           # saves pos of where word is contained
        count = 0                                       # counter variable
        output = output[token:len(output)].replace('/', ' ')
        nline = FastIronDriver.creates_list_of_nlines(output)
        ip6_dict = dict()                               # creates dictionary

        for sentence in nline:                          # separated n lines goes n line by n line
            sentence = sentence.split()                 # sentence contains list of words

            if len(sentence) > 2:                       # if length of list is greater than 2
                count += 1                              # its a parent interface
                if count > 1:                           # only a single parent interface at a time
                    break                               # breaks if another parent interface found
                ip6_dict.update({                       # Update ipv6 dict with ipv6 add and mask
                        sentence[2]: {'prefix_length': sentence[3]}
                })
            if len(sentence) == 2:                      # child ipv6 interface is found
                ip6_dict.update({                       # updates dictionary with ipv6 and mask
                        sentence[0]: {'prefix_length': sentence[1]}
                })

        return ip6_dict                                 # returns ipv6 dictionary

    @staticmethod
    def creates_config_block(list_1):
        config_block = list()
        temp_block = list()

        for line_cmd in list_1:
            cmd_position = list_1.index(line_cmd)
            if cmd_position != 0:
                if list_1[cmd_position - 1] == '!':
                    while list_1[cmd_position] != '!' and cmd_position < len(list_1) - 1:
                        temp_block.append(list_1[cmd_position])
                        cmd_position += 1

                    if len(temp_block) > 0:
                        config_block.append(temp_block)
                    temp_block = list()

        return config_block

    @staticmethod
    def comparing_list(list_1, list_2, symbol):
        diff_list = list()
        config_blocks_1 = FastIronDriver.creates_config_block(list_1)
        config_blocks_2 = FastIronDriver.creates_config_block(list_2)

        for cb_1 in config_blocks_1:                # Grabs a single config block
            is_found = False
            temp_list = list()

            if cb_1 not in config_blocks_2:         # checks if config block already exisit
                cmd = cb_1[0]                       # grabs first cmd of config block

                for cb_2 in config_blocks_2:        # grabs a single config block
                    if cmd == cb_2[0]:              # checks cmd not found
                        is_found = True
                        for single_cmd in cb_1:     # iterates through cmd of config block
                            if single_cmd == cmd:   # if this is first command add as base
                                temp_list.append(single_cmd)    # add to list with no changes
                            elif single_cmd not in cb_2:
                                temp_list.append(symbol + " " + single_cmd)

                if is_found == 0:
                    for value in cb_1:
                        temp_list.append(symbol + " " + value)

            if len(temp_list) > 1:
                diff_list.append(temp_list)

        return diff_list

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
        file_content = ""

        if filename is None and config is None:             # if nothing is entered returns none
            print("No filename or config was entered")
            return None

        if filename is not None:
            try:
                file_content = open(filename, "r")          # attempts to open file
                temp = file_content.read()                  # stores file content
                self.config_replace = FastIronDriver.creates_list_of_nlines(temp)
                self.replace_config = True                  # file opened successfully
                return
            except ValueError:
                raise ReplaceConfigException("Configuration error")

        if config is not None:
            try:
                self.config_replace = FastIronDriver.creates_list_of_nlines(config)
                self.replace_config = True                  # string successfully saved
                return
            except ValueError:
                raise ReplaceConfigException("Configuration error")

        raise ReplaceConfigException("Configuration error")

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
        file_content = ""

        if filename is None and config is None:             # if nothing is entered returns none
            print("No filename or config was entered")
            return None

        if filename is not None:
            try:
                file_content = open(filename, "r")          # attempts to open file
                temp = file_content.read()                  # stores file content
                self.config_merge = FastIronDriver.creates_list_of_nlines(temp)
                self.merge_config = True                    # file opened successfully
                return
            except ValueError:
                raise MergeConfigException("Configuration error")

        if config is not None:
            try:
                self.config_merge = FastIronDriver.creates_list_of_nlines(config)
                self.merge_config = True                    # string successfully saved
                return
            except ValueError:
                raise MergeConfigException("Configuration error")

        raise MergeConfigException("Configuration error")

    def compare_config(self):                               # optimize implementation
        """
        :return: A string showing the difference between the running configuration and the \
        candidate configuration. The running_config is loaded automatically just before doing the \
        comparison so there is no need for you to do it.
        """
        # compare_list = list()
        if self.replace_config is not True and self.merge_config is not True:
            return -1                           # Configuration was never loaded

        mystring = ""
        running_config = FastIronDriver.get_config(self, 'running')
        rc = running_config.get('running')
        stored_conf = None

        if self.replace_config is True:
            stored_conf = self.config_replace
        elif self.merge_config is True:
            stored_conf = self.config_merge
        else:
            return -1                           # No configuration was found

        diff_1 = FastIronDriver.comparing_list(rc, stored_conf, "+")
        diff_2 = FastIronDriver.comparing_list(stored_conf, rc, "-")

        for cb_1 in diff_1:
            mystring += cb_1[0] + '\n'
            for cb_2 in diff_2:
                if cb_1[0] in cb_2:
                    for value_2 in range(1, len(cb_2)):
                        mystring += cb_2[value_2] + '\n'
            for input_1 in range(1, len(cb_1)):
                mystring += cb_1[input_1] + '\n'

        for cb_2 in diff_2:
            found = False
            for cb_1 in diff_1:
                if cb_2[0] in cb_1:
                    found = True

            if found == 0:
                for input_2 in cb_2:
                    mystring += input_2 + '\n'

        return mystring

    def commit_config(self):
        """
        Commits the changes requested by the method load_replace_candidate or load_merge_candidate.
        """
        if self.replace_config is False and self.merge_config is False:
            print("Please replace or merge a configuration ")
            return -1                                           # returns failure

        if self.replace_config is not False:
            replace_list = list()

            diff_in_config = FastIronDriver.compare_config(self)
            my_temp = FastIronDriver.creates_list_of_nlines(diff_in_config)

            for sentence in my_temp:

                if sentence[0] == '-':
                    sentence = sentence[1:len(sentence)]
                elif sentence[0] == '+':
                    sentence = 'no' + sentence[1:len(sentence)]
                replace_list.append(sentence)

            self.device.config_mode()
            self.device.send_config_set(replace_list)

            return True

        if self.merge_config is not False:  # merges candidate configuration with existing config
            self.device.config_mode()
            self.device.send_config_set(self.config_merge)

            return True                     # returns success

    def discard_config(self):
        """
        Discards the configuration loaded into the candidate.
        """
        self.config_merge = None
        self.config_replace = None
        self.replace_config = False
        self.merge_config = False

    def rollback(self):
        """
        If changes were made, revert changes to the original state.
        """
        filename = self.rollback_cfg

        if filename is not None:
            try:
                file_content = open(filename, "r")          # attempts to open file
                temp = file_content.read()                  # stores file content
                # sends configuration
                self.device.send_command(temp)

                # Save config to startup
                self.device.send_command_expect("write mem")
            except ValueError:
                raise MergeConfigException("Configuration error")
        else:
            print("no rollback file found, please insert")

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
        version_output = self.device.send_command('show version')   # show version output
        interfaces_up = self.device.send_command('show int brief')  # show int brief output
        host_name = self.device.send_command('show running | i hostname')

        return{
            'uptime': FastIronDriver.facts_uptime(version_output),  # time of device in sec
            'vendor': 'Ruckus',                                     # Vendor of ICX switches
            'model':  FastIronDriver.facts_model(version_output),   # Model type of switch
            'hostname':  FastIronDriver.facts_hostname(host_name),  # Host name if configured
            'fqdn': None,
            'os_version':  FastIronDriver.facts_os_version(version_output),
            'serial_number':  FastIronDriver.facts_serial(version_output),
            'interface_list':  FastIronDriver.facts_interface_list(interfaces_up)
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
        interfaces = FastIronDriver.facts_interface_list(int_brief)
        int_up = FastIronDriver.facts_interface_list(int_brief, pos=1, del_word="Link")
        mac_ad = FastIronDriver.facts_interface_list(int_brief, pos=9, del_word="MAC")
        flapped = FastIronDriver.port_time(flap_output)
        size = len(interfaces)

        is_en = FastIronDriver.facts_interface_list(int_brief, pos=2, del_word="State")
        int_speed = FastIronDriver.facts_interface_list(speed_output, pos=2)
        actual_spd = FastIronDriver.get_interface_speed(int_speed)

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
        main_dictionary = {}
        chassis_output = self.device.send_command('show chassis')
        cpu_output = self.device.send_command('show cpu')
        mem_output = self.device.send_command('show memory')
        pwr_output = self.device.send_command('show inline power')
        main_dictionary.update(FastIronDriver.environment_fan(chassis_output))
        main_dictionary.update(FastIronDriver.environment_temperature(chassis_output))
        main_dictionary.update(FastIronDriver.environment_power(chassis_output, pwr_output))
        main_dictionary.update(FastIronDriver.environment_cpu(cpu_output))
        main_dictionary.update(FastIronDriver.environment_memory(mem_output))

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
        int_output = self.device.send_command('show interface brief')
        ports = FastIronDriver.facts_interface_list(int_output, trigger=1)
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
                'tx_discards': None,    # discard is not put in output of current show int
                'rx_discards': None,    # alternative is to make individual calls which break
                'tx_octets': None,
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

        e_token_sd = output.find("System description") + len("System description")
        s_token_sc = output.find("System capabilities")
        e_token_sc = output.find("System capabilities") + len("System capabilities")
        s_token_ma = output.find("Management address")
        s_token_la = output.find("Link aggregation")
        e_token_pd = output.find("Port description") + len("Port description")

        sys_des = output[e_token_sd:s_token_sc]                 # grabs system description
        sys_cap = output[e_token_sc:s_token_ma]                 # grabs system capability
        port_de = output[e_token_pd:s_token_la]                 # grabs ports description

        sys_des = FastIronDriver.unite_strings(sys_des)     # removes excess spaces and n lines
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
        output = self.device.send_command('show ntp associations')
        token = output.find('disp') + len('disp') + 1
        output = output[token:len(output)]
        nline = FastIronDriver.creates_list_of_nlines(output)
        ntp_peers = dict()
        for val in range(len(nline)-1):
            val = nline[val].replace("~", " ")
            val = val.split()
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
        output = self.device.send_command('show ntp associations')
        token = output.find('disp') + len('disp') + 1
        output = output[token:len(output)]
        nline = FastIronDriver.creates_list_of_nlines(output)
        ntp_servers = dict()
        for val in range(len(nline)-1):
            val = nline[val].replace("~", " ")
            val = val.split()
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

        ip_interface = dict()
        ip4_dict = dict()                                       # ip4 dict
        ip6_dict = dict()                                       # ip6 dict
        output = self.device.send_command('show ip interface')  # obtains ip4 information
        ipv6_output = self.device.send_command('show ipv6 interface')   # obtains ip6 information
        token = output.find('VRF') + len('VRF') + 4                 # finds when to start parsing
        output = output[token:len(output)]              # grabs output within certain limits
        n_line = FastIronDriver.creates_list_of_nlines(output)
        last_port = ""                                          # saves last port information

        for index in range(len(n_line)):
            pos = 0                             # if interface more than one IP, list is size 1
            sentence = n_line[index].split()                    # creates word list from string

            if len(sentence) == 0:                              # if empty skip
                continue

            if len(sentence) > 2:                               # parent interface,size not 1
                last_port = sentence[0] + " " + sentence[1]     # grabs port description
                pos = 2                                         # New position of IP address

                if ipv6_output.__contains__(last_port):         # will return ipv6 address
                    ip6_dict = FastIronDriver.output_parser(ipv6_output, last_port)

            ip4_dict.update({                                   # updates ipv4 dictionary
                    sentence[pos]: {'prefix_length': None}
            })

            if index == (len(n_line) - 1) or len(n_line[index + 1].split()) > 2:
                ip_interface.update({       # if new parent interface is next
                    last_port: {            # save all current interfaces
                        'ipv4': ip4_dict,
                        'ipv6': ip6_dict}
                })
                ip4_dict = dict()           # resets dictionary
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
        for words in new_out:                            # loop goes sentence by sentence
            sentence = words.split()                                # breaks sentence into words

            if sentence[2] == 'Dynamic':
                is_dynamic = True
            else:
                is_dynamic = False

            if sentence[4] == 'forward':
                is_active = True
            else:
                is_active = False

            mac_tbl.append({                            # appends data
                'mac': sentence[0],
                'interface': sentence[1],
                'vlan': sentence[3],
                'static': is_dynamic,
                'active': is_active,
                'moves': None,
                'last_move': None
            })

        return mac_tbl

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
        vrf_dict = dict()                                           # Dictionary that will append
        vrf_interface = dict()
        check = self.device.send_command('show version')

        if check.__contains__('7150'):                              # ICX7150 does not support VRF
            return {}

        if check.__contains__('SPR'):                               # check if router version
            vrf_type = 'L3VRF'                                      # adds vrf of type router
        else:
            vrf_type = 'L2VRF'                                      # adds vrf of type switch

        if name != '':                                              # Name was entered must look
            output = self.device.send_command('show vrf ' + name)   # grabs vrf of specified name
            token = output.find('Interfaces:') + len('Interfaces:') + 1
            ioutput = output[token:len(output)]                     # limits scope of output range
            sentence = ioutput.split()                              # returns strings of interest
            rid = FastIronDriver.retrieve_all_locations(output, 'RD', 0)[0]
            rid = rid.replace(',', '')

            for interface in sentence:
                vrf_interface.update({interface: {}})

            return {
                name: {
                    u'name': name, u'type': vrf_type, u'state': {
                        u'route_distinguisher': rid
                    },
                    u'interfaces': {
                        vrf_interface
                        }}}

        else:
            output = self.device.send_command('show vrf detail')
            # ftoken = output.find('Total number of IPv4')
            output = output.replace('|', ' ')
            output = output.replace(',', '')
            vrf_name_list = FastIronDriver.retrieve_all_locations(output, 'VRF', 0)
            vrf_rd = FastIronDriver.retrieve_all_locations(output, 'RD', 0)

        for interface in range(0, len(vrf_name_list)):
            vrf = vrf_name_list.pop()                                   # pops the next vrf name
            rd = vrf_rd.pop()                                           # pops the next router id
            vrf_dict.update({                                           # updates the dictionary
                vrf: {
                    u'name': vrf, u'type': vrf_type, u'state': {
                        u'route_distinguisher': rd
                    },
                    u'interfaces': {
                        u'interface': {
                            '': {}
                        }
                    }
                }
            })

        return vrf_dict
