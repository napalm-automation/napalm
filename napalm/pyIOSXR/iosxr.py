# -*- coding: utf-8 -*-
# Copyright 2015 Netflix. All rights reserved.
# Copyright 2016 BigWaveIT. All rights reserved.
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

"""
Contains the main IOS-XR driver class.

Forked from https://github.com/fooelisa/pyiosxr 2019-09-22

Contributors fooelisa, mirceaulinic, et all
"""

# stdlib
import re
import time
import difflib
import logging
from threading import Lock
from xml.sax.saxutils import escape as escape_xml


# third party lib
from lxml import etree as ET
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException
from netmiko.ssh_exception import NetMikoAuthenticationException

# local modules
from napalm.pyIOSXR.exceptions import LockError
from napalm.pyIOSXR.exceptions import UnlockError
from napalm.pyIOSXR.exceptions import XMLCLIError
from napalm.pyIOSXR.exceptions import CommitError
from napalm.pyIOSXR.exceptions import ConnectError
from napalm.pyIOSXR.exceptions import TimeoutError
from napalm.pyIOSXR.exceptions import IteratorIDError
from napalm.pyIOSXR.exceptions import InvalidInputError
from napalm.pyIOSXR.exceptions import InvalidXMLResponse

logger = logging.getLogger(__name__)


class IOSXR(object):
    """
    Establishes a connection with the IOS-XR device via SSH and facilitates the communication
    through the XML agent.
    """

    _XML_SHELL = "xml"
    _XML_MODE_PROMPT = r"XML>"
    _READ_DELAY = 0.1  # at least 0.1, corresponding to 600 max loops (60s timeout)
    _XML_MODE_DELAY = 1  # should be able to read within one second

    _ITERATOR_ID_ERROR_MSG = (
        "Non-supported IteratorID in response object. "
        'Turn iteration off on your XML agent by configuring "xml agent [tty | ssl] iteration off".'
        " For more information refer to "
        "http://www.cisco.com/c/en/us/td/docs/ios_xr_sw/iosxr_r4-1/xml/"
        "programming/guide/xl41apidoc.pdf, page 7-99. "
        "Please turn iteration off for the XML agent."
    )

    def __init__(
        self,
        hostname,
        username,
        password,
        port=22,
        timeout=60,
        logfile=None,
        lock=True,
        **netmiko_kwargs
    ):
        """
        IOS-XR device constructor.

        :param hostname:  (str) IP or FQDN of the target device
        :param username:  (str) Username
        :param password:  (str) Password
        :param port:      (int) SSH Port (default: 22)
        :param timeout:   (int) Timeout (default: 60 sec)
        :param logfile:   File-like object to save device communication to or None to disable
                          logging
        :param lock:      (bool) Auto-lock config upon open() if set to True, connect without
                          locking if False (default: True)
        :netmiko_kwargs   (kwargs) Key-value args to forward to Netmiko.
        """
        self.hostname = str(hostname)
        self.username = str(username)
        self.password = str(password)
        self.port = int(port)
        self.timeout = int(timeout)
        self.logfile = logfile
        self.lock_on_connect = lock
        self.locked = False
        self.netmiko_kwargs = netmiko_kwargs
        self._cli_prompt = None
        self._xml_agent_locker = Lock()
        self._xml_agent_alive = False

    def __getattr__(self, item):
        """
        Dynamic getter to translate generic show commands.

        David came up with this dynamic method. It takes
        calls with show commands encoded in the name. I'll replace the
        underscores for spaces and issues the show command on the device...
        pretty neat!

        non keyword params for show command:
          all non keyword arguments is added to the command to allow dynamic parameters:
          eg: .show_interface("GigabitEthernet0/0/0/0")

        keyword params for show command:
          config=True/False :   set True to run show command in config mode
          eg: .show_configuration_merge(config=True)

        """

        def _getattr(*args, **kwargs):

            cmd = item.replace("_", " ")
            for arg in args:
                cmd += " %s" % arg

            if kwargs.get("config"):
                response = self._execute_config_show(cmd)
            else:
                response = self._execute_show(cmd)

            match = re.search(
                ".*(!! IOS XR Configuration.*)</Exec>", response, re.DOTALL
            )

            if match is not None:
                response = match.group(1)
            return response

        if item.startswith("show"):
            return _getattr
        else:
            raise AttributeError(
                "type object '%s' has no attribute '%s'"
                % (self.__class__.__name__, item)
            )

    def make_rpc_call(self, rpc_command):
        """
        Allow a user to query a device directly using XML-requests.

        :param rpc_command: (str) rpc command such as:
                                  <Get><Operational><LLDP><NodeTable></NodeTable></LLDP></Operational></Get>
        """
        # ~~~ hack: ~~~
        if not self.is_alive():
            logger.debug("Force closing tunnel before making RPC Call")
            self.close()  # force close for safety
            self.open()  # reopen
            logger.debug("Re-opening tunnel before making RPC Call")
        # ~~~ end hack ~~~
        result = self._execute_rpc(rpc_command)
        logger.debug(result)
        return ET.tostring(result)

    def open(self):
        """
        Open a connection to an IOS-XR device.

        Connects to the device using SSH and drops into XML mode.
        """
        try:
            self.device = ConnectHandler(
                device_type="cisco_xr",
                ip=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                global_cmd_verify=False,
                **self.netmiko_kwargs
            )
            self.device.timeout = self.timeout
            self._xml_agent_alive = True  # successfully open thus alive
        except NetMikoTimeoutException as t_err:
            logger.error(t_err.args[0])
            raise ConnectError(t_err.args[0])
        except NetMikoAuthenticationException as au_err:
            logger.error(au_err.args[0])
            raise ConnectError(au_err.args[0])

        self._cli_prompt = self.device.find_prompt()  # get the prompt
        self._enter_xml_mode()

    def is_alive(self):
        """
        Returns the XML agent connection state (and SSH connection state).
        """
        if hasattr(self.device, "remote_conn"):
            return (
                self.device.remote_conn.transport.is_active() and self._xml_agent_alive
            )
        return False  # remote_conn not there => connection not init => not alive

    def _timeout_exceeded(self, start=None, msg="Timeout exceeded!"):
        if not start:
            return False  # reference not specified, noth to compare => no error
        if time.time() - start > self.timeout:
            # it timeout exceeded, throw TimeoutError
            raise TimeoutError(msg, self)
        return False

    def _lock_xml_agent(self, start=None):
        while not self._xml_agent_locker.acquire(False) and not self._timeout_exceeded(
            start, "Waiting to acquire the XML agent!"
        ):
            # will wait here till the XML agent is ready to receive new requests
            # if stays too much, _timeout_exceeded will raise TimeoutError
            pass  # do nothing, just wait
        return True  # ready to go now

    def _unlock_xml_agent(self):
        if self._xml_agent_locker.locked():
            self._xml_agent_locker.release()

    def _send_command_timing(self, command):

        return self.device.send_command_timing(
            command,
            delay_factor=self._READ_DELAY,
            max_loops=self._XML_MODE_DELAY / self._READ_DELAY,
            strip_prompt=False,
            strip_command=False,
        )

    def _in_cli_mode(self):

        out = self._send_command_timing("\n")
        if not out:
            return False
        if self._cli_prompt in out:
            return True
        return False

    def _enter_xml_mode(self):

        self._unlock_xml_agent()
        # release - other commands should not have anyway access to the XML agent
        # when not in XML mode
        self._lock_xml_agent()  # make sure it won't collide with other parallel requests

        out = self._send_command_timing(self._XML_SHELL)  # send xml shell command

        if "0x24319600" in out:
            # XML agent is not enabled
            raise ConnectError(
                "XML agent is not enabled. Please configure `xml agent tty iteration off`!",
                self,
            )

        self._unlock_xml_agent()

        if self.lock_on_connect:
            self.lock()

    def _send_command(
        self,
        command,
        delay_factor=None,
        start=None,
        expect_string=None,
        read_output=None,
        receive=False,
    ):

        if not expect_string:
            expect_string = self._XML_MODE_PROMPT

        if read_output is None:
            read_output = ""

        if not delay_factor:
            delay_factor = self._READ_DELAY

        if not start:
            start = time.time()

        output = read_output

        last_read = ""

        if not read_output and not receive:
            # because the XML agent is able to process only one single request over the same SSH
            # session at a time first come first served
            self._lock_xml_agent(start)
            try:
                max_loops = self.timeout / delay_factor
                last_read = self.device.send_command_expect(
                    command,
                    expect_string=expect_string,
                    strip_prompt=False,
                    strip_command=False,
                    delay_factor=delay_factor,
                    max_loops=max_loops,
                )
                output += last_read
            except IOError:
                if (not last_read and self._in_cli_mode()) or (
                    self._cli_prompt in output
                    and "% Invalid input detected at '^' marker." in output
                ):
                    # something happened
                    # e.g. connection with the XML agent died while reading
                    # netmiko throws error and the last output read is empty (ofc)
                    # and in CLI mode
                    #
                    # OR
                    #
                    # Sometimes the XML agent simply exits and all issued commands provide the
                    #  following output (as in CLI mode)
                    # <?
                    #       ^
                    # % Invalid input detected at '^' marker.
                    # RP/0/RSP1/CPU0:edge01.dus01#<xml version="1.0" encoding="UTF-8"?
                    #                             ^
                    # % Invalid input detected at '^' marker.
                    # RP/0/RSP1/CPU0:edge01.dus01#<xml version
                    #
                    # Which of course does not contain the XML and netmiko throws the not found
                    # error therefore we need to re-enter in XML mode
                    self._enter_xml_mode()
                    # and let's issue the command again if still got time
                    if not self._timeout_exceeded(start=start):
                        # if still got time
                        # reiterate the command from the beginning
                        return self._send_command(
                            command,
                            expect_string=expect_string,
                            delay_factor=delay_factor,
                        )
        else:
            output += self._netmiko_recv()  # try to read some more

        if "0xa3679e00" in output or "0xa367da00" in output:
            # when multiple parallel request are made, the device throws one of the the errors:
            # ---
            # ERROR: 0xa3679e00 'XML Service Library' detected the 'fatal' condition
            # 'Multiple concurrent requests are not allowed over the same session.
            # A request is already in progress on this session.'
            #
            # ERROR: 0xa367da00 XML Service Library' detected the 'fatal' condition
            # 'Sending multiple documents is not supported.'
            # ---
            # we could use a mechanism similar to NETCONF and push the requests in queue and serve
            # them sequentially, BUT we are not able to assign unique IDs and identify the
            # request-reply map so will throw an error that does not help too much :(
            raise XMLCLIError("XML agent cannot process parallel requests!", self)

        if not output.strip().endswith("XML>"):
            if "0x44318c06" in output or (
                self._cli_prompt
                and expect_string != self._cli_prompt
                and (
                    output.startswith(self._cli_prompt)
                    or output.endswith(self._cli_prompt)
                )
            ):
                # sometimes the device throws a stupid error like:
                # ERROR: 0x44318c06 'XML-TTY' detected the 'warning' condition
                # 'A Light Weight Messaging library communication function returned an error': No
                # such device or address and the XML agent connection is closed, but the SSH
                # connection is fortunately maintained
                # OR sometimes, the device simply exits from the XML mode without any clue
                # In both cases, we need to re-enter in XML mode...
                # so, whenever the CLI promt is detected, will re-enter in XML mode
                # unless the expected string is the prompt
                self._unlock_xml_agent()
                self._enter_xml_mode()
                # however, the command could not be executed properly, so we need to raise the
                # XMLCLIError exception
                raise XMLCLIError(
                    "Could not properly execute the command. Re-entering XML mode...",
                    self,
                )
            if (
                not output.strip()
            ):  # empty output, means that the device did not start delivering the output
                # but for sure is still in XML mode as netmiko did not throw error
                if not self._timeout_exceeded(start=start):
                    return self._send_command(
                        command, receive=True, start=start
                    )  # let's try receiving more

            raise XMLCLIError(output.strip(), self)

        self._unlock_xml_agent()
        return str(output.replace("XML>", "").strip())

    def _netmiko_recv(self):

        output = ""

        for tmp_output in self.device.receive_data_generator():
            output += tmp_output

        return output

    # previous module function __execute_rpc__
    def _execute_rpc(self, command_xml, delay_factor=0.1):

        xml_rpc_command = (
            '<?xml version="1.0" encoding="UTF-8"?><Request MajorVersion="1" MinorVersion="0">'
            + command_xml
            + "</Request>"
        )

        response = self._send_command(xml_rpc_command, delay_factor=delay_factor)

        try:
            root = ET.fromstring(str.encode(response))
        except ET.XMLSyntaxError:
            if 'IteratorID="' in response:
                logger.error(self._ITERATOR_ID_ERROR_MSG)
                raise IteratorIDError(self._ITERATOR_ID_ERROR_MSG, self)
            raise InvalidXMLResponse(
                "Unable to process the XML Response from the device!", self
            )

        if "IteratorID" in root.attrib:
            logger.error(self._ITERATOR_ID_ERROR_MSG)
            raise IteratorIDError(self._ITERATOR_ID_ERROR_MSG, self)

        childs = [x.tag for x in list(root)]

        result_summary = root.find("ResultSummary")

        if result_summary is not None and int(result_summary.get("ErrorCount", 0)) > 0:

            if "CLI" in childs:
                error_msg = root.find("CLI").get("ErrorMsg") or ""
            elif "Commit" in childs:
                error_msg = root.find("Commit").get("ErrorMsg") or ""
                error_code = root.find("Commit").get("ErrorCode") or ""
                if error_code == "0x41866c00":
                    # yet another pointless IOS-XR error:
                    # if the config DB was changed by another process,
                    # while the current SSH connection is established and alive,
                    # we won't be able to commit and the device will throw the following error:
                    # 'CfgMgr' detected the 'warning' condition
                    # 'One or more commits have occurred from other configuration sessions since
                    # this session started or since the last commit was made from this session.'
                    # in this case we need to re-open the connection with the XML agent
                    _candidate_config = self.get_candidate_config(merge=True)
                    self.discard_config()  # discard candidate config
                    try:
                        # exiting from the XML mode
                        self._send_command("exit", expect_string=self._cli_prompt)
                    except XMLCLIError:
                        pass  # because does not end with `XML>`
                    self._enter_xml_mode()  # re-entering XML mode
                    self.load_candidate_config(config=_candidate_config)
                    return self.commit_config()
                elif error_code == "0x41864e00" or error_code == "0x43682c00":
                    # raises this error when the commit buffer is empty
                    raise CommitError("The target configuration buffer is empty.", self)

            else:
                error_msg = root.get("ErrorMsg") or ""

            error_msg += "\nOriginal call was: %s" % xml_rpc_command
            logger.error(error_msg)
            raise XMLCLIError(error_msg, self)

        if "CLI" in childs:
            cli_childs = [x.tag for x in list(root.find("CLI"))]
            if "Configuration" in cli_childs:
                output = root.find("CLI").find("Configuration").text
            elif "Exec" in cli_childs:
                output = root.find("CLI").find("Exec").text
            if output is None:
                output = ""
            elif "Invalid input detected" in output:
                logger.error("Invalid input entered:\n%s" % (output))
                raise InvalidInputError("Invalid input entered:\n%s" % output, self)

        return root

    # previous module function __execute_show__
    def _execute_show(self, show_command):
        """
        Executes an operational show-type command.
        """
        rpc_command = "<CLI><Exec>{show_command}</Exec></CLI>".format(
            show_command=escape_xml(show_command)
        )
        response = self._execute_rpc(rpc_command)
        raw_response = response.xpath(".//CLI/Exec")[0].text
        return raw_response.strip() if raw_response else ""

    # previous module function __execute_config_show__
    def _execute_config_show(self, show_command, delay_factor=0.1):
        """
        Executes a configuration show-type command.
        """
        rpc_command = "<CLI><Configuration>{show_command}</Configuration></CLI>".format(
            show_command=escape_xml(show_command)
        )
        response = self._execute_rpc(rpc_command, delay_factor=delay_factor)
        raw_response = response.xpath(".//CLI/Configuration")[0].text
        return raw_response.strip() if raw_response else ""

    def close(self):
        """
        Close the connection to the IOS-XR device.

        Clean up after you are done and explicitly close the router connection.
        """
        if self.lock_on_connect or self.locked:
            self.unlock()  # this refers to the config DB
        self._unlock_xml_agent()  # this refers to the XML agent
        if hasattr(self.device, "remote_conn"):
            self.device.remote_conn.close()  # close the underlying SSH session

    def lock(self):
        """
        Lock the config database.

        Use if Locking/Unlocking is not performaed automatically by lock=False
        """
        if not self.locked:
            rpc_command = "<Lock/>"
            try:
                self._execute_rpc(rpc_command)
            except XMLCLIError:
                raise LockError("Unable to enter in configure exclusive mode!", self)
            self.locked = True

    def unlock(self):
        """
        Unlock the IOS-XR device config.

        Use if Locking/Unlocking is not performaed automatically by lock=False
        """
        if self.locked:
            rpc_command = "<Unlock/>"
            try:
                self._execute_rpc(rpc_command)
            except XMLCLIError:
                raise UnlockError("Unable to unlock the config!", self)
            self.locked = False

    def load_candidate_config(self, filename=None, config=None):
        """
        Load candidate confguration.

        Populate the attribute candidate_config with the desired
        configuration and loads it into the router. You can populate it from
        a file or from a string. If you send both a filename and a string
        containing the configuration, the file takes precedence.

        :param filename:  Path to the file containing the desired
                          configuration. By default is None.
        :param config:    String containing the desired configuration.
        """
        configuration = ""

        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()

        rpc_command = "<CLI><Configuration>{configuration}</Configuration></CLI>".format(
            configuration=escape_xml(
                configuration
            )  # need to escape, otherwise will try to load invalid XML
        )

        try:
            self._execute_rpc(rpc_command)
        except InvalidInputError as e:
            self.discard_config()
            raise InvalidInputError(e.args[0], self)

    def get_candidate_config(self, merge=False, formal=False):
        """
        Retrieve the configuration loaded as candidate config in your configuration session.

        :param merge:  Merge candidate config with running config to return
                       the complete configuration including all changed
        :param formal: Return configuration in IOS-XR formal config format
        """
        command = "show configuration"
        if merge:
            command += " merge"
        if formal:
            command += " formal"
        response = self._execute_config_show(command)

        match = re.search(".*(!! IOS XR Configuration.*)$", response, re.DOTALL)
        if match is not None:
            response = match.group(1)

        return response

    def compare_config(self):
        """
        Compare configuration to be merged with the one on the device.

        Compare executed candidate config with the running config and
        return a diff, assuming the loaded config will be merged with the
        existing one.

        :return:  Config diff.
        """
        show_merge = self._execute_config_show("show configuration merge")
        show_run = self._execute_config_show("show running-config")

        show_merge = self.strip_config_header(show_merge)
        show_run = self.strip_config_header(show_run)

        diff = difflib.unified_diff(
            show_run.splitlines(keepends=True), show_merge.splitlines(keepends=True)
        )
        return "".join([x.replace("\r", "") for x in diff])

    @staticmethod
    def strip_config_header(config):
        config = re.sub(r"^Building config.*\n!! IOS.*", "", config, flags=re.M)
        config = config.strip()
        config = re.sub(r"^!!.*", "", config)
        return config.strip()

    def compare_replace_config(self):
        """
        Compare configuration to be replaced with the one on the device.

        Compare executed candidate config with the running config and
        return a diff, assuming the entire config will be replaced.

        :return:  Config diff.
        """
        diff = self._execute_config_show("show configuration changes diff")
        # Strip header lines
        diff = self.strip_config_header(diff)
        # Strip trailer line
        diff = re.sub(r"^end$", "", diff, flags=re.M)
        return diff.strip()

    def commit_config(self, label=None, comment=None, confirmed=None):
        """
        Commit the candidate config.

        :param label:     Commit comment, displayed in the commit entry on the device.
        :param comment:   Commit label, displayed instead of the commit ID on the device.
                          (Max 60 characters)
        :param confirmed: Commit with auto-rollback if new commit is not made in 30 to 300 sec
        """
        rpc_command = "<Commit"
        if label:
            rpc_command += ' Label="%s"' % label
        if comment:
            rpc_command += ' Comment="%s"' % comment[:60]
        if confirmed:
            if 30 <= int(confirmed) <= 300:
                rpc_command += ' Confirmed="%d"' % int(confirmed)
            else:
                raise InvalidInputError(
                    "confirmed needs to be between 30 and 300 seconds", self
                )
        rpc_command += "/>"

        self._execute_rpc(rpc_command)

    def commit_replace_config(self, label=None, comment=None, confirmed=None):
        """
        Commit the candidate config to the device, by replacing the existing one.

        :param comment:   User comment saved on this commit on the device
        :param label:     User label saved on this commit on the device
        :param confirmed: Commit with auto-rollback if new commit is not made in 30 to 300 sec
        """
        rpc_command = '<Commit Replace="true"'
        if label:
            rpc_command += ' Label="%s"' % label
        if comment:
            rpc_command += ' Comment="%s"' % comment
        if confirmed:
            if 30 <= int(confirmed) <= 300:
                rpc_command += ' Confirmed="%d"' % int(confirmed)
            else:
                raise InvalidInputError(
                    "confirmed needs to be between 30 and 300 seconds", self
                )
        rpc_command += "/>"
        self._execute_rpc(rpc_command)

    def discard_config(self):
        """
        Clear uncommited changes in the current session.

        Clear previously loaded configuration on the device without committing it.
        """
        rpc_command = "<Clear/>"
        self._execute_rpc(rpc_command)

    def rollback(self, rb_id=1):
        """
        Rollback the last committed configuration.

        :param rb_id: Rollback a specific number of steps. Default: 1
        """
        rpc_command = "<Unlock/><Rollback><Previous>{rb_id}</Previous></Rollback><Lock/>".format(
            rb_id=rb_id
        )
        self._execute_rpc(rpc_command)
