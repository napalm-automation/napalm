"""
Fork of pynxos library from network to code and mzbenami

Reimplemented by ktbyers to support XML-RPC in addition to JSON-RPC
"""
from __future__ import print_function, unicode_literals

from builtins import super
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectionError
import json

from lxml import etree

from six import string_types

from napalm.nxapi_plumbing.errors import (
    NXAPIError,
    NXAPIPostError,
    NXAPICommandError,
    NXAPIXMLError,
    NXAPIAuthError,
    NXAPIConnectionError,
)


class RPCBase(object):
    """RPCBase class should be API-type neutral (i.e. shouldn't care whether XML or jsonrpc)."""

    def __init__(
        self,
        host,
        username,
        password,
        transport="https",
        port=None,
        timeout=30,
        verify=True,
    ):
        if transport not in ["http", "https"]:
            raise NXAPIError("'{}' is an invalid transport.".format(transport))

        if port is None:
            if transport == "http":
                port = 80
            elif transport == "https":
                port = 443

        self.url = "{}://{}:{}/ins".format(transport, host, port)
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify = verify

    def _process_api_response(self, response, commands, raw_text=False):
        raise NotImplementedError("Method must be implemented in child class")

    def _send_request(self, commands, method):
        payload = self._build_payload(commands, method)

        try:
            response = requests.post(
                self.url,
                timeout=self.timeout,
                data=payload,
                headers=self.headers,
                auth=HTTPBasicAuth(self.username, self.password),
                verify=self.verify,
            )
        except ConnectionError as e:
            raise NXAPIConnectionError(str(e))

        if response.status_code == 401:
            msg = (
                "Authentication to NX-API failed please verify your username, password, "
                "and hostname."
            )
            raise NXAPIAuthError(msg)

        if response.status_code not in [200]:
            msg = """Invalid status code returned on NX-API POST
commands: {}
status_code: {}""".format(
                commands, response.status_code
            )
            raise NXAPIPostError(msg)

        return response.text


class RPCClient(RPCBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers = {"content-type": "application/json-rpc"}
        self.api = "jsonrpc"
        self.cmd_method = "cli"
        self.cmd_method_conf = "cli"
        self.cmd_method_raw = "cli_ascii"

    def _nxapi_command(self, commands, method=None):
        """Send a command down the NX-API channel."""
        if method is None:
            method = self.cmd_method
        if isinstance(commands, string_types):
            commands = [commands]

        raw_text = True if method == "cli_ascii" else False

        response = self._send_request(commands, method=method)
        api_response = self._process_api_response(response, commands, raw_text=raw_text)
        return api_response

    def _nxapi_command_conf(self, commands, method=None):
        if method is None:
            method = self.cmd_method_conf
        return self._nxapi_command(commands=commands, method=method)

    def _build_payload(self, commands, method, rpc_version="2.0", api_version=1.0):
        """Construct the JSON-RPC payload for NX-API."""
        payload_list = []
        id_num = 1
        for command in commands:
            payload = {
                "jsonrpc": rpc_version,
                "method": method,
                "params": {"cmd": command, "version": api_version},
                "id": id_num,
            }
            payload_list.append(payload)
            id_num += 1

        return json.dumps(payload_list)

    def _process_api_response(self, response, commands, raw_text=False):
        """
        Normalize the API response including handling errors; adding the sent command into
        the returned data strucutre; make response structure consistent for raw_text and
        structured data.
        """

        response_list = json.loads(response)
        if isinstance(response_list, dict):
            response_list = [response_list]

        # Add the 'command' that was executed to the response dictionary
        for i, response_dict in enumerate(response_list):
            response_dict["command"] = commands[i]

        new_response = []
        for response in response_list:

            # Dectect errors
            self._error_check(response)

            # Some commands like "show run" can have a None result
            cmd_response = response.get("result")
            if cmd_response is None:
                cmd_response = {}

            # Normalize the response data structure
            response_dict = {"command": response["command"]}
            if response and raw_text:
                response_dict["result"] = cmd_response.get("msg")
            elif response and not raw_text:
                response_dict["result"] = cmd_response.get("body")
            else:
                raise NXAPIError("Unexpected value encountered processing response.")
            new_response.append(response_dict)

        return new_response

    def _error_check(self, command_response):
        error = command_response.get("error")
        if error:
            command = command_response.get("command")
            if "data" in error:
                raise NXAPICommandError(command, error["data"]["msg"])
            else:
                raise NXAPICommandError(command, "Invalid command.")


class XMLClient(RPCBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers = {"content-type": "application/xml"}
        self.api = "xml"
        self.cmd_method = "cli_show"
        self.cmd_method_conf = "cli_conf"
        self.cmd_method_raw = "cli_show_ascii"

    def _nxapi_command(self, commands, method=None):
        """Send a command down the NX-API channel."""
        if method is None:
            method = self.cmd_method
        if isinstance(commands, string_types):
            commands = [commands]

        response = self._send_request(commands, method=method)
        api_response = self._process_api_response(response, commands)

        for command_response in api_response:
            self._error_check(command_response)
        return api_response

    def _nxapi_command_conf(self, commands, method=None):
        if method is None:
            method = self.cmd_method_conf
        return self._nxapi_command(commands=commands, method=method)

    def _build_payload(self, commands, method, xml_version="1.0", version="1.0"):
        xml_commands = ""
        for command in commands:
            if not xml_commands:
                # initial command is just the command itself
                xml_commands += command
            else:
                # subsequent commands are separate by semi-colon
                xml_commands += " ;{}".format(command)

        payload = """<?xml version="{xml_version}"?>
            <ins_api>
                <version>{version}</version>
                <type>{method}</type>
                <chunk>0</chunk>
                <sid>sid</sid>
                <input>{command}</input>
                <output_format>xml</output_format>
            </ins_api>""".format(
            xml_version=xml_version,
            version=version,
            method=method,
            command=xml_commands,
        )
        return payload

    def _process_api_response(self, response, commands, raw_text=False):
        xml_root = etree.fromstring(response)
        response_list = xml_root.xpath("outputs/output")
        if len(commands) != len(response_list):
            raise NXAPIXMLError(
                "XML response doesn't match expected number of commands."
            )

        return response_list

    def _error_check(self, command_response):
        """commmand_response will be an XML Etree object."""
        error_list = command_response.find("./clierror")
        command_obj = command_response.find("./input")
        if error_list is not None:
            command = command_obj.text if command_obj is not None else "Unknown command"
            msg = etree.tostring(error_list).decode()
            raise NXAPICommandError(command, msg)
