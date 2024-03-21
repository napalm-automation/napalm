"""
Fork of pynxos library from network to code and mzbenami

Reimplemented by ktbyers to support XML-RPC in addition to JSON-RPC
"""

from __future__ import print_function, unicode_literals

from builtins import super
from typing import Optional, List, Dict, Any

import requests
from requests import Response
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectionError
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
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
        host: str,
        username: str,
        password: str,
        transport: str = "https",
        port: Optional[int] = None,
        timeout: int = 30,
        verify: bool = True,
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
        self.cmd_method: str
        self.cmd_method_conf: str
        self.cmd_method_raw: str
        self.headers: Dict

    def _process_api_response(
        self, response: Response, commands: List[str], raw_text: bool = False
    ) -> List[Any]:
        raise NotImplementedError("Method must be implemented in child class")

    def _nxapi_command_conf(
        self, commands: List[str], method: Optional[str] = None
    ) -> List[Any]:
        raise NotImplementedError("Method must be implemented in child class")

    def _build_payload(
        self,
        commands: List[str],
        method: str,
        rpc_version: str = "2.0",
        api_version: str = "1.0",
    ) -> str:
        raise NotImplementedError("Method must be implemented in child class")

    def _nxapi_command(
        self, commands: List[str], method: Optional[str] = None
    ) -> List[Any]:
        raise NotImplementedError("Method must be implemented in child class")

    def _send_request(self, commands: List[str], method: str) -> Response:
        payload = self._build_payload(commands, method)

        try:
            if not self.verify:
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore

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

        return response


class RPCClient(RPCBase):
    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.headers = {"content-type": "application/json-rpc"}
        self.api = "jsonrpc"
        self.cmd_method = "cli"
        self.cmd_method_conf = "cli"
        self.cmd_method_raw = "cli_ascii"

    def _nxapi_command(
        self, commands: List[str], method: Optional[str] = None
    ) -> List[Any]:
        """Send a command down the NX-API channel."""
        if method is None:
            method = self.cmd_method
        if isinstance(commands, string_types):
            commands = [commands]

        raw_text = True if method == "cli_ascii" else False

        response = self._send_request(commands, method=method)
        api_response = self._process_api_response(response, commands, raw_text=raw_text)
        return api_response

    def _nxapi_command_conf(
        self, commands: List[str], method: Optional[str] = None
    ) -> List[Any]:
        if method is None:
            method = self.cmd_method_conf
        return self._nxapi_command(commands=commands, method=method)

    def _build_payload(
        self,
        commands: List[str],
        method: str,
        rpc_version: str = "2.0",
        api_version: str = "1.0",
    ) -> str:
        """Construct the JSON-RPC payload for NX-API."""
        payload_list = []
        id_num = 1
        for command in commands:
            payload = {
                "jsonrpc": rpc_version,
                "method": method,
                "params": {"cmd": command, "version": float(api_version)},
                "id": id_num,
            }
            payload_list.append(payload)
            id_num += 1

        return json.dumps(payload_list)

    def _process_api_response(
        self, response: Response, commands: List[str], raw_text: bool = False
    ) -> List[Any]:
        """
        Normalize the API response including handling errors; adding the sent command into
        the returned data strucutre; make response structure consistent for raw_text and
        structured data.
        """

        response_list = json.loads(response.text)
        if isinstance(response_list, dict):
            response_list = [response_list]

        # Add the 'command' that was executed to the response dictionary
        for i, response_dict in enumerate(response_list):
            response_dict["command"] = commands[i]

        new_response = []
        for response in response_list:
            # Detect errors
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

    def _error_check(self, command_response: Dict) -> None:
        error = command_response.get("error")
        if error:
            command = command_response.get("command")
            assert isinstance(command, str)
            if "data" in error:
                raise NXAPICommandError(command, error["data"]["msg"])
            else:
                raise NXAPICommandError(command, "Invalid command.")


class XMLClient(RPCBase):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.headers = {"content-type": "application/xml"}
        self.api = "xml"
        self.cmd_method = "cli_show"
        self.cmd_method_conf = "cli_conf"
        self.cmd_method_raw = "cli_show_ascii"

    def _nxapi_command(
        self, commands: List[str], method: Optional[str] = None
    ) -> List[Any]:
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

    def _nxapi_command_conf(
        self, commands: List[str], method: Optional[str] = None
    ) -> List[Any]:
        if method is None:
            method = self.cmd_method_conf
        return self._nxapi_command(commands=commands, method=method)

    def _build_payload(
        self,
        commands: List[str],
        method: str,
        xml_version: str = "1.0",
        version: str = "1.0",
    ) -> str:
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

    def _process_api_response(
        self, response: Response, commands: List[str], raw_text: bool = False
    ) -> List[Any]:
        if response.status_code not in [200]:
            msg = """Invalid status code returned on NX-API POST
commands: {}
status_code: {}""".format(
                commands, response.status_code
            )
            raise NXAPIPostError(msg)

        xml_root = etree.fromstring(response.text)
        response_list = xml_root.xpath("outputs/output")
        if len(commands) != len(response_list):
            raise NXAPIXMLError(
                "XML response doesn't match expected number of commands."
            )

        return response_list

    def _error_check(self, command_response: etree) -> None:
        """commmand_response will be an XML Etree object."""
        error_list = command_response.find("./clierror")
        command_obj = command_response.find("./input")
        if error_list is not None:
            command = command_obj.text if command_obj is not None else "Unknown command"
            msg = etree.tostring(error_list).decode()
            raise NXAPICommandError(command, msg)
