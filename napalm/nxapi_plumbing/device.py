"""
Fork of pynxos library from network to code and mzbenami

Reimplemented by ktbyers to support XML-RPC in addition to JSON-RPC
"""

from __future__ import print_function, unicode_literals

from typing import List, Optional, Any, Union

from napalm.nxapi_plumbing.errors import NXAPIError, NXAPICommandError
from napalm.nxapi_plumbing.api_client import RPCClient, XMLClient, RPCBase


class Device(object):
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        transport: str = "http",
        api_format: str = "jsonrpc",
        port: Optional[int] = None,
        timeout: int = 30,
        verify: bool = True,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.transport = transport
        self.api_format = api_format
        self.verify = verify
        self.port = port

        self.api: RPCBase
        if api_format == "xml":
            self.api = XMLClient(
                host,
                username,
                password,
                transport=transport,
                port=port,
                timeout=timeout,
                verify=verify,
            )
        elif api_format == "jsonrpc":
            self.api = RPCClient(
                host,
                username,
                password,
                transport=transport,
                port=port,
                timeout=timeout,
                verify=verify,
            )

    def show(self, command: str, raw_text: bool = False) -> Any:
        """Send a non-configuration command.

        Args:
            command (str): The command to send to the device.

        Keyword Args:
            raw_text (bool): Whether to return raw text or structured data.

        Returns:
            The output of the show command, which could be raw text or structured data.
        """
        commands = [command]
        result = self.show_list(commands, raw_text)
        if len(result) > 1:
            raise NXAPIError(
                "Length of response inconsistent with number of commands executed."
            )

        # Return the only entry or the empty response
        if result:
            if self.api_format == "jsonrpc":
                return result[0]["result"]
            elif self.api_format == "xml":
                return result[0]

        return result

    def show_list(self, commands: List[str], raw_text: bool = False) -> List[Any]:
        """Send a list of non-configuration commands.

        Args:
            commands (list): A list of commands to send to the device.

        Keyword Args:
            raw_text (bool): Whether to return raw text or structured data.

        Returns:
            A list of outputs for each show command
        """
        cmd_method = self.api.cmd_method_raw if raw_text else self.api.cmd_method
        return self.api._nxapi_command(commands, method=cmd_method)

    def config(self, command: str) -> Union[str, List]:
        """Send a configuration command.

        Args:
            command (str): The command to send to the device.

        Raises:
            NXAPICommandError: If there is a problem with the supplied command.
        """
        commands = [command]
        result = self.config_list(commands)

        if len(result) > 1:
            raise NXAPIError(
                "Length of response inconsistent with number of commands executed."
            )

        # Return the only entry or the empty response
        if result:
            if self.api_format == "jsonrpc":
                return result[0]["result"]
            elif self.api_format == "xml":
                return result[0]

        return result

    def config_list(self, commands: List[str]) -> List[Any]:
        """Send a list of configuration commands.

        Args:
            commands (list): A list of commands to send to the device.

        Raises:
            NXAPICommandError: If there is a problem with one of the commands in the list.
        """
        return self.api._nxapi_command_conf(commands)

    def save(self, filename: str = "startup-config") -> bool:
        """Save a device's running configuration.

        Args:
            filename (str): The filename on the remote device.
                If none is supplied, the implementing class should
                save to the "startup configuration".
        """
        try:
            cmd = "copy run {}".format(filename)
            self.show(cmd, raw_text=True)
        except NXAPICommandError as e:
            if "overwrite" in e.message:
                return False
            raise
        return True

    def rollback(self, filename: str) -> None:
        """Rollback to a checkpoint file.

        Args:
            filename (str): The filename of the checkpoint file to load into the running
            configuration.
        """
        cmd = "rollback running-config file {}".format(filename)
        self.show(cmd, raw_text=True)

    def checkpoint(self, filename: str) -> None:
        """Save a checkpoint of the running configuration to the device.

        Args:
            filename (str): The filename to save the checkpoint as on the remote device.
        """
        self.show_list(
            ["terminal dont-ask", "checkpoint file {}".format(filename)], raw_text=True
        )
