"""Select the right NX-OS class based on the transport, default to NX-API."""
from napalm.base import NetworkDriver
from napalm.nxos_api.nxos_api import NXOSAPIDriver
from napalm.nxos_ssh.nxos_ssh import NXOSSSHDriver


class NXOSDriver(NetworkDriver):
    """
    Select the right NX-OS class based on the transport, default to NX-API.

    Circular reference problems coupled with get_network_driver caused this class to be in a
    separate module.

    You can't use a more standard Factory Function given the way get_network_driver() operates.
    """

    def __new__(cls, hostname, username, password, timeout=60, optional_args=None):
        transport = optional_args.get(
            "transport", optional_args.get("nxos_protocol", "https")
        )
        if transport == "ssh":
            return NXOSSSHDriver(
                hostname,
                username,
                password,
                timeout=timeout,
                optional_args=optional_args,
            )
        elif transport in ["http", "https"]:
            return NXOSAPIDriver(
                hostname,
                username,
                password,
                timeout=timeout,
                optional_args=optional_args,
            )
