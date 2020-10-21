"""
Fork of pynxos library from network to code and mzbenami

Re-implemented by ktbyers to support XML-RPC in addition to JSON-RPC
"""
from napalm.nxapi_plumbing.device import Device
from napalm.nxapi_plumbing.api_client import RPCClient, XMLClient
from napalm.nxapi_plumbing.errors import (
    NXAPIError,
    NXAPICommandError,
    NXAPIConnectionError,
    NXAPIAuthError,
    NXAPIPostError,
    NXAPIXMLError,
)

__version__ = "0.6.0"
__all__ = (
    "Device",
    "RPCClient",
    "XMLClient",
    "NXAPIError",
    "NXAPICommandError",
    "NXAPIConnectionError",
    "NXAPIAuthError",
    "NXAPIPostError",
    "NXAPIXMLError",
)
