import pkg_resources
import sys
import logging

from napalm.base import get_network_driver
from napalm._SUPPORTED_DRIVERS import SUPPORTED_DRIVERS

# Load constituent packages to fix threading deadlock on get_network_driver()
import napalm.eos
import napalm.ios
import napalm.iosxr
import napalm.junos
import napalm.nxos
import napalm.nxos_ssh
import napalm.pyIOSXR
import napalm.nxapi_plumbing  # noqa

# Verify Python Version that is running
try:
    if not (sys.version_info.major == 3 and sys.version_info.minor >= 6):
        raise RuntimeError("NAPALM requires Python 3.6 or greater")
except AttributeError:
    raise RuntimeError("NAPALM requires Python 3.6 or greater")

try:
    __version__ = pkg_resources.get_distribution("napalm").version
except pkg_resources.DistributionNotFound:
    __version__ = "Not installed"

__all__ = ("get_network_driver", "SUPPORTED_DRIVERS")

logger = logging.getLogger("napalm")
