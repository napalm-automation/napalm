import pkg_resources
import sys
from napalm.base import get_network_driver
from napalm._SUPPORTED_DRIVERS import SUPPORTED_DRIVERS

# Verify Python Version that is running
try:
    if not(sys.version_info.major == 2 and sys.version_info.minor == 7) and \
            not(sys.version_info.major == 3):
        raise RuntimeError('NAPALM requires Python 2.7 or Python3')
except AttributeError:
    raise RuntimeError('NAPALM requires Python 2.7 or Python3')

try:
    __version__ = pkg_resources.get_distribution('napalm').version
except pkg_resources.DistributionNotFound:
    __version__ = "Not installed"

__all__ = ('get_network_driver', 'SUPPORTED_DRIVERS')
