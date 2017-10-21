import pkg_resources
import sys

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


SUPPORTED_DRIVERS = [
    "eos",
    "ios",
    "junos",
]
