"""napalm_ros package."""

# Import stdlib
import pkg_resources

# Import local modules
from napalm_ros.ros import ROSDriver

try:
    __version__ = pkg_resources.get_distribution('napalm-ros').version
except pkg_resources.DistributionNotFound:
    __version__ = "Not installed"

__all__ = ('ROSDriver',)
