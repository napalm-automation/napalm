from .ros import ROSDriver

import pkg_resources

try:
    __version__ = pkg_resources.get_distribution('napalm-ros').version
except pkg_resources.DistributionNotFound:
    __version__ = "Not installed"

__all__ = ('ROSDriver',)
