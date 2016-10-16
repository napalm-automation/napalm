from .ros import ROSDriver

from pkg_resources import get_distribution

try:
    __version__ = pkg_resources.get_distribution('napalm-ros').version
except pkg_resources.DistributionNotFound:
    __version__ = "Not installed"

__all__ = ('ROSDriver',)
