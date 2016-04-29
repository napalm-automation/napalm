# Copyright 2015 Spotify AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""napalm_base package."""

# Python std lib
import inspect
import importlib

# NAPALM base
from napalm_base.base import NetworkDriver
from napalm_base.exceptions import ModuleImportError


__all__ = [
    'get_network_driver',  # export the function
    'NetworkDriver'  # also export the base class
]


def get_network_driver(module_name):

    """
    Searches for a class derived form the base NAPALM class NetworkDriver in a specific library.
    The library name must repect the following pattern: napalm_[DEVICE_OS].
    NAPALM community supports a list of devices and provides the corresponding libraries; for full reference
    please refer to the `Supported Network Operation Systems`_ paragraph on `Read the Docs`_.

    .. _`Supported Network Operation Systems`: http://napalm.readthedocs.io/en/latest/#supported-network-operating-systems
    .. _`Read the Docs`: http://napalm.readthedocs.io/

    :param module_name:         the name of the device operating system, or the name of the library.
    :return:                    the first class derived from NetworkDriver, found in the library.
    :raise ModuleImportError:   when the library is not installed, or a derived class from NetworkDriver was not found.

    Example::

    .. code-block:: python

        >>> get_network_driver('junos')
        <class 'napalm_junos.junos.JunOSDriver'>
        >>> get_network_driver('IOS-XR')
        <class 'napalm_iosxr.iosxr.IOSXRDriver'>
        >>> get_network_driver('napalm_eos')
        <class 'napalm_eos.eos.EOSDriver'>
        >>> get_network_driver('wrong')
        napalm_base.exceptions.ModuleImportError: Cannot import "napalm_wrong". Is the library installed?
    """

    if not (isinstance(module_name, basestring) and len(module_name) > 0):
        raise ModuleImportError('Please provide a valid driver name.')

    try:
        module_name = module_name.lower()  # only lowercase allowed
        module_install_name = module_name.replace('-', '')  # to not raise error when users requests IOS-XR for e.g.
        if 'napalm_' not in module_install_name:  # can also request using napalm_[SOMETHING]
            module_install_name = 'napalm_{name}'.format(name=module_install_name)
        module = importlib.import_module(module_install_name)
    except ImportError:
        raise ModuleImportError(
                'Cannot import "{install_name}". Is the library installed?'.format(
                    install_name=module_install_name
                )
            )

    for name, obj in inspect.getmembers(module):
        if inspect.isclass(obj) and issubclass(obj, NetworkDriver):
            return obj

    # looks like you don't have any Driver class in your module...
    raise ModuleImportError(
            'No class inheriting "napalm_base.base.NetworkDriver" found in "{install_name}".'.format(
                install_name=module_install_name
            )
        )
