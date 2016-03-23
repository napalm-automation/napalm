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

import sys
import imp
import inspect

from base import NetworkDriver


def _import_module(name):
    """Import a module into the current runtime environment.

    This function will take a full path module name and break it into
    its parts iteratively attempting to import each one.  The function
    will check to be sure that the module hasn't been previously imported.

    .. doctest::

        >>> _import_module('os') #doctest: +ELLIPSIS
        <module 'os' from '...'>

    :param str name:
        The name of the module to import

    :returns:
        The imported Python module
    """
    parts = name.split('.')
    path = None
    module_name = ''
    fhandle = None

    for index, part in enumerate(parts):
        module_name = part if index == 0 else '%s.%s' % (module_name, part)
        path = [path] if path is not None else path

        try:
            fhandle, path, descr = imp.find_module(part, path)
            if module_name in sys.modules:
                # since imp.load_module works like reload, need to be sure not
                # to reload a previously loaded module
                mod = sys.modules[module_name]
            else:
                mod = imp.load_module(module_name, fhandle, path, descr)
        finally:
            # lets be sure to clean up after ourselves
            if fhandle:
                fhandle.close()

    return mod


def _load_module(name):
    """Attempt to load a module into the current environment.

    This function will load a module from the Python sys.path.  It will
    check to be sure the module wasn't already loaded.  If the module
    was prevsiouly loaded, it will simply return the loaded module and not
    reload it

    .. doctest::

        >>> _load_module('sys')
        <module 'sys' (built-in)>

    :param str name:
        The name of the module to load

    :returns:
        The named Python module

    :raises ImportError:
        If the module could not be loaded
    """
    try:
        mod = None
        mod = sys.modules[name]
    except KeyError:
        try:
            mod = _import_module(name)
        except ImportError:
            raise
    finally:
        if not mod:
            raise
        return mod


def _napalm_namespace(module):
    """Prepend the default namespace onto the module name.

    The function is only applicable in cases where a module
    name is provided without a full path namespace.  In this
    case, the module name is prepended with the device namespace.
    If the module name is a fully qualified namespace, the
    module name is returned.

    .. doctest::

        >>> _napalm_namespace('test')
        'napalm_test.test'
        >>> _napalm_namespace('napalm.test')
        'napalm.test'

    :param str module:
        The name of the module to verify

    :returns:
        The fully qualified module namespace
    """
    if '.' in module:
        return module
    return 'napalm_{}'.format(module)


def _discover_driver_from_module(module):
    """Return the first subclass of ``NetworkDriver`` found in ``module``."""
    driver = None
    for member in inspect.getmembers(module):
        if inspect.isclass(member[1]):
            if issubclass(member[1], NetworkDriver) and member[1] is not NetworkDriver:
                driver = member[1]
                break
    return driver


def get_network_driver(module, loader='load_driver', *args, **kwargs):
    """Attempt to load a class instance from the module.

    The function will load the specified module and create
    an instance.  The loader works by looking for a function in
    the module and loading it.

    :param str module:
        The name of the module to dynamically load

    :param str loader:
        The name of the function to call to load the driver.  The
        default value is 'load_driver'

    :param args:
        An ordered set of arbitrary arguments that are passed to the
        instance function

    :param kwargs:
        An unordered set of arbitrary keyword arguments that are passed
        to the instance function

    :returns object:
        Instantiates a Python object an returns it
    """
    loader = loader or 'load_driver'
    mod = _load_module(_napalm_namespace(module))

    if hasattr(mod, loader):
        func = getattr(mod, loader)
        return func(*args, **kwargs)
    else:
        discovered_driver = _discover_driver_from_module(mod)
        if discovered_driver is None:
            raise Exception("Failed finding load_driver method and discovering driver in "
                            "module {}".format(mod))
        else:
            return discovered_driver
