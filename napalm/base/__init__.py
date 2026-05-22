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

"""napalm.base package."""

# Python std lib
import inspect
import importlib

# NAPALM base
from typing import Type

from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ModuleImportError
from napalm.base.mock import MockDriver

__all__ = [
    "get_network_driver",  # export the function
    "NetworkDriver",  # also export the base class
]


def _validate_driver_name(module_install_name: str, original_name: str) -> None:
    """
    Validate that *module_install_name* (the normalised form of the caller-supplied
    driver name, after lower-casing and hyphen removal) does not contain unsafe
    path components that could reach unintended modules via
    ``importlib.import_module``.

    Rules
    -----
    * A dot is only permitted when the name begins with exactly ``napalm.`` or
      ``custom_napalm.`` — the two documented namespaces for explicit driver
      references.
    * The portion *after* the allowed prefix must itself be dot-free, preventing
      traversal into arbitrary sub-packages (e.g. ``napalm.eos.eos`` is rejected).
    * All other names with dots are rejected unconditionally.

    :param module_install_name: normalised driver name (lowercase, hyphens removed).
    :param original_name:       the raw value supplied by the caller, used in the
                                error message.
    :raise ModuleImportError:   when the name violates the rules above.
    """
    if "." not in module_install_name:
        return  # simple identifier — nothing more to check

    for prefix in ("napalm.", "custom_napalm."):
        if module_install_name.startswith(prefix):
            suffix = module_install_name[len(prefix) :]
            if "." not in suffix:
                # exactly one dot, in an allowed namespace
                return
            # starts with a known prefix but has extra dots — fall through to error
            break

    raise ModuleImportError(
        f'Invalid driver name "{original_name}": dots are only permitted in the '
        '"napalm.<driver>" or "custom_napalm.<driver>" forms.'
    )


def get_network_driver(name: str, prepend: bool = True) -> Type[NetworkDriver]:
    """
    Searches for a class derived from the base NAPALM class NetworkDriver in a specific library.
    NAPALM community supports a list of devices and provides the corresponding libraries; for
    full reference please refer to the `Supported Network Operation Systems`_ paragraph on
    `Read the Docs`_.

    .. _`Supported Network Operation Systems`: \
    http://napalm.readthedocs.io/en/latest/#supported-network-operating-systems
    .. _`Read the Docs`: \
    http://napalm.readthedocs.io/

    The *name* argument must be one of three forms (case-insensitive; hyphens are ignored):

    1. **Plain driver name** — a simple identifier with no dots, e.g. ``"eos"``, ``"junos"``,
       ``"IOS-XR"``.  The function will search for the driver in the following order:
       ``custom_napalm.<name>`` (site-local), ``napalm.<name>`` (core), ``napalm_<name>``
       (community).
    2. **Explicit core/custom path** — a single-dot name beginning with ``napalm.`` or
       ``custom_napalm.``, e.g. ``"napalm.eos"`` or ``"custom_napalm.mydriver"``.  Only that
       exact module is tried; no additional candidates are constructed.  Requires
       ``prepend=True`` (the default).
    3. **Already-qualified name** — any name that already contains ``"napalm"`` (e.g.
       ``"napalm_eos"``), passed with ``prepend=False`` to suppress the automatic
       ``napalm.`` prefix.  The name must still satisfy rule 1 or 2 above.

    Names with more than one dot, dots outside the ``napalm.`` / ``custom_napalm.``
    prefixes, or bare names passed with ``prepend=False`` are rejected with
    ``ModuleImportError``.

    :param name:         the driver name in one of the three forms described above.
    :param prepend:      when ``True`` (default) the ``napalm.`` prefix is added automatically
                         for plain names.  Set to ``False`` only when *name* already contains
                         ``"napalm"``.
    :return:             the first class derived from NetworkDriver found in the resolved module.
    :raise ModuleImportError:   when the name is invalid, the library is not installed, or no
                                class derived from NetworkDriver was found.

    Example::

    .. code-block:: python

        >>> get_network_driver('junos')
        <class 'napalm.junos.junos.JunOSDriver'>
        >>> get_network_driver('IOS-XR')
        <class 'napalm.iosxr.iosxr.IOSXRDriver'>
        >>> get_network_driver('napalm.eos')
        <class 'napalm.eos.eos.EOSDriver'>
        >>> get_network_driver('wrong')
        napalm.base.exceptions.ModuleImportError: Cannot import "napalm_wrong". Is the library \
        installed?
    """
    if name == "mock":
        return MockDriver

    if not (isinstance(name, str) and len(name) > 0):
        raise ModuleImportError("Please provide a valid driver name.")

    # Only lowercase allowed
    name = name.lower()
    # Try to not raise error when users requests IOS-XR for e.g.
    module_install_name = name.replace("-", "")
    _validate_driver_name(module_install_name, name)

    if not prepend and "napalm" not in module_install_name:
        raise ModuleImportError(
            f'Invalid driver name "{name}": when prepend=False the name must '
            'already contain "napalm" (e.g. "napalm.eos" or "napalm_eos").'
        )

    if "." in module_install_name:
        # Caller supplied an explicit dotted module path (e.g. "napalm.eos" or
        # "custom_napalm.mydriver").
        candidates = [module_install_name]
    else:
        community_install_name = f"napalm_{module_install_name}"
        custom_install_name = f"custom_napalm.{module_install_name}"
        # Can also request using napalm_[SOMETHING]
        if "napalm" not in module_install_name:
            module_install_name = f"napalm.{module_install_name}"
        # Order is custom_napalm_os (local only) ->  napalm.os (core) ->  napalm_os (community)
        candidates = [
            custom_install_name,
            module_install_name,
            community_install_name,
        ]

    for module_name in candidates:
        try:
            module = importlib.import_module(module_name)
            break
        except ImportError as e:
            message = str(e)
            if "No module named" in message:
                # py2 doesn't have ModuleNotFoundError exception
                failed_module = message.split()[-1]
                if failed_module.replace("'", "") in module_name:
                    continue
            raise e
    else:
        raise ModuleImportError(f'Cannot import "{name}". Is the library installed?')

    for name, obj in inspect.getmembers(module):
        if inspect.isclass(obj) and issubclass(obj, NetworkDriver):
            return obj

    # looks like you don't have any Driver class in your module...
    raise ModuleImportError(
        f'No class inheriting "napalm.base.base.NetworkDriver" found in "{module_install_name}".'
    )
