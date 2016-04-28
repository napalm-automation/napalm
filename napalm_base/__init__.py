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
import napalm_base


def get_network_driver(module_name):

    if not (isinstance(module_name, str) and len(module_name) > 0):
        raise napalm_base.exceptions.ModuleImportError('Please provide a valid driver name.')

    try:
        module_name = module_name.lower()  # only lowercase allowed
        module_install_name = module_name
        if 'napalm_' not in module_name:  # can also request using napalm_[SOMETHING]
            module_install_name = 'napalm_{name}'.format(name=module_name)
        module = importlib.import_module(module_install_name)
    except ImportError:
        raise napalm_base.exceptions.ModuleImportError(
                'Cannot import "{install_name}". Is the library installed?'.format(
                    install_name=module_install_name
                )
            )

    for name, obj in inspect.getmembers(module):
        if inspect.isclass(obj) and issubclass(obj, napalm_base.base.NetworkDriver):
            return obj

    # looks like you don't have any Driver class in your module...
    raise napalm_base.exceptions.ModuleImportError(
            'No class inheriting "napalm_base.base.NetworkDriver" found in "{install_name}".'.format(
                install_name=module_install_name
            )
        )
