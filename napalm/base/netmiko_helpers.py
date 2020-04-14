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
import inspect
from netmiko import BaseConnection


def netmiko_args(optional_args):
    """Check for Netmiko arguments that were passed in as NAPALM optional arguments.

    Return a dictionary of these optional args  that will be passed into the Netmiko
    ConnectHandler call.
    """
    fields = inspect.getfullargspec(BaseConnection.__init__)
    args = fields[0]
    defaults = fields[3]

    check_self = args.pop(0)
    if check_self != "self":
        raise ValueError("Error processing Netmiko arguments")

    netmiko_argument_map = dict(zip(args, defaults))

    # Netmiko arguments that are integrated into NAPALM already
    netmiko_filter = ["ip", "host", "username", "password", "device_type", "timeout"]

    # Filter out all of the arguments that are integrated into NAPALM
    for k in netmiko_filter:
        netmiko_argument_map.pop(k)

    # Check if any of these arguments were passed in as NAPALM optional_args
    netmiko_optional_args = {}
    for k, v in netmiko_argument_map.items():
        try:
            netmiko_optional_args[k] = optional_args[k]
        except KeyError:
            pass

    # Return these arguments for use with establishing Netmiko SSH connection
    return netmiko_optional_args
