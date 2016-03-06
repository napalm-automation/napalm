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


def _get_eos_driver():
    from napalm_eos.eos import EOSDriver
    return EOSDriver


def _get_junos_driver():
    from napalm_junos.junos import JunOSDriver
    return JunOSDriver


def get_network_driver(vendor):
    """Given a vendor name returns the network driver."""
    driver_mapping = {
        'EOS': _get_eos_driver,
        'ARISTA': _get_eos_driver,
        'JUNOS': _get_junos_driver,
        'JUNIPER': _get_junos_driver,
        # 'IOS-XR': IOSXRDriver,
        # 'IOSXR': IOSXRDriver,
        # 'FORTIOS': FortiOSDriver,
        # 'NXOS': NXOSDriver,
        # 'IBM': IBMDriver,
        # 'IOS' : IOSDriver,
        # 'PLURIBUS': PluribusDriver
    }
    try:
        return driver_mapping[vendor.upper()]()
    except KeyError:
        raise Exception('Vendor/OS not supported: %s' % vendor)
