# Copyright 2026 NAPALM. All rights reserved.
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

"""Regression tests for EOSDriver.open() error handling (napalm-automation/napalm#2318)."""

from unittest import mock

import pytest
from netmiko import NetMikoTimeoutException
from pyeapi.eapilib import ConnectionError as PyeapiConnectionError

from napalm.base.exceptions import ConnectionException
from napalm.eos.eos import EOSDriver


def _make_driver(transport):
    return EOSDriver(
        hostname="127.0.0.1",
        username="admin",
        password="admin",
        optional_args={"transport": transport},
    )


@pytest.mark.parametrize(
    "transport, raised",
    [
        ("https", PyeapiConnectionError("device", "timed out")),
        ("ssh", NetMikoTimeoutException("timed out")),
    ],
)
def test_open_wraps_first_command_error_in_connection_exception(transport, raised):
    """
    A device that accepts the underlying connection but fails on the first real
    command (the "show version" call used to detect the EOS version) must still
    raise napalm's ConnectionException rather than leaking the raw pyeapi/netmiko
    exception.
    """
    driver = _make_driver(transport)

    if transport == "ssh":
        driver._netmiko_open = mock.MagicMock(return_value=mock.MagicMock())
    else:
        driver.transport_class = mock.MagicMock()

    with (
        mock.patch.object(EOSDriver, "_run_commands", side_effect=raised),
        pytest.raises(ConnectionException),
    ):
        driver.open()
