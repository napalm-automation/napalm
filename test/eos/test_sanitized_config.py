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

"""Tests for the eos_sanitized_config optional arg."""

from textwrap import dedent

from pyeapi.eapilib import CommandError

from napalm.eos.eos import EOSDriver

NTP = "ntp server 192.0.2.10\n"
SNMP = "snmp-server community <removed> ro\n"
BGP = dedent(
    """\
    router bgp 65000
       neighbor PEERS peer group
       neighbor PEERS remote-as 65001
       neighbor PEERS password 7 <removed>
       neighbor 198.51.100.1 peer group PEERS
    """
)
RUNNING_CONFIG = NTP + SNMP + BGP
SECTIONS = {
    "section router bgp": BGP,
    "section ntp": NTP,
    "section snmp-server community": SNMP,
    "include service routing protocols model multi-agent": "",
}


class SanitizedOnlyDevice:
    """Rejects any running-config read that is not sanitized."""

    def run_commands(self, commands, encoding="json", send_enable=True):
        result = []
        for command in commands:
            cmd, _, pipe = command.partition(" | ")
            if cmd == "show running-config sanitized":
                result.append({"output": SECTIONS[pipe] if pipe else RUNNING_CONFIG})
            elif cmd.startswith("show running-config"):
                raise CommandError(1005, "permission to run command denied")
            else:
                result.append({"output": ""} if encoding == "text" else {})
        return result


def test_getters_use_sanitized_config():
    driver = EOSDriver("192.0.2.1", "user", "pass", optional_args={"eos_sanitized_config": True})
    driver.device = SanitizedOnlyDevice()

    assert driver.get_bgp_config()["PEERS"]["authentication_key"] == "<removed>"
    assert list(driver.get_ntp_servers()) == ["192.0.2.10"]
    assert list(driver.get_snmp_information()["community"]) == ["<removed>"]
    assert driver.get_config(retrieve="running")["running"] == RUNNING_CONFIG
    driver.get_bgp_neighbors_detail()
