# -*- coding: utf-8 -*-
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

"""Driver for JunOS devices."""

# import stdlib
import re
import json
import logging
import collections
from copy import deepcopy
from collections import OrderedDict, defaultdict

# import third party lib
from lxml.builder import E
from lxml import etree

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import RpcError
from jnpr.junos.exception import ConfigLoadError
from jnpr.junos.exception import RpcTimeoutError
from jnpr.junos.exception import ConnectTimeoutError
from jnpr.junos.exception import ProbeError
from jnpr.junos.exception import LockError as JnprLockError
from jnpr.junos.exception import UnlockError as JnrpUnlockError

# import NAPALM Base
import napalm.base.helpers
from napalm.base.base import NetworkDriver
from napalm.junos import constants as C
from napalm.base.exceptions import ConnectionException
from napalm.base.exceptions import MergeConfigException
from napalm.base.exceptions import CommandErrorException
from napalm.base.exceptions import ReplaceConfigException
from napalm.base.exceptions import CommandTimeoutException
from napalm.base.exceptions import LockError
from napalm.base.exceptions import UnlockError

# import local modules
from napalm.junos.utils import junos_views

log = logging.getLogger(__file__)


class JunOSDriver(NetworkDriver):
    """JunOSDriver class - inherits NetworkDriver from napalm.base."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialise JunOS driver.

        Optional args:
            * config_lock (True/False): lock configuration DB after the connection is established.
            * lock_disable (True/False): force configuration lock to be disabled (for external lock
                management).
            * config_private (True/False): juniper configure private command, no DB locking
            * port (int): custom port
            * key_file (string): SSH key file path
            * keepalive (int): Keepalive interval
            * ignore_warning (boolean): not generate warning exceptions
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.config_replace = False
        self.locked = False

        # Get optional arguments
        if optional_args is None:
            optional_args = {}

        self.port = optional_args.get("port", 22)
        self.key_file = optional_args.get("key_file", None)
        self.keepalive = optional_args.get("keepalive", 30)
        self.ssh_config_file = optional_args.get("ssh_config_file", None)
        self.ignore_warning = optional_args.get("ignore_warning", False)
        self.auto_probe = optional_args.get("auto_probe", 0)

        # Define locking method
        self.lock_disable = optional_args.get("lock_disable", False)
        self.session_config_lock = optional_args.get("config_lock", False)
        self.config_private = optional_args.get("config_private", False)

        # Junos driver specific options
        self.junos_config_database = optional_args.get(
            "junos_config_database", "committed"
        )

        if self.key_file:
            self.device = Device(
                hostname,
                user=username,
                password=password,
                ssh_private_key_file=self.key_file,
                ssh_config=self.ssh_config_file,
                port=self.port,
            )
        else:
            self.device = Device(
                hostname,
                user=username,
                password=password,
                port=self.port,
                ssh_config=self.ssh_config_file,
            )

        self.platform = "junos"
        self.profile = [self.platform]

    def open(self):
        """Open the connection with the device."""
        try:
            self.device.open(auto_probe=self.auto_probe)
        except (ConnectTimeoutError, ProbeError) as cte:
            raise ConnectionException(cte.msg) from cte
        self.device.timeout = self.timeout
        self.device._conn._session.transport.set_keepalive(self.keepalive)
        if hasattr(self.device, "cu"):
            # make sure to remove the cu attr from previous session
            # ValueError: requested attribute name cu already exists
            del self.device.cu
        self.device.bind(cu=Config)
        if not self.lock_disable and self.session_config_lock:
            self._lock()

    def close(self):
        """Close the connection."""
        if not self.lock_disable and self.session_config_lock:
            self._unlock()
        self.device.close()

    def _lock(self):
        """Lock the config DB."""
        if not self.locked:
            try:
                self.device.cu.lock()
                self.locked = True
            except JnprLockError as jle:
                raise LockError(str(jle))

    def _unlock(self):
        """Unlock the config DB."""
        if self.locked:
            try:
                self.device.cu.unlock()
                self.locked = False
            except JnrpUnlockError as jue:
                raise UnlockError(jue)

    def _rpc(self, get, child=None, **kwargs):
        """
        This allows you to construct an arbitrary RPC call to retreive common stuff. For example:
        Configuration:  get: "<get-configuration/>"
        Interface information:  get: "<get-interface-information/>"
        A particular interfacece information:
              get: "<get-interface-information/>"
              child: "<interface-name>ge-0/0/0</interface-name>"
        """
        rpc = etree.fromstring(get)

        if child:
            rpc.append(etree.fromstring(child))

        response = self.device.execute(rpc)
        return etree.tostring(response)

    def is_alive(self):
        # evaluate the state of the underlying SSH connection
        # and also the NETCONF status from PyEZ
        return {
            "is_alive": self.device._conn._session.transport.is_active()
            and self.device.connected
        }

    @staticmethod
    def _is_json_format(config):
        try:
            _ = json.loads(config)  # noqa
        except (TypeError, ValueError):
            return False
        return True

    def _detect_config_format(self, config):
        fmt = "text"
        set_action_matches = [
            "set",
            "activate",
            "deactivate",
            "annotate",
            "copy",
            "delete",
            "insert",
            "protect",
            "rename",
            "unprotect",
            "edit",
            "top",
        ]
        if config.strip().startswith("<"):
            return "xml"
        elif config.strip().split(" ")[0] in set_action_matches:
            return "set"
        elif self._is_json_format(config):
            return "json"
        return fmt

    def _load_candidate(self, filename, config, overwrite):
        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()

        if (
            not self.lock_disable
            and not self.session_config_lock
            and not self.config_private
        ):
            # if not locked during connection time, will try to lock
            self._lock()

        try:
            fmt = self._detect_config_format(configuration)

            if fmt == "xml":
                configuration = etree.XML(configuration)

            if self.config_private:
                try:
                    self.device.rpc.open_configuration(private=True, normalize=True)
                except RpcError as err:
                    if str(err) == "uncommitted changes will be discarded on exit":
                        pass

            self.device.cu.load(
                configuration,
                format=fmt,
                overwrite=overwrite,
                ignore_warning=self.ignore_warning,
            )
        except ConfigLoadError as e:
            if self.config_replace:
                raise ReplaceConfigException(e.errs)
            else:
                raise MergeConfigException(e.errs)

    def load_replace_candidate(self, filename=None, config=None):
        """Open the candidate config and merge."""
        self.config_replace = True
        self._load_candidate(filename, config, True)

    def load_merge_candidate(self, filename=None, config=None):
        """Open the candidate config and replace."""
        self.config_replace = False
        self._load_candidate(filename, config, False)

    def compare_config(self):
        """Compare candidate config with running."""
        diff = self.device.cu.diff()

        if diff is None:
            return ""
        else:
            return diff.strip()

    def commit_config(self, message=""):
        """Commit configuration."""
        commit_args = {"comment": message} if message else {}
        self.device.cu.commit(ignore_warning=self.ignore_warning, **commit_args)
        if not self.lock_disable and not self.session_config_lock:
            self._unlock()
        if self.config_private:
            self.device.rpc.close_configuration()

    def discard_config(self):
        """Discard changes (rollback 0)."""
        self.device.cu.rollback(rb_id=0)
        if not self.lock_disable and not self.session_config_lock:
            self._unlock()
        if self.config_private:
            self.device.rpc.close_configuration()

    def rollback(self):
        """Rollback to previous commit."""
        self.device.cu.rollback(rb_id=1)
        self.commit_config()

    def get_facts(self):
        """Return facts of the device."""
        output = self.device.facts

        uptime = self.device.uptime or -1

        interfaces = junos_views.junos_iface_table(self.device)
        interfaces.get()
        interface_list = interfaces.keys()

        return {
            "vendor": "Juniper",
            "model": str(output["model"]),
            "serial_number": str(output["serialnumber"]),
            "os_version": str(output["version"]),
            "hostname": str(output["hostname"]),
            "fqdn": str(output["fqdn"]),
            "uptime": uptime,
            "interface_list": interface_list,
        }

    def get_interfaces(self):
        """Return interfaces details."""
        result = {}

        interfaces = junos_views.junos_iface_table(self.device)
        interfaces.get()
        interfaces_logical = junos_views.junos_logical_iface_table(self.device)
        interfaces_logical.get()

        # convert all the tuples to our pre-defined dict structure
        def _convert_to_dict(interfaces):
            # calling .items() here wont work.
            # The dictionary values will end up being tuples instead of dictionaries
            interfaces = dict(interfaces)
            for iface, iface_data in interfaces.items():
                result[iface] = {
                    "is_up": iface_data["is_up"],
                    # For physical interfaces <admin-status> will always be there, so just
                    # return the value interfaces[iface]['is_enabled']
                    # For logical interfaces if <iff-down> is present interface is disabled,
                    # otherwise interface is enabled
                    "is_enabled": (
                        True
                        if iface_data["is_enabled"] is None
                        else iface_data["is_enabled"]
                    ),
                    "description": (iface_data["description"] or ""),
                    "last_flapped": float((iface_data["last_flapped"] or -1)),
                    "mac_address": napalm.base.helpers.convert(
                        napalm.base.helpers.mac,
                        iface_data["mac_address"],
                        str(iface_data["mac_address"]),
                    ),
                    "speed": -1,
                    "mtu": 0,
                }
                # result[iface]['last_flapped'] = float(result[iface]['last_flapped'])

                match_mtu = re.search(r"(\w+)", str(iface_data["mtu"]) or "")
                mtu = napalm.base.helpers.convert(int, match_mtu.group(0), 0)
                result[iface]["mtu"] = mtu
                match = re.search(r"(\d+|[Aa]uto)(\w*)", iface_data["speed"] or "")
                if match and match.group(1).lower() == "auto":
                    match = re.search(
                        r"(\d+)(\w*)", iface_data["negotiated_speed"] or ""
                    )
                if match is None:
                    continue
                speed_value = napalm.base.helpers.convert(int, match.group(1), -1)
                if speed_value == -1:
                    continue
                speed_unit = match.group(2)
                if speed_unit.lower() == "gbps":
                    speed_value *= 1000
                result[iface]["speed"] = speed_value

            return result

        result = _convert_to_dict(interfaces)
        result.update(_convert_to_dict(interfaces_logical))
        return result

    def get_interfaces_counters(self):
        """Return interfaces counters."""
        query = junos_views.junos_iface_counter_table(self.device)
        query.get()
        interface_counters = {}
        for interface, counters in query.items():
            interface_counters[interface] = {
                k: v if v is not None else -1 for k, v in counters
            }
        return interface_counters

    def get_environment(self):
        """Return environment details."""
        if self.device.facts.get("srx_cluster", False):
            environment = junos_views.junos_environment_table_srx_cluster(self.device)
            routing_engine = junos_views.junos_routing_engine_table_srx_cluster(
                self.device
            )
            temperature_thresholds = junos_views.junos_temperature_thresholds_srx_cluster(
                self.device
            )
        else:
            environment = junos_views.junos_environment_table(self.device)
            routing_engine = junos_views.junos_routing_engine_table(self.device)
            temperature_thresholds = junos_views.junos_temperature_thresholds(
                self.device
            )
        power_supplies = junos_views.junos_pem_table(self.device)
        environment.get()
        routing_engine.get()
        temperature_thresholds.get()
        environment_data = {}
        current_class = None

        for sensor_object, object_data in environment.items():
            structured_object_data = {k: v for k, v in object_data}

            if structured_object_data["class"]:
                # If current object has a 'class' defined, store it for use
                # on subsequent unlabeled lines.
                current_class = structured_object_data["class"]
            else:
                # Juniper doesn't label the 2nd+ lines of a given class with a
                # class name.  In that case, we use the most recent class seen.
                structured_object_data["class"] = current_class

            if structured_object_data["class"] == "Power":
                # Create a dict for the 'power' key
                try:
                    environment_data["power"][sensor_object] = {}
                except KeyError:
                    environment_data["power"] = {}
                    environment_data["power"][sensor_object] = {}

                environment_data["power"][sensor_object]["capacity"] = -1.0
                environment_data["power"][sensor_object]["output"] = -1.0

            if structured_object_data["class"] == "Fans":
                # Create a dict for the 'fans' key
                try:
                    environment_data["fans"][sensor_object] = {}
                except KeyError:
                    environment_data["fans"] = {}
                    environment_data["fans"][sensor_object] = {}

            status = structured_object_data["status"]
            env_class = structured_object_data["class"]
            if status == "OK" and env_class == "Power":
                # If status is Failed, Absent or Testing, set status to False.
                environment_data["power"][sensor_object]["status"] = True

            elif status != "OK" and env_class == "Power":
                environment_data["power"][sensor_object]["status"] = False

            elif status == "OK" and env_class == "Fans":
                # If status is Failed, Absent or Testing, set status to False.
                environment_data["fans"][sensor_object]["status"] = True

            elif status != "OK" and env_class == "Fans":
                environment_data["fans"][sensor_object]["status"] = False

            for temperature_object, temperature_data in temperature_thresholds.items():
                structured_temperature_data = {k: v for k, v in temperature_data}
                if structured_object_data["class"] == "Temp":
                    # Create a dict for the 'temperature' key
                    try:
                        environment_data["temperature"][sensor_object] = {}
                    except KeyError:
                        environment_data["temperature"] = {}
                        environment_data["temperature"][sensor_object] = {}
                    # Check we have a temperature field in this class (See #66)
                    if structured_object_data["temperature"]:
                        environment_data["temperature"][sensor_object][
                            "temperature"
                        ] = float(structured_object_data["temperature"])
                    # Set a default value (False) to the key is_critical and is_alert
                    environment_data["temperature"][sensor_object]["is_alert"] = False
                    environment_data["temperature"][sensor_object][
                        "is_critical"
                    ] = False
                    # Check if the working temperature is equal to or higher than alerting threshold
                    temp = structured_object_data["temperature"]
                    if temp is not None:
                        if structured_temperature_data["red-alarm"] <= temp:
                            environment_data["temperature"][sensor_object][
                                "is_critical"
                            ] = True
                            environment_data["temperature"][sensor_object][
                                "is_alert"
                            ] = True
                        elif structured_temperature_data["yellow-alarm"] <= temp:
                            environment_data["temperature"][sensor_object][
                                "is_alert"
                            ] = True
                    else:
                        environment_data["temperature"][sensor_object][
                            "temperature"
                        ] = 0.0

        # Try to correct Power Supply information
        pem_table = dict()
        try:
            power_supplies.get()
        except RpcError:
            # Not all platforms have support for this
            pass
        else:
            # Format PEM information and correct capacity and output values
            if "power" not in environment_data.keys():
                # Power supplies were not included from the environment table above
                # Need to initialize data
                environment_data["power"] = {}
                for pem in power_supplies.items():
                    pem_name = pem[0].replace("PEM", "Power Supply")
                    environment_data["power"][pem_name] = {}
                    environment_data["power"][pem_name]["output"] = -1.0
                    environment_data["power"][pem_name]["capacity"] = -1.0
                    environment_data["power"][pem_name]["status"] = False
            for pem in power_supplies.items():
                pem_name = pem[0].replace("PEM", "Power Supply")
                pem_table[pem_name] = dict(pem[1])
                if pem_table[pem_name]["capacity"] is not None:
                    environment_data["power"][pem_name]["capacity"] = pem_table[
                        pem_name
                    ]["capacity"]
                if pem_table[pem_name]["output"] is not None:
                    environment_data["power"][pem_name]["output"] = pem_table[pem_name][
                        "output"
                    ]
                environment_data["power"][pem_name]["status"] = pem_table[pem_name][
                    "status"
                ]

        for routing_engine_object, routing_engine_data in routing_engine.items():
            structured_routing_engine_data = {k: v for k, v in routing_engine_data}
            # Create dicts for 'cpu' and 'memory'.
            try:
                environment_data["cpu"][routing_engine_object] = {}
                environment_data["memory"] = {}
            except KeyError:
                environment_data["cpu"] = {}
                environment_data["cpu"][routing_engine_object] = {}
                environment_data["memory"] = {}
            # Calculate the CPU usage by using the CPU idle value.
            environment_data["cpu"][routing_engine_object]["%usage"] = (
                100.0 - structured_routing_engine_data["cpu-idle"]
            )
            try:
                environment_data["memory"]["available_ram"] = int(
                    structured_routing_engine_data["memory-dram-size"]
                )
            except ValueError:
                environment_data["memory"]["available_ram"] = int(
                    "".join(
                        i
                        for i in structured_routing_engine_data["memory-dram-size"]
                        if i.isdigit()
                    )
                )
            if not structured_routing_engine_data["memory-system-total-used"]:
                # Junos gives us RAM in %, so calculation has to be made.
                # Sadly, bacause of this, results are not 100% accurate to the truth.
                environment_data["memory"]["used_ram"] = int(
                    round(
                        environment_data["memory"]["available_ram"]
                        / 100.0
                        * structured_routing_engine_data["memory-buffer-utilization"]
                    )
                )
            else:
                environment_data["memory"]["used_ram"] = structured_routing_engine_data[
                    "memory-system-total-used"
                ]

        return environment_data

    @staticmethod
    def _get_address_family(table, instance):
        """
        Function to derive address family from a junos table name.

        :params table: The name of the routing table
        :returns: address family
        """
        address_family_mapping = {"inet": "ipv4", "inet6": "ipv6", "inetflow": "flow"}
        if instance == "master":
            family = table.rsplit(".", 1)[-2]
        else:
            family = table.split(".")[-2]
        try:
            address_family = address_family_mapping[family]
        except KeyError:
            address_family = None
        return address_family

    def _parse_route_stats(self, neighbor, instance):
        data = {
            "ipv4": {
                "received_prefixes": -1,
                "accepted_prefixes": -1,
                "sent_prefixes": -1,
            },
            "ipv6": {
                "received_prefixes": -1,
                "accepted_prefixes": -1,
                "sent_prefixes": -1,
            },
        }
        if not neighbor["is_up"]:
            return data
        elif isinstance(neighbor["tables"], list):
            if isinstance(neighbor["sent_prefixes"], int):
                # We expect sent_prefixes to be a list, but sometimes it
                # is of type int. Therefore convert attribute to list
                neighbor["sent_prefixes"] = [neighbor["sent_prefixes"]]
            for idx, table in enumerate(neighbor["tables"]):
                family = self._get_address_family(table, instance)
                if family is None:
                    # Need to remove counter from sent_prefixes list anyway
                    if "in sync" in neighbor["send-state"][idx]:
                        neighbor["sent_prefixes"].pop(0)
                    continue
                data[family] = {}
                data[family]["received_prefixes"] = neighbor["received_prefixes"][idx]
                data[family]["accepted_prefixes"] = neighbor["accepted_prefixes"][idx]
                if "in sync" in neighbor["send-state"][idx]:
                    data[family]["sent_prefixes"] = neighbor["sent_prefixes"].pop(0)
                else:
                    data[family]["sent_prefixes"] = 0
        else:
            family = self._get_address_family(neighbor["tables"], instance)
            if family is not None:
                data[family] = {}
                data[family]["received_prefixes"] = neighbor["received_prefixes"]
                data[family]["accepted_prefixes"] = neighbor["accepted_prefixes"]
                data[family]["sent_prefixes"] = neighbor["sent_prefixes"]
        return data

    @staticmethod
    def _parse_value(value):
        if isinstance(value, str):
            return str(value)
        elif value is None:
            return ""
        else:
            return value

    def get_bgp_neighbors(self):
        """Return BGP neighbors details."""
        bgp_neighbor_data = {}
        default_neighbor_details = {
            "local_as": 0,
            "remote_as": 0,
            "remote_id": "",
            "is_up": False,
            "is_enabled": False,
            "description": "",
            "uptime": 0,
            "address_family": {},
        }
        keys = default_neighbor_details.keys()

        uptime_table = junos_views.junos_bgp_uptime_table(self.device)
        bgp_neighbors_table = junos_views.junos_bgp_table(self.device)

        uptime_table_lookup = {}

        def _get_uptime_table(instance):
            if instance not in uptime_table_lookup:
                uptime_table_lookup[instance] = uptime_table.get(
                    instance=instance
                ).items()
            return uptime_table_lookup[instance]

        def _get_bgp_neighbors_core(
            neighbor_data, instance=None, uptime_table_items=None
        ):
            """
            Make sure to execute a simple request whenever using
            junos > 13. This is a helper used to avoid code redundancy
            and reuse the function also when iterating through the list
            BGP neighbors under a specific routing instance,
            also when the device is capable to return the routing
            instance name at the BGP neighbor level.
            """
            for bgp_neighbor in neighbor_data:
                peer_ip = napalm.base.helpers.ip(bgp_neighbor[0].split("+")[0])
                neighbor_details = deepcopy(default_neighbor_details)
                neighbor_details.update(
                    {
                        elem[0]: elem[1]
                        for elem in bgp_neighbor[1]
                        if elem[1] is not None
                    }
                )
                if not instance:
                    # not instance, means newer Junos version,
                    # as we request everything in a single request
                    peer_fwd_rti = neighbor_details.pop("peer_fwd_rti")
                    instance = peer_fwd_rti
                else:
                    # instance is explicitly requests,
                    # thus it's an old Junos, so we retrieve the BGP neighbors
                    # under a certain routing instance
                    peer_fwd_rti = neighbor_details.pop("peer_fwd_rti", "")
                instance_name = "global" if instance == "master" else instance
                if instance_name not in bgp_neighbor_data:
                    bgp_neighbor_data[instance_name] = {}
                if "router_id" not in bgp_neighbor_data[instance_name]:
                    # we only need to set this once
                    bgp_neighbor_data[instance_name]["router_id"] = str(
                        neighbor_details.get("local_id", "")
                    )
                peer = {
                    key: self._parse_value(value)
                    for key, value in neighbor_details.items()
                    if key in keys
                }
                peer["local_as"] = napalm.base.helpers.as_number(peer["local_as"])
                peer["remote_as"] = napalm.base.helpers.as_number(peer["remote_as"])
                peer["address_family"] = self._parse_route_stats(
                    neighbor_details, instance
                )
                if "peers" not in bgp_neighbor_data[instance_name]:
                    bgp_neighbor_data[instance_name]["peers"] = {}
                bgp_neighbor_data[instance_name]["peers"][peer_ip] = peer
                if not uptime_table_items:
                    uptime_table_items = _get_uptime_table(instance)
                for neighbor, uptime in uptime_table_items:
                    normalized_neighbor = napalm.base.helpers.ip(neighbor)
                    if (
                        normalized_neighbor
                        not in bgp_neighbor_data[instance_name]["peers"]
                    ):
                        bgp_neighbor_data[instance_name]["peers"][
                            normalized_neighbor
                        ] = {}
                    bgp_neighbor_data[instance_name]["peers"][normalized_neighbor][
                        "uptime"
                    ] = uptime[0][1]

        # Commenting out the following sections, till Junos
        #   will provide a way to identify the routing instance name
        #   from the details of the BGP neighbor
        #   currently, there are Junos 15 version having a field called `peer_fwd_rti`
        #   but unfortunately, this is not consistent.
        # Junos 17 might have this fixed, but this needs to be revisited later.
        # In the definition below, `old_junos` means a version that does not provide
        #   the forwarding RTI information.
        #
        # old_junos = napalm.base.helpers.convert(
        #     int, self.device.facts.get('version', '0.0').split('.')[0], 0) < 15

        # if old_junos:
        instances = junos_views.junos_route_instance_table(self.device).get()
        for instance, instance_data in instances.items():
            if instance.startswith("__"):
                # junos internal instances
                continue
            bgp_neighbor_data[instance] = {"peers": {}}
            instance_neighbors = bgp_neighbors_table.get(instance=instance).items()
            uptime_table_items = uptime_table.get(instance=instance).items()
            _get_bgp_neighbors_core(
                instance_neighbors,
                instance=instance,
                uptime_table_items=uptime_table_items,
            )
        # If the OS provides the `peer_fwd_rti` or any way to identify the
        #   routing instance name (see above), the performances of this getter
        #   can be significantly improved, as we won't execute one request
        #   for each an every RT.
        # However, this improvement would only be beneficial for multi-VRF envs.
        #
        # else:
        #     instance_neighbors = bgp_neighbors_table.get().items()
        #     _get_bgp_neighbors_core(instance_neighbors)
        bgp_tmp_dict = {}
        for k, v in bgp_neighbor_data.items():
            if bgp_neighbor_data[k]["peers"]:
                bgp_tmp_dict[k] = v
        return bgp_tmp_dict

    def get_lldp_neighbors(self):
        """Return LLDP neighbors details."""
        lldp = junos_views.junos_lldp_table(self.device)
        try:
            lldp.get()
        except RpcError as rpcerr:
            # this assumes the library runs in an environment
            # able to handle logs
            # otherwise, the user just won't see this happening
            log.error("Unable to retrieve the LLDP neighbors information:")
            log.error(str(rpcerr))
            return {}
        result = lldp.items()

        neighbors = {}
        for neigh in result:
            if neigh[0] not in neighbors.keys():
                neighbors[neigh[0]] = []
            neighbors[neigh[0]].append({x[0]: str(x[1]) for x in neigh[1]})

        return neighbors

    def _transform_lldp_capab(self, capabilities):
        if capabilities and isinstance(capabilities, str):
            capabilities = capabilities.lower()
            return sorted(
                [
                    translation
                    for entry, translation in C.LLDP_CAPAB_TRANFORM_TABLE.items()
                    if entry in capabilities
                ]
            )
        else:
            return []

    def get_lldp_neighbors_detail(self, interface=""):
        """Detailed view of the LLDP neighbors."""
        lldp_neighbors = defaultdict(list)
        lldp_table = junos_views.junos_lldp_neighbors_detail_table(self.device)
        if not interface:
            try:
                lldp_table.get()
            except RpcError as rpcerr:
                # this assumes the library runs in an environment
                # able to handle logs
                # otherwise, the user just won't see this happening
                log.error("Unable to retrieve the LLDP neighbors information:")
                log.error(str(rpcerr))
                return {}
            interfaces = lldp_table.get().keys()
        else:
            interfaces = [interface]

        if self.device.facts.get("switch_style") == "VLAN":
            lldp_table.GET_RPC = "get-lldp-interface-neighbors-information"
            interface_variable = "interface_name"
            alt_rpc = "get-lldp-interface-neighbors"
            alt_interface_variable = "interface_device"
        else:
            lldp_table.GET_RPC = "get-lldp-interface-neighbors"
            interface_variable = "interface_device"
            alt_rpc = "get-lldp-interface-neighbors-information"
            alt_interface_variable = "interface_name"

        for interface in interfaces:
            try:
                interface_args = {interface_variable: interface}
                lldp_table.get(**interface_args)
            except RpcError as e:
                if "syntax error" in str(e):
                    # Looks like we need to call a different RPC on this device
                    # Switch to the alternate style
                    lldp_table.GET_RPC = alt_rpc
                    interface_variable = alt_interface_variable
                    # Retry
                    interface_args = {interface_variable: interface}
                    lldp_table.get(**interface_args)

            for item in lldp_table:
                lldp_neighbors[interface].append(
                    {
                        "parent_interface": item.parent_interface,
                        "remote_port": item.remote_port or "",
                        "remote_chassis_id": napalm.base.helpers.convert(
                            napalm.base.helpers.mac,
                            item.remote_chassis_id,
                            item.remote_chassis_id,
                        ),
                        "remote_port_description": napalm.base.helpers.convert(
                            str, item.remote_port_description
                        ),
                        "remote_system_name": item.remote_system_name,
                        "remote_system_description": item.remote_system_description,
                        "remote_system_capab": self._transform_lldp_capab(
                            item.remote_system_capab
                        ),
                        "remote_system_enable_capab": self._transform_lldp_capab(
                            item.remote_system_enable_capab
                        ),
                    }
                )

        return lldp_neighbors

    def cli(self, commands):
        """Execute raw CLI commands and returns their output."""
        cli_output = {}

        def _count(txt, none):  # Second arg for consistency only. noqa
            """
            Return the exact output, as Junos displays
            e.g.:
            > show system processes extensive | match root | count
            Count: 113 lines
            """
            count = len(txt.splitlines())
            return "Count: {count} lines".format(count=count)

        def _trim(txt, length):
            """
            Trim specified number of columns from start of line.
            """
            try:
                newlines = []
                for line in txt.splitlines():
                    newlines.append(line[int(length) :])
                return "\n".join(newlines)
            except ValueError:
                return txt

        def _except(txt, pattern):
            """
            Show only text that does not match a pattern.
            """
            rgx = "^.*({pattern}).*$".format(pattern=pattern)
            unmatched = [
                line for line in txt.splitlines() if not re.search(rgx, line, re.I)
            ]
            return "\n".join(unmatched)

        def _last(txt, length):
            """
            Display end of output only.
            """
            try:
                return "\n".join(txt.splitlines()[(-1) * int(length) :])
            except ValueError:
                return txt

        def _match(txt, pattern):
            """
            Show only text that matches a pattern.
            """
            rgx = "^.*({pattern}).*$".format(pattern=pattern)
            matched = [line for line in txt.splitlines() if re.search(rgx, line, re.I)]
            return "\n".join(matched)

        def _find(txt, pattern):
            """
            Search for first occurrence of pattern.
            """
            rgx = "^.*({pattern})(.*)$".format(pattern=pattern)
            match = re.search(rgx, txt, re.I | re.M | re.DOTALL)
            if match:
                return "{pattern}{rest}".format(pattern=pattern, rest=match.group(2))
            else:
                return "\nPattern not found"

        def _process_pipe(cmd, txt):
            """
            Process CLI output from Juniper device that
            doesn't allow piping the output.
            """
            if txt is None:
                return txt
            _OF_MAP = OrderedDict()
            _OF_MAP["except"] = _except
            _OF_MAP["match"] = _match
            _OF_MAP["last"] = _last
            _OF_MAP["trim"] = _trim
            _OF_MAP["count"] = _count
            _OF_MAP["find"] = _find
            # the operations order matter in this case!
            exploded_cmd = cmd.split("|")
            pipe_oper_args = {}
            for pipe in exploded_cmd[1:]:
                exploded_pipe = pipe.split()
                pipe_oper = exploded_pipe[0]  # always there
                pipe_args = "".join(exploded_pipe[1:2])
                # will not throw error when there's no arg
                pipe_oper_args[pipe_oper] = pipe_args
            for oper in _OF_MAP.keys():
                # to make sure the operation sequence is correct
                if oper not in pipe_oper_args.keys():
                    continue
                txt = _OF_MAP[oper](txt, pipe_oper_args[oper])
            return txt

        if not isinstance(commands, list):
            raise TypeError("Please enter a valid list of commands!")
        _PIPE_BLACKLIST = ["save"]
        # Preprocessing to avoid forbidden commands
        for command in commands:
            exploded_cmd = command.split("|")
            command_safe_parts = []
            for pipe in exploded_cmd[1:]:
                exploded_pipe = pipe.split()
                pipe_oper = exploded_pipe[0]  # always there
                if pipe_oper in _PIPE_BLACKLIST:
                    continue
                pipe_args = "".join(exploded_pipe[1:2])
                safe_pipe = (
                    pipe_oper
                    if not pipe_args
                    else "{fun} {args}".format(fun=pipe_oper, args=pipe_args)
                )
                command_safe_parts.append(safe_pipe)
            safe_command = (
                exploded_cmd[0]
                if not command_safe_parts
                else "{base} | {pipes}".format(
                    base=exploded_cmd[0], pipes=" | ".join(command_safe_parts)
                )
            )
            raw_txt = self.device.cli(safe_command, warning=False)
            cli_output[str(command)] = str(_process_pipe(command, raw_txt))
        return cli_output

    def get_bgp_config(self, group="", neighbor=""):
        """Return BGP configuration."""

        def _check_nhs(policies, nhs_policies):
            if not isinstance(policies, list):
                # Make it a list if it is a single policy
                policies = [policies]
            # Return True if "next-hop self" was found in any of the policies p
            for p in policies:
                if nhs_policies[p] is True:
                    return True
            return False

        def update_dict(d, u):  # for deep dictionary update
            for k, v in u.items():
                if isinstance(d, collections.Mapping):
                    if isinstance(v, collections.Mapping):
                        r = update_dict(d.get(k, {}), v)
                        d[k] = r
                    else:
                        d[k] = u[k]
                else:
                    d = {k: u[k]}
            return d

        def build_prefix_limit(**args):
            """
            Transform the lements of a dictionary into nested dictionaries.

            Example:
                {
                    'inet_unicast_limit': 500,
                    'inet_unicast_teardown_threshold': 95,
                    'inet_unicast_teardown_timeout': 5
                }

                becomes:

                {
                    'inet': {
                        'unicast': {
                            'limit': 500,
                            'teardown': {
                                'threshold': 95,
                                'timeout': 5
                            }
                        }
                    }
                }
            """
            prefix_limit = {}

            for key, value in args.items():
                key_levels = key.split("_")
                length = len(key_levels) - 1
                temp_dict = {key_levels[length]: value}
                for index in reversed(range(length)):
                    level = key_levels[index]
                    temp_dict = {level: temp_dict}
                update_dict(prefix_limit, temp_dict)

            return prefix_limit

        _COMMON_FIELDS_DATATYPE_ = {
            "description": str,
            "local_address": str,
            "local_as": int,
            "remote_as": int,
            "import_policy": str,
            "export_policy": str,
            "inet_unicast_limit_prefix_limit": int,
            "inet_unicast_teardown_threshold_prefix_limit": int,
            "inet_unicast_teardown_timeout_prefix_limit": int,
            "inet_unicast_novalidate_prefix_limit": int,
            "inet_flow_limit_prefix_limit": int,
            "inet_flow_teardown_threshold_prefix_limit": int,
            "inet_flow_teardown_timeout_prefix_limit": int,
            "inet_flow_novalidate_prefix_limit": str,
            "inet6_unicast_limit_prefix_limit": int,
            "inet6_unicast_teardown_threshold_prefix_limit": int,
            "inet6_unicast_teardown_timeout_prefix_limit": int,
            "inet6_unicast_novalidate_prefix_limit": int,
            "inet6_flow_limit_prefix_limit": int,
            "inet6_flow_teardown_threshold_prefix_limit": int,
            "inet6_flow_teardown_timeout_prefix_limit": int,
            "inet6_flow_novalidate_prefix_limit": str,
        }

        _PEER_FIELDS_DATATYPE_MAP_ = {
            "authentication_key": str,
            "route_reflector_client": bool,
            "nhs": bool,
        }
        _PEER_FIELDS_DATATYPE_MAP_.update(_COMMON_FIELDS_DATATYPE_)

        _GROUP_FIELDS_DATATYPE_MAP_ = {
            "type": str,
            "apply_groups": list,
            "remove_private_as": bool,
            "multipath": bool,
            "multihop_ttl": int,
        }
        _GROUP_FIELDS_DATATYPE_MAP_.update(_COMMON_FIELDS_DATATYPE_)

        _DATATYPE_DEFAULT_ = {str: "", int: 0, bool: False, list: []}

        bgp_config = {}

        if group:
            bgp = junos_views.junos_bgp_config_group_table(self.device)
            bgp.get(group=group, options={"database": self.junos_config_database})
        else:
            bgp = junos_views.junos_bgp_config_table(self.device)
            bgp.get(options={"database": self.junos_config_database})
            neighbor = ""  # if no group is set, no neighbor should be set either
        bgp_items = bgp.items()

        if neighbor:
            neighbor_ip = napalm.base.helpers.ip(neighbor)

        # Get all policies configured in one go and check if "next-hop self" is found in each policy
        # Save the result in a dict indexed by policy name (junos policy-statement)
        # The value is a boolean. True if "next-hop self" was found
        # The resulting dict (nhs_policies) will be used by _check_nhs to determine if "nhs"
        # is configured or not in the policies applied to a BGP neighbor
        policy = junos_views.junos_policy_nhs_config_table(self.device)
        policy.get(options={"database": self.junos_config_database})
        nhs_policies = dict()
        for policy_name, is_nhs_list in policy.items():
            # is_nhs_list is a list with one element. Ex: [('is_nhs', True)]
            is_nhs, boolean = is_nhs_list[0]
            nhs_policies[policy_name] = boolean if boolean is not None else False

        for bgp_group in bgp_items:
            bgp_group_name = bgp_group[0]
            bgp_group_details = bgp_group[1]
            bgp_config[bgp_group_name] = {
                field: _DATATYPE_DEFAULT_.get(datatype)
                for field, datatype in _GROUP_FIELDS_DATATYPE_MAP_.items()
                if "_prefix_limit" not in field
            }
            for elem in bgp_group_details:
                if not ("_prefix_limit" not in elem[0] and elem[1] is not None):
                    continue
                datatype = _GROUP_FIELDS_DATATYPE_MAP_.get(elem[0])
                default = _DATATYPE_DEFAULT_.get(datatype)
                key = elem[0]
                value = elem[1]
                if key in ["export_policy", "import_policy"]:
                    if isinstance(value, list):
                        value = " ".join(value)
                if key == "local_address":
                    value = napalm.base.helpers.convert(
                        napalm.base.helpers.ip, value, value
                    )
                if key == "neighbors":
                    bgp_group_peers = value
                    continue
                bgp_config[bgp_group_name].update(
                    {key: napalm.base.helpers.convert(datatype, value, default)}
                )
            prefix_limit_fields = {}
            for elem in bgp_group_details:
                if "_prefix_limit" in elem[0] and elem[1] is not None:
                    datatype = _GROUP_FIELDS_DATATYPE_MAP_.get(elem[0])
                    default = _DATATYPE_DEFAULT_.get(datatype)
                    prefix_limit_fields.update(
                        {
                            elem[0].replace(
                                "_prefix_limit", ""
                            ): napalm.base.helpers.convert(datatype, elem[1], default)
                        }
                    )
            bgp_config[bgp_group_name]["prefix_limit"] = build_prefix_limit(
                **prefix_limit_fields
            )
            if "multihop" in bgp_config[bgp_group_name].keys():
                # Delete 'multihop' key from the output
                del bgp_config[bgp_group_name]["multihop"]
                if bgp_config[bgp_group_name]["multihop_ttl"] == 0:
                    # Set ttl to default value 64
                    bgp_config[bgp_group_name]["multihop_ttl"] = 64

            bgp_config[bgp_group_name]["neighbors"] = {}
            for bgp_group_neighbor in bgp_group_peers.items():
                bgp_peer_address = napalm.base.helpers.ip(bgp_group_neighbor[0])
                if neighbor and bgp_peer_address != neighbor:
                    continue  # if filters applied, jump over all other neighbors
                bgp_group_details = bgp_group_neighbor[1]
                bgp_peer_details = {
                    field: _DATATYPE_DEFAULT_.get(datatype)
                    for field, datatype in _PEER_FIELDS_DATATYPE_MAP_.items()
                    if "_prefix_limit" not in field
                }
                for elem in bgp_group_details:
                    if not ("_prefix_limit" not in elem[0] and elem[1] is not None):
                        continue
                    datatype = _PEER_FIELDS_DATATYPE_MAP_.get(elem[0])
                    default = _DATATYPE_DEFAULT_.get(datatype)
                    key = elem[0]
                    value = elem[1]
                    if key in ["export_policy"]:
                        # next-hop self is applied on export IBGP sessions
                        bgp_peer_details["nhs"] = _check_nhs(value, nhs_policies)
                    if key in ["export_policy", "import_policy"]:
                        if isinstance(value, list):
                            value = " ".join(value)
                    if key == "local_address":
                        value = napalm.base.helpers.convert(
                            napalm.base.helpers.ip, value, value
                        )
                    bgp_peer_details.update(
                        {key: napalm.base.helpers.convert(datatype, value, default)}
                    )
                    bgp_peer_details["local_as"] = napalm.base.helpers.as_number(
                        bgp_peer_details["local_as"]
                    )
                    bgp_peer_details["remote_as"] = napalm.base.helpers.as_number(
                        bgp_peer_details["remote_as"]
                    )
                    if key == "cluster":
                        bgp_peer_details["route_reflector_client"] = True
                        # we do not want cluster in the output
                        del bgp_peer_details["cluster"]

                if "cluster" in bgp_config[bgp_group_name].keys():
                    bgp_peer_details["route_reflector_client"] = True
                prefix_limit_fields = {}
                for elem in bgp_group_details:
                    if "_prefix_limit" in elem[0] and elem[1] is not None:
                        datatype = _PEER_FIELDS_DATATYPE_MAP_.get(elem[0])
                        default = _DATATYPE_DEFAULT_.get(datatype)
                        prefix_limit_fields.update(
                            {
                                elem[0].replace(
                                    "_prefix_limit", ""
                                ): napalm.base.helpers.convert(
                                    datatype, elem[1], default
                                )
                            }
                        )
                bgp_peer_details["prefix_limit"] = build_prefix_limit(
                    **prefix_limit_fields
                )
                bgp_config[bgp_group_name]["neighbors"][
                    bgp_peer_address
                ] = bgp_peer_details
                if neighbor and bgp_peer_address == neighbor_ip:
                    break  # found the desired neighbor

            if "cluster" in bgp_config[bgp_group_name].keys():
                # we do not want cluster in the output
                del bgp_config[bgp_group_name]["cluster"]

        return bgp_config

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        """Detailed view of the BGP neighbors operational data."""
        bgp_neighbors = {}
        default_neighbor_details = {
            "up": False,
            "local_as": 0,
            "remote_as": 0,
            "router_id": "",
            "local_address": "",
            "routing_table": "",
            "local_address_configured": False,
            "local_port": 0,
            "remote_address": "",
            "remote_port": 0,
            "multihop": False,
            "multipath": False,
            "remove_private_as": False,
            "import_policy": "",
            "export_policy": "",
            "input_messages": -1,
            "output_messages": -1,
            "input_updates": -1,
            "output_updates": -1,
            "messages_queued_out": -1,
            "connection_state": "",
            "previous_connection_state": "",
            "last_event": "",
            "suppress_4byte_as": False,
            "local_as_prepend": False,
            "holdtime": 0,
            "configured_holdtime": 0,
            "keepalive": 0,
            "configured_keepalive": 0,
            "active_prefix_count": -1,
            "received_prefix_count": -1,
            "accepted_prefix_count": -1,
            "suppressed_prefix_count": -1,
            "advertised_prefix_count": -1,
            "flap_count": 0,
        }
        OPTION_KEY_MAP = {
            "RemovePrivateAS": "remove_private_as",
            "Multipath": "multipath",
            "Multihop": "multihop",
            "AddressFamily": "local_address_configured"
            # 'AuthKey'        : 'authentication_key_set'
            # but other vendors do not specify if auth key is set
            # other options:
            # Preference, HoldTime, Ttl, LogUpDown, Refresh
        }

        def _bgp_iter_core(neighbor_data, instance=None):
            """
            Iterate over a list of neighbors.
            For older junos, the routing instance is not specified inside the
            BGP neighbors XML, therefore we need to use a super sub-optimal structure
            as in get_bgp_neighbors: iterate through the list of network instances
            then execute one request for each and every routing instance.
            For newer junos, this is not necessary as the routing instance is available
            and we can get everything solve in a single request.
            """
            for bgp_neighbor in neighbor_data:
                remote_as = int(bgp_neighbor[0])
                neighbor_details = deepcopy(default_neighbor_details)
                neighbor_details.update(
                    {
                        elem[0]: elem[1]
                        for elem in bgp_neighbor[1]
                        if elem[1] is not None
                    }
                )
                if not instance:
                    peer_fwd_rti = neighbor_details.pop("peer_fwd_rti")
                    instance = peer_fwd_rti
                else:
                    peer_fwd_rti = neighbor_details.pop("peer_fwd_rti", "")
                instance_name = "global" if instance == "master" else instance
                options = neighbor_details.pop("options", "")
                if isinstance(options, str):
                    options_list = options.split()
                    for option in options_list:
                        key = OPTION_KEY_MAP.get(option)
                        if key is not None:
                            neighbor_details[key] = True
                four_byte_as = neighbor_details.pop("4byte_as", 0)
                local_address = neighbor_details.pop("local_address", "")
                local_details = local_address.split("+")
                neighbor_details["local_address"] = napalm.base.helpers.convert(
                    napalm.base.helpers.ip, local_details[0], local_details[0]
                )
                if len(local_details) == 2:
                    neighbor_details["local_port"] = int(local_details[1])
                else:
                    neighbor_details["local_port"] = 179
                neighbor_details["suppress_4byte_as"] = remote_as != four_byte_as
                peer_address = neighbor_details.pop("peer_address", "")
                remote_details = peer_address.split("+")
                neighbor_details["remote_address"] = napalm.base.helpers.convert(
                    napalm.base.helpers.ip, remote_details[0], remote_details[0]
                )
                if len(remote_details) == 2:
                    neighbor_details["remote_port"] = int(remote_details[1])
                else:
                    neighbor_details["remote_port"] = 179
                neighbor_details["routing_table"] = instance_name
                neighbor_details["local_as"] = napalm.base.helpers.as_number(
                    neighbor_details["local_as"]
                )
                neighbor_details["remote_as"] = napalm.base.helpers.as_number(
                    neighbor_details["remote_as"]
                )
                neighbors_rib = neighbor_details.pop("rib")
                neighbors_queue = neighbor_details.pop("queue")
                messages_queued_out = 0
                for queue_entry in neighbors_queue.items():
                    messages_queued_out += queue_entry[1][0][1]
                neighbor_details["messages_queued_out"] = messages_queued_out
                if instance_name not in bgp_neighbors.keys():
                    bgp_neighbors[instance_name] = {}
                if remote_as not in bgp_neighbors[instance_name].keys():
                    bgp_neighbors[instance_name][remote_as] = []
                neighbor_rib_stats = neighbors_rib.items()
                if not neighbor_rib_stats:
                    bgp_neighbors[instance_name][remote_as].append(neighbor_details)
                    continue  # no RIBs available, pass default details
                neighbor_rib_details = {
                    "active_prefix_count": 0,
                    "received_prefix_count": 0,
                    "accepted_prefix_count": 0,
                    "suppressed_prefix_count": 0,
                    "advertised_prefix_count": 0,
                }
                for rib_entry in neighbor_rib_stats:
                    for elem in rib_entry[1]:
                        if elem[1] is None:
                            neighbor_rib_details[elem[0]] += 0
                        else:
                            neighbor_rib_details[elem[0]] += elem[1]
                neighbor_details.update(neighbor_rib_details)
                bgp_neighbors[instance_name][remote_as].append(neighbor_details)

        # old_junos = napalm.base.helpers.convert(
        #     int, self.device.facts.get('version', '0.0').split('.')[0], 0) < 15
        bgp_neighbors_table = junos_views.junos_bgp_neighbors_table(self.device)

        # if old_junos:
        instances = junos_views.junos_route_instance_table(self.device)
        for instance, instance_data in instances.get().items():
            if instance.startswith("__"):
                # junos internal instances
                continue
            neighbor_data = bgp_neighbors_table.get(
                instance=instance, neighbor_address=str(neighbor_address)
            ).items()
            _bgp_iter_core(neighbor_data, instance=instance)
        # else:
        #     bgp_neighbors_table = junos_views.junos_bgp_neighbors_table(self.device)
        #     neighbor_data = bgp_neighbors_table.get(neighbor_address=neighbor_address).items()
        #     _bgp_iter_core(neighbor_data)
        return bgp_neighbors

    def get_arp_table(self, vrf=""):
        """Return the ARP table."""
        # could use ArpTable
        # from jnpr.junos.op.phyport import ArpTable
        # and simply use it
        # but
        # we need:
        #   - filters
        #   - group by VLAN ID
        #   - hostname & TTE fields as well
        if vrf:
            msg = "VRF support has not been added for this getter on this platform."
            raise NotImplementedError(msg)

        arp_table = []

        arp_table_raw = junos_views.junos_arp_table(self.device)
        arp_table_raw.get()
        arp_table_items = arp_table_raw.items()

        for arp_table_entry in arp_table_items:
            arp_entry = {elem[0]: elem[1] for elem in arp_table_entry[1]}
            arp_entry["mac"] = napalm.base.helpers.mac(arp_entry.get("mac"))
            arp_entry["ip"] = napalm.base.helpers.ip(arp_entry.get("ip"))
            arp_table.append(arp_entry)

        return arp_table

    def get_ipv6_neighbors_table(self):
        """Return the IPv6 neighbors table."""
        ipv6_neighbors_table = []

        ipv6_neighbors_table_raw = junos_views.junos_ipv6_neighbors_table(self.device)
        ipv6_neighbors_table_raw.get()
        ipv6_neighbors_table_items = ipv6_neighbors_table_raw.items()

        for ipv6_table_entry in ipv6_neighbors_table_items:
            ipv6_entry = {elem[0]: elem[1] for elem in ipv6_table_entry[1]}
            ipv6_entry["mac"] = napalm.base.helpers.mac(ipv6_entry.get("mac"))
            ipv6_entry["ip"] = napalm.base.helpers.ip(ipv6_entry.get("ip"))
            ipv6_neighbors_table.append(ipv6_entry)

        return ipv6_neighbors_table

    def get_ntp_peers(self):
        """Return the NTP peers configured on the device."""
        ntp_table = junos_views.junos_ntp_peers_config_table(self.device)
        ntp_table.get(options={"database": self.junos_config_database})

        ntp_peers = ntp_table.items()

        if not ntp_peers:
            return {}

        return {napalm.base.helpers.ip(peer[0]): {} for peer in ntp_peers}

    def get_ntp_servers(self):
        """Return the NTP servers configured on the device."""
        ntp_table = junos_views.junos_ntp_servers_config_table(self.device)
        ntp_table.get(options={"database": self.junos_config_database})

        ntp_servers = ntp_table.items()

        if not ntp_servers:
            return {}

        return {napalm.base.helpers.ip(server[0]): {} for server in ntp_servers}

    def get_ntp_stats(self):
        """Return NTP stats (associations)."""
        # NTP Peers does not have XML RPC defined
        # thus we need to retrieve raw text and parse...
        # :(

        ntp_stats = []

        REGEX = (
            r"^\s?(\+|\*|x|-)?([a-zA-Z0-9\.+-:]+)"
            r"\s+([a-zA-Z0-9\.]+)\s+([0-9]{1,2})"
            r"\s+(-|u)\s+([0-9h-]+)\s+([0-9]+)"
            r"\s+([0-9]+)\s+([0-9\.]+)\s+([0-9\.-]+)"
            r"\s+([0-9\.]+)\s?$"
        )

        ntp_assoc_output = self.device.cli("show ntp associations no-resolve")
        ntp_assoc_output_lines = ntp_assoc_output.splitlines()

        for ntp_assoc_output_line in ntp_assoc_output_lines[3:]:  # except last line
            line_search = re.search(REGEX, ntp_assoc_output_line, re.I)
            if not line_search:
                continue  # pattern not found
            line_groups = line_search.groups()
            try:
                ntp_stats.append(
                    {
                        "remote": napalm.base.helpers.ip(line_groups[1]),
                        "synchronized": (line_groups[0] == "*"),
                        "referenceid": str(line_groups[2]),
                        "stratum": int(line_groups[3]),
                        "type": str(line_groups[4]),
                        "when": str(line_groups[5]),
                        "hostpoll": int(line_groups[6]),
                        "reachability": int(line_groups[7]),
                        "delay": float(line_groups[8]),
                        "offset": float(line_groups[9]),
                        "jitter": float(line_groups[10]),
                    }
                )
            except Exception:
                continue  # jump to next line

        return ntp_stats

    def get_interfaces_ip(self):
        """Return the configured IP addresses."""
        interfaces_ip = {}

        interface_table = junos_views.junos_ip_interfaces_table(self.device)
        interface_table.get()
        interface_table_items = interface_table.items()

        _FAMILY_VMAP_ = {
            "inet": "ipv4",
            "inet6": "ipv6"
            # can add more mappings
        }
        _FAMILY_MAX_PREFIXLEN = {"inet": 32, "inet6": 128}

        for interface_details in interface_table_items:
            ip_network = interface_details[0]
            ip_address = ip_network.split("/")[0]
            address = napalm.base.helpers.convert(
                napalm.base.helpers.ip, ip_address, ip_address
            )
            try:
                interface_details_dict = dict(interface_details[1])
                family_raw = interface_details_dict.get("family")
                interface = str(interface_details_dict.get("interface"))
            except ValueError:
                continue
            prefix = napalm.base.helpers.convert(
                int, ip_network.split("/")[-1], _FAMILY_MAX_PREFIXLEN.get(family_raw)
            )
            family = _FAMILY_VMAP_.get(family_raw)
            if not family or not interface:
                continue
            if interface not in interfaces_ip.keys():
                interfaces_ip[interface] = {}
            if family not in interfaces_ip[interface].keys():
                interfaces_ip[interface][family] = {}
            if address not in interfaces_ip[interface][family].keys():
                interfaces_ip[interface][family][address] = {}
            interfaces_ip[interface][family][address]["prefix_length"] = prefix

        return interfaces_ip

    def get_mac_address_table(self):
        """Return the MAC address table."""
        mac_address_table = []

        switch_style = self.device.facts.get("switch_style", "")
        if switch_style == "VLAN_L2NG":
            mac_table = junos_views.junos_mac_address_table_switch_l2ng(self.device)
        elif switch_style == "BRIDGE_DOMAIN":
            mac_table = junos_views.junos_mac_address_table(self.device)
        else:  # switch_style == "VLAN"
            mac_table = junos_views.junos_mac_address_table_switch(self.device)

        try:
            mac_table.get()
        except RpcError as e:
            # Device hasn't got it's l2 subsystem running
            # Don't error but just return an empty result
            if "l2-learning subsystem" in str(e):
                return []
            else:
                raise

        mac_table_items = mac_table.items()

        default_values = {
            "mac": "",
            "interface": "",
            "vlan": 0,
            "static": False,
            "active": True,
            "moves": 0,
            "last_move": 0.0,
        }

        for mac_table_entry in mac_table_items:
            mac_entry = default_values.copy()
            mac_entry.update({elem[0]: elem[1] for elem in mac_table_entry[1]})
            mac = mac_entry.get("mac")

            # JUNOS returns '*' for Type = Flood
            if mac == "*":
                continue

            mac_entry["mac"] = napalm.base.helpers.mac(mac)
            mac_address_table.append(mac_entry)

        return mac_address_table

    def get_route_to(self, destination="", protocol="", longer=False):
        """Return route details to a specific destination, learned from a certain protocol."""
        routes = {}

        if not isinstance(destination, str):
            raise TypeError("Please specify a valid destination!")

        if longer:
            raise NotImplementedError("Longer prefixes not yet supported on JunOS")

        if protocol and isinstance(destination, str):
            protocol = protocol.lower()

        if protocol == "connected":
            protocol = "direct"  # this is how is called on JunOS

        _COMMON_PROTOCOL_FIELDS_ = [
            "destination",
            "prefix_length",
            "protocol",
            "current_active",
            "last_active",
            "age",
            "next_hop",
            "outgoing_interface",
            "selected_next_hop",
            "preference",
            "inactive_reason",
            "routing_table",
        ]  # identifies the list of fileds common for all protocols

        _BOOLEAN_FIELDS_ = [
            "current_active",
            "selected_next_hop",
            "last_active",
        ]  # fields expected to have boolean values

        _PROTOCOL_SPECIFIC_FIELDS_ = {
            "bgp": [
                "local_as",
                "remote_as",
                "as_path",
                "communities",
                "local_preference",
                "preference2",
                "remote_address",
                "metric",
                "metric2",
            ],
            "isis": ["level", "metric", "local_as"],
        }

        routes_table = junos_views.junos_protocol_route_table(self.device)

        rt_kargs = {"destination": destination}
        if protocol and isinstance(destination, str):
            rt_kargs["protocol"] = protocol

        try:
            routes_table.get(**rt_kargs)
        except RpcTimeoutError:
            # on devices with milions of routes
            # in case the destination is too generic (e.g.: 10/8)
            # will take very very long to determine all routes and
            # moreover will return a huge list
            raise CommandTimeoutException(
                "Too many routes returned! Please try with a longer prefix or a specific protocol!"
            )
        except RpcError as rpce:
            if len(rpce.errs) > 0 and "bad_element" in rpce.errs[0]:
                raise CommandErrorException(
                    "Unknown protocol: {proto}".format(
                        proto=rpce.errs[0]["bad_element"]
                    )
                )
            raise CommandErrorException(rpce)
        except Exception as err:
            raise CommandErrorException(
                "Cannot retrieve routes! Reason: {err}".format(err=err)
            )

        routes_items = routes_table.items()

        for route in routes_items:
            d = {}
            # next_hop = route[0]
            d = {elem[0]: elem[1] for elem in route[1]}
            destination = d.pop("destination", "")
            prefix_length = d.pop("prefix_length", 32)
            destination = "{d}/{p}".format(d=destination, p=prefix_length)
            d.update({key: False for key in _BOOLEAN_FIELDS_ if d.get(key) is None})
            as_path = d.get("as_path")
            if as_path is not None:
                d["as_path"] = (
                    as_path.split(" I ")[0]
                    .replace("AS path:", "")
                    .replace("I", "")
                    .strip()
                )
                # to be sure that contains only AS Numbers
            if d.get("inactive_reason") is None:
                d["inactive_reason"] = ""
            route_protocol = d.get("protocol").lower()
            if protocol and protocol != route_protocol:
                continue
            communities = d.get("communities")
            if communities is not None and type(communities) is not list:
                d["communities"] = [communities]
            d_keys = list(d.keys())
            # fields that are not in _COMMON_PROTOCOL_FIELDS_ are supposed to be protocol specific
            all_protocol_attributes = {
                key: d.pop(key) for key in d_keys if key not in _COMMON_PROTOCOL_FIELDS_
            }
            protocol_attributes = {
                key: value
                for key, value in all_protocol_attributes.items()
                if key in _PROTOCOL_SPECIFIC_FIELDS_.get(route_protocol, [])
            }
            d["protocol_attributes"] = protocol_attributes
            if destination not in routes.keys():
                routes[destination] = []
            routes[destination].append(d)

        return routes

    def get_snmp_information(self):
        """Return the SNMP configuration."""
        snmp_information = {}

        snmp_config = junos_views.junos_snmp_config_table(self.device)
        snmp_config.get(options={"database": self.junos_config_database})
        snmp_items = snmp_config.items()

        if not snmp_items:
            return snmp_information

        snmp_information = {
            str(ele[0]): ele[1] if ele[1] else "" for ele in snmp_items[0][1]
        }

        snmp_information["community"] = {}
        communities_table = snmp_information.pop("communities_table")
        if not communities_table:
            return snmp_information

        for community in communities_table.items():
            community_name = str(community[0])
            community_details = {"acl": ""}
            community_details.update(
                {
                    str(ele[0]): str(
                        ele[1]
                        if ele[0] != "mode"
                        else C.SNMP_AUTHORIZATION_MODE_MAP.get(ele[1])
                    )
                    for ele in community[1]
                }
            )
            snmp_information["community"][community_name] = community_details

        return snmp_information

    def get_probes_config(self):
        """Return the configuration of the RPM probes."""
        probes = {}

        probes_table = junos_views.junos_rpm_probes_config_table(self.device)
        probes_table.get(options={"database": self.junos_config_database})
        probes_table_items = probes_table.items()

        for probe_test in probes_table_items:
            test_name = str(probe_test[0])
            test_details = {p[0]: p[1] for p in probe_test[1]}
            probe_name = napalm.base.helpers.convert(
                str, test_details.pop("probe_name")
            )
            target = napalm.base.helpers.convert(str, test_details.pop("target", ""))
            test_interval = napalm.base.helpers.convert(
                int, test_details.pop("test_interval", "0")
            )
            probe_count = napalm.base.helpers.convert(
                int, test_details.pop("probe_count", "0")
            )
            probe_type = napalm.base.helpers.convert(
                str, test_details.pop("probe_type", "")
            )
            source = napalm.base.helpers.convert(
                str, test_details.pop("source_address", "")
            )
            if probe_name not in probes.keys():
                probes[probe_name] = {}
            probes[probe_name][test_name] = {
                "probe_type": probe_type,
                "target": target,
                "source": source,
                "probe_count": probe_count,
                "test_interval": test_interval,
            }

        return probes

    def get_probes_results(self):
        """Return the results of the RPM probes."""
        probes_results = {}

        probes_results_table = junos_views.junos_rpm_probes_results_table(self.device)
        probes_results_table.get()
        probes_results_items = probes_results_table.items()

        for probe_result in probes_results_items:
            probe_name = str(probe_result[0])
            test_results = {p[0]: p[1] for p in probe_result[1]}
            test_results["last_test_loss"] = napalm.base.helpers.convert(
                int, test_results.pop("last_test_loss"), 0
            )
            for test_param_name, test_param_value in test_results.items():
                if isinstance(test_param_value, float):
                    test_results[test_param_name] = test_param_value * 1e-3
                    # convert from useconds to mseconds
            test_name = test_results.pop("test_name", "")
            source = test_results.get("source", "")
            if source is None:
                test_results["source"] = ""
            if probe_name not in probes_results.keys():
                probes_results[probe_name] = {}
            probes_results[probe_name][test_name] = test_results

        return probes_results

    def traceroute(
        self,
        destination,
        source=C.TRACEROUTE_SOURCE,
        ttl=C.TRACEROUTE_TTL,
        timeout=C.TRACEROUTE_TIMEOUT,
        vrf=C.TRACEROUTE_VRF,
    ):
        """Execute traceroute and return results."""
        traceroute_result = {}

        # calling form RPC does not work properly :(
        # but defined junos_route_instance_table just in case

        source_str = ""
        maxttl_str = ""
        wait_str = ""
        vrf_str = ""

        if source:
            source_str = " source {source}".format(source=source)
        if ttl:
            maxttl_str = " ttl {ttl}".format(ttl=ttl)
        if timeout:
            wait_str = " wait {timeout}".format(timeout=timeout)
        if vrf:
            vrf_str = " routing-instance {vrf}".format(vrf=vrf)

        traceroute_command = "traceroute {destination}{source}{maxttl}{wait}{vrf}".format(
            destination=destination,
            source=source_str,
            maxttl=maxttl_str,
            wait=wait_str,
            vrf=vrf_str,
        )

        traceroute_rpc = E("command", traceroute_command)
        rpc_reply = self.device._conn.rpc(traceroute_rpc)._NCElement__doc
        # make direct RPC call via NETCONF
        traceroute_results = rpc_reply.find(".//traceroute-results")

        traceroute_failure = napalm.base.helpers.find_txt(
            traceroute_results, "traceroute-failure", ""
        )
        error_message = napalm.base.helpers.find_txt(
            traceroute_results, "rpc-error/error-message", ""
        )

        if traceroute_failure and error_message:
            return {"error": "{}: {}".format(traceroute_failure, error_message)}

        traceroute_result["success"] = {}
        for hop in traceroute_results.findall("hop"):
            ttl_value = napalm.base.helpers.convert(
                int, napalm.base.helpers.find_txt(hop, "ttl-value"), 1
            )
            if ttl_value not in traceroute_result["success"]:
                traceroute_result["success"][ttl_value] = {"probes": {}}
            for probe in hop.findall("probe-result"):
                probe_index = napalm.base.helpers.convert(
                    int, napalm.base.helpers.find_txt(probe, "probe-index"), 0
                )
                ip_address = napalm.base.helpers.convert(
                    napalm.base.helpers.ip,
                    napalm.base.helpers.find_txt(probe, "ip-address"),
                    "*",
                )
                host_name = str(napalm.base.helpers.find_txt(probe, "host-name", "*"))
                rtt = (
                    napalm.base.helpers.convert(
                        float, napalm.base.helpers.find_txt(probe, "rtt"), 0
                    )
                    * 1e-3
                )  # ms
                traceroute_result["success"][ttl_value]["probes"][probe_index] = {
                    "ip_address": ip_address,
                    "host_name": host_name,
                    "rtt": rtt,
                }

        return traceroute_result

    def ping(
        self,
        destination,
        source=C.PING_SOURCE,
        ttl=C.PING_TTL,
        timeout=C.PING_TIMEOUT,
        size=C.PING_SIZE,
        count=C.PING_COUNT,
        vrf=C.PING_VRF,
    ):

        ping_dict = {}

        source_str = ""
        maxttl_str = ""
        timeout_str = ""
        size_str = ""
        count_str = ""
        vrf_str = ""

        if source:
            source_str = " source {source}".format(source=source)
        if ttl:
            maxttl_str = " ttl {ttl}".format(ttl=ttl)
        if timeout:
            timeout_str = " wait {timeout}".format(timeout=timeout)
        if size:
            size_str = " size {size}".format(size=size)
        if count:
            count_str = " count {count}".format(count=count)
        if vrf:
            vrf_str = " routing-instance {vrf}".format(vrf=vrf)

        ping_command = "ping {destination}{source}{ttl}{timeout}{size}{count}{vrf}".format(
            destination=destination,
            source=source_str,
            ttl=maxttl_str,
            timeout=timeout_str,
            size=size_str,
            count=count_str,
            vrf=vrf_str,
        )

        ping_rpc = E("command", ping_command)
        rpc_reply = self.device._conn.rpc(ping_rpc)._NCElement__doc
        # make direct RPC call via NETCONF
        probe_summary = rpc_reply.find(".//probe-results-summary")

        if probe_summary is None:
            rpc_error = rpc_reply.find(".//rpc-error")
            return {
                "error": "{}".format(
                    napalm.base.helpers.find_txt(rpc_error, "error-message")
                )
            }

        packet_loss = napalm.base.helpers.convert(
            int, napalm.base.helpers.find_txt(probe_summary, "packet-loss"), 100
        )

        # rtt values are valid only if a we get an ICMP reply
        if packet_loss != 100:
            ping_dict["success"] = {}
            ping_dict["success"]["probes_sent"] = int(
                probe_summary.findtext("probes-sent")
            )
            ping_dict["success"]["packet_loss"] = packet_loss
            ping_dict["success"].update(
                {
                    "rtt_min": round(
                        (
                            napalm.base.helpers.convert(
                                float,
                                napalm.base.helpers.find_txt(
                                    probe_summary, "rtt-minimum"
                                ),
                                -1,
                            )
                            * 1e-3
                        ),
                        3,
                    ),
                    "rtt_max": round(
                        (
                            napalm.base.helpers.convert(
                                float,
                                napalm.base.helpers.find_txt(
                                    probe_summary, "rtt-maximum"
                                ),
                                -1,
                            )
                            * 1e-3
                        ),
                        3,
                    ),
                    "rtt_avg": round(
                        (
                            napalm.base.helpers.convert(
                                float,
                                napalm.base.helpers.find_txt(
                                    probe_summary, "rtt-average"
                                ),
                                -1,
                            )
                            * 1e-3
                        ),
                        3,
                    ),
                    "rtt_stddev": round(
                        (
                            napalm.base.helpers.convert(
                                float,
                                napalm.base.helpers.find_txt(
                                    probe_summary, "rtt-stddev"
                                ),
                                -1,
                            )
                            * 1e-3
                        ),
                        3,
                    ),
                }
            )

            tmp = rpc_reply.find(".//ping-results")

            results_array = []
            for probe_result in tmp.findall("probe-result"):
                ip_address = napalm.base.helpers.convert(
                    napalm.base.helpers.ip,
                    napalm.base.helpers.find_txt(probe_result, "ip-address"),
                    "*",
                )

                rtt = round(
                    (
                        napalm.base.helpers.convert(
                            float, napalm.base.helpers.find_txt(probe_result, "rtt"), -1
                        )
                        * 1e-3
                    ),
                    3,
                )

                results_array.append({"ip_address": ip_address, "rtt": rtt})

            ping_dict["success"].update({"results": results_array})
        else:
            return {"error": "Packet loss {}".format(packet_loss)}

        return ping_dict

    def _get_root(self):
        """get root user password."""
        _DEFAULT_USER_DETAILS = {"level": 20, "password": "", "sshkeys": []}
        root = {}
        root_table = junos_views.junos_root_table(self.device)
        root_table.get(options={"database": self.junos_config_database})
        root_items = root_table.items()
        for user_entry in root_items:
            username = "root"
            user_details = _DEFAULT_USER_DETAILS.copy()
            user_details.update({d[0]: d[1] for d in user_entry[1] if d[1]})
            user_details = {key: str(user_details[key]) for key in user_details.keys()}
            user_details["level"] = int(user_details["level"])
            user_details["sshkeys"] = [
                user_details.pop(key)
                for key in ["ssh_rsa", "ssh_dsa", "ssh_ecdsa"]
                if user_details.get(key, "")
            ]
            root[username] = user_details
        return root

    def get_users(self):
        """Return the configuration of the users."""
        users = {}

        _JUNOS_CLASS_CISCO_PRIVILEGE_LEVEL_MAP = {
            "super-user": 15,
            "superuser": 15,
            "operator": 5,
            "read-only": 1,
            "unauthorized": 0,
        }

        _DEFAULT_USER_DETAILS = {"level": 0, "password": "", "sshkeys": []}

        users_table = junos_views.junos_users_table(self.device)
        users_table.get(options={"database": self.junos_config_database})
        users_items = users_table.items()
        root_user = self._get_root()

        for user_entry in users_items:
            username = user_entry[0]
            user_details = _DEFAULT_USER_DETAILS.copy()
            user_details.update({d[0]: d[1] for d in user_entry[1] if d[1]})
            user_class = user_details.pop("class", "")
            user_details = {key: str(user_details[key]) for key in user_details.keys()}
            level = _JUNOS_CLASS_CISCO_PRIVILEGE_LEVEL_MAP.get(user_class, 0)
            user_details.update({"level": level})
            user_details["sshkeys"] = [
                user_details.pop(key)
                for key in ["ssh_rsa", "ssh_dsa", "ssh_ecdsa"]
                if user_details.get(key, "")
            ]
            users[username] = user_details
        users.update(root_user)
        return users

    def get_optics(self):
        """Return optics information."""
        optics_table = junos_views.junos_intf_optics_table(self.device)
        optics_table.get()
        optics_items = optics_table.items()

        # optics_items has no lane information, so we need to re-format data
        # inserting lane 0 for all optics. Note it contains all optics 10G/40G/100G
        # but the information for 40G/100G is incorrect at this point
        # Example: intf_optic item is now: ('xe-0/0/0', [ optical_values ])
        optics_items_with_lane = []
        for intf_optic_item in optics_items:
            temp_list = list(intf_optic_item)
            temp_list.insert(1, "0")
            new_intf_optic_item = tuple(temp_list)
            optics_items_with_lane.append(new_intf_optic_item)

        # Now optics_items_with_lane has all optics with lane 0 included
        # Example: ('xe-0/0/0', u'0', [ optical_values ])

        # Get optical information for 40G/100G optics
        optics_table40G = junos_views.junos_intf_40Goptics_table(self.device)
        optics_table40G.get()
        optics_40Gitems = optics_table40G.items()

        # Re-format data as before inserting lane value
        new_optics_40Gitems = []
        for item in optics_40Gitems:
            lane = item[0]
            iface = item[1].pop(0)
            new_optics_40Gitems.append((iface[1], str(lane), item[1]))

        # New_optics_40Gitems contains 40G/100G optics only:
        # ('et-0/0/49', u'0', [ optical_values ]),
        # ('et-0/0/49', u'1', [ optical_values ]),
        # ('et-0/0/49', u'2', [ optical_values ])

        # Remove 40G/100G optics entries with wrong information returned
        # from junos_intf_optics_table()
        iface_40G = [item[0] for item in new_optics_40Gitems]
        for intf_optic_item in optics_items_with_lane:
            iface_name = intf_optic_item[0]
            if iface_name not in iface_40G:
                new_optics_40Gitems.append(intf_optic_item)

        # New_optics_40Gitems contains all optics 10G/40G/100G with the lane
        optics_detail = {}
        for intf_optic_item in new_optics_40Gitems:
            lane = intf_optic_item[1]
            interface_name = str(intf_optic_item[0])
            optics = dict(intf_optic_item[2])
            if interface_name not in optics_detail:
                optics_detail[interface_name] = {}
                optics_detail[interface_name]["physical_channels"] = {}
                optics_detail[interface_name]["physical_channels"]["channel"] = []

            INVALID_LIGHT_LEVEL = [None, C.OPTICS_NULL_LEVEL, C.OPTICS_NULL_LEVEL_SPC]

            # Defaulting avg, min, max values to 0.0 since device does not
            # return these values
            intf_optics = {
                "index": int(lane),
                "state": {
                    "input_power": {
                        "instant": (
                            float(optics["input_power"])
                            if optics["input_power"] not in INVALID_LIGHT_LEVEL
                            else 0.0
                        ),
                        "avg": 0.0,
                        "max": 0.0,
                        "min": 0.0,
                    },
                    "output_power": {
                        "instant": (
                            float(optics["output_power"])
                            if optics["output_power"] not in INVALID_LIGHT_LEVEL
                            else 0.0
                        ),
                        "avg": 0.0,
                        "max": 0.0,
                        "min": 0.0,
                    },
                    "laser_bias_current": {
                        "instant": (
                            float(optics["laser_bias_current"])
                            if optics["laser_bias_current"] not in INVALID_LIGHT_LEVEL
                            else 0.0
                        ),
                        "avg": 0.0,
                        "max": 0.0,
                        "min": 0.0,
                    },
                },
            }
            optics_detail[interface_name]["physical_channels"]["channel"].append(
                intf_optics
            )

        return optics_detail

    def get_config(self, retrieve="all", full=False, sanitized=False):
        rv = {"startup": "", "running": "", "candidate": ""}

        options = {"format": "text", "database": "candidate"}
        sanitize_strings = {
            r"^(\s+community\s+)\w+(\s+{.*)$": r"\1<removed>\2",
            r'^(.*)"\$\d\$\S+"(;.*)$': r"\1<removed>\2",
        }
        if retrieve in ("candidate", "all"):
            config = self.device.rpc.get_config(filter_xml=None, options=options)
            rv["candidate"] = str(config.text)
        if retrieve in ("running", "all"):
            options["database"] = "committed"
            config = self.device.rpc.get_config(filter_xml=None, options=options)
            rv["running"] = str(config.text)

        if sanitized:
            return napalm.base.helpers.sanitize_configs(rv, sanitize_strings)

        return rv

    def get_network_instances(self, name=""):

        network_instances = {}

        ri_table = junos_views.junos_nw_instances_table(self.device)
        ri_table.get(options={"database": self.junos_config_database})
        ri_entries = ri_table.items()

        vrf_interfaces = []

        for ri_entry in ri_entries:
            ri_name = str(ri_entry[0])
            ri_details = {d[0]: d[1] for d in ri_entry[1]}
            ri_type = ri_details["instance_type"]
            if ri_type is None:
                ri_type = "default"
            ri_rd = ri_details["route_distinguisher"]
            ri_interfaces = ri_details["interfaces"]
            if not isinstance(ri_interfaces, list):
                ri_interfaces = [ri_interfaces]
            network_instances[ri_name] = {
                "name": ri_name,
                "type": C.OC_NETWORK_INSTANCE_TYPE_MAP.get(
                    ri_type, ri_type
                ),  # default: return raw
                "state": {"route_distinguisher": ri_rd if ri_rd else ""},
                "interfaces": {
                    "interface": {
                        intrf_name: {} for intrf_name in ri_interfaces if intrf_name
                    }
                },
            }
            vrf_interfaces.extend(
                network_instances[ri_name]["interfaces"]["interface"].keys()
            )

        all_interfaces = self.get_interfaces().keys()
        default_interfaces = list(set(all_interfaces) - set(vrf_interfaces))
        if "default" not in network_instances:
            network_instances["default"] = {
                "name": "default",
                "type": C.OC_NETWORK_INSTANCE_TYPE_MAP.get("default"),
                "state": {"route_distinguisher": ""},
                "interfaces": {
                    "interface": {
                        str(intrf_name): {} for intrf_name in default_interfaces
                    }
                },
            }

        if not name:
            return network_instances
        if name not in network_instances:
            return {}
        return {name: network_instances[name]}
