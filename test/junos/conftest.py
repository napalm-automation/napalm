"""Test fixtures."""
import copy

import lxml
import yaml
import pytest
from napalm.base.test import conftest as parent_conftest

from napalm.base.test.double import BaseTestDouble

from napalm.junos import junos


@pytest.fixture(scope="class")
def set_device_parameters(request):
    """Set up the class."""

    def fin():
        request.cls.device.close()

    request.addfinalizer(fin)

    request.cls.driver = junos.JunOSDriver
    request.cls.patched_driver = PatchedJunOSDriver
    request.cls.vendor = "junos"
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedJunOSDriver(junos.JunOSDriver):
    """Patched JunOS Driver."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        optional_args["config_lock"] = False  # to not try lock on open()
        super(self.__class__, self).__init__(
            hostname, username, password, timeout, optional_args
        )

        self.patched_attrs = ["device"]
        self.device = FakeJunOSDevice()

    def is_alive(self):
        return {"is_alive": True}  # always alive during the tests...


class FakeJunOSDevice(BaseTestDouble):
    def __init__(self):
        self.rpc = FakeRPCObject(self)
        self._conn = FakeConnection(self.rpc)
        self.alternative_facts_file = "facts.yml"
        self.ON_JUNOS = True  # necessary for fake devices
        self.default_facts = {
            "domain": None,
            "hostname": "vsrx",
            "ifd_style": "CLASSIC",
            "2RE": False,
            "serialnumber": "beb914a9cca3",
            "fqdn": "vsrx",
            "virtual": True,
            "switch_style": "NONE",
            "version": "12.1X47-D20.7",
            "HOME": "/cf/var/home/vagrant",
            "srx_cluster": False,
            "model": "FIREFLY-PERIMETER",
            "RE0": {
                "status": "Testing",
                "last_reboot_reason": "Router rebooted after a normal shutdown.",
                "model": "FIREFLY-PERIMETER RE",
                "up_time": "1 hour, 13 minutes, 37 seconds",
            },
            "vc_capable": False,
            "personality": "SRX_BRANCH",
        }
        self._uptime = 4380

    @property
    def facts(self):
        # we want to reinitialize it every time to avoid side effects
        self._facts = copy.deepcopy(self.default_facts)
        try:
            alt_facts_filepath = self.find_file(self.alternative_facts_file)
        except IOError:
            self._facts = self.default_facts
            return self._facts
        with open(alt_facts_filepath, "r") as alt_facts:
            self._facts.update(yaml.safe_load(alt_facts))
        return self._facts

    @property
    def uptime(self):
        return self._uptime

    def open(self):
        pass

    def close(self):
        pass

    def bind(*args, **kvargs):
        pass

    def cli(self, command=""):
        filename = "{safe_command}.txt".format(safe_command=self.sanitize_text(command))
        fielpath = self.find_file(filename)
        return self.read_txt_file(fielpath)


class FakeRPCObject:

    """
    Fake RPC caller.
    """

    def __init__(self, device):
        self._device = device

    def __getattr__(self, item):
        self.item = item
        return self

    def response(self, **rpc_args):
        instance = rpc_args.pop("instance", "")

        filename = "{item}{instance}.xml".format(item=self.item, instance=instance)
        filepathpath = self._device.find_file(filename)
        xml_string = self._device.read_txt_file(filepathpath)

        return lxml.etree.fromstring(xml_string)

    def get_config(self, get_cmd=None, filter_xml=None, options={}):

        # get_cmd is an XML tree that requests a specific part of the config
        # E.g.: <configuration><protocols><bgp><group/></bgp></protocols></configuration>

        if get_cmd is not None:
            get_cmd_str = lxml.etree.tostring(get_cmd).decode("utf-8")
            filename = self._device.sanitize_text(get_cmd_str)

        # no get_cmd means it should mock the eznc get_config
        else:
            filename = "get_config__" + "__".join(
                ["{0}_{1}".format(k, v) for k, v in sorted(options.items())]
            )

        filename = "{filename}.xml".format(filename=filename[0:150])
        filepathpath = self._device.find_file(filename)
        xml_string = self._device.read_txt_file(filepathpath)

        return lxml.etree.fromstring(xml_string)

    __call__ = response


class FakeConnectionRPCObject:

    """
    Will make fake RPC requests that usually are directly made via netconf.
    """

    def __init__(self, rpc):
        self._rpc = rpc

    def response(self, non_std_command=None):
        class RPCReply:
            def __init__(self, reply):
                self._NCElement__doc = reply

        rpc_reply = RPCReply(self._rpc.get_config(get_cmd=non_std_command))
        return rpc_reply

    __call__ = response


class FakeConnection:
    def __init__(self, rpc):
        self.rpc = FakeConnectionRPCObject(rpc)
        self._session = FakeSession()


class FakeSession:
    def __init__(self):
        self.transport = FakeTransport()


class FakeTransport:
    def set_keepalive(self, keepalive):
        self.keepalive = keepalive
