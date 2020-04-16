"""Test fixtures."""
import pytest
from lxml import etree
from napalm.base.test import conftest as parent_conftest

from napalm.base.test.double import BaseTestDouble

from napalm.iosxr_netconf import iosxr_netconf


@pytest.fixture(scope="class")
def set_device_parameters(request):
    """Set up the class."""

    def fin():
        request.cls.device.close()

    request.addfinalizer(fin)

    request.cls.driver = iosxr_netconf.IOSXRNETCONFDriver
    request.cls.patched_driver = PatchedIOSXRNETCONFDriver
    request.cls.vendor = "iosxr_netconf"
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedIOSXRNETCONFDriver(iosxr_netconf.IOSXRNETCONFDriver):
    """Patched IOSXR NETCONF Driver."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):

        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ["device"]
        self.device = FakeIOSXRNETCONFDevice()

    def is_alive(self):
        return {"is_alive": True}  # In testing everything works..

    def open(self):
        pass


class FakeIOSXRNETCONFDevice(BaseTestDouble):
    """IOSXR NETCONF device test double."""

    @property
    def server_capabilities(self):
        """Return mocked server capabilities for the current testcase."""
        ns = {'nc': 'urn:ietf:params:xml:ns:netconf:base:1.0'}
        server_capabilities = []
        try:
            full_path = self.find_file("server_capabilities.xml")
        except IOError:
            full_path = None
        if full_path is not None:
            server_capabilities_str = self.read_txt_file(full_path)
            server_capabilities_etree = etree.fromstring(server_capabilities_str)
            for capability in server_capabilities_etree.xpath(
                    ".//nc:capabilities/nc:capability", namespaces=ns):
                server_capabilities.append(capability.text)
        return iter(server_capabilities)

    def close_session(self):
        pass

    def find_mocked_data_file(self, rpc_req_ele):
        """Find mocked XML file for the current testcase."""
        filename = "{}{}.xml".format(self.current_test[5:], rpc_req_ele)
        full_path = self.find_file(filename)
        data = self.read_txt_file(full_path)
        return data

    def dispatch(self, rpc_command, source=None, filter=None):
        rpc_req_ele = ""
        for child in rpc_command[0]:
            rpc_req_ele += "__" + child.tag.split("}")[1]
        return FakeRPCReply(self.find_mocked_data_file(rpc_req_ele))

    def get(self, filter=None):
        rpc_req_ele = "__" + etree.fromstring(filter[1]).tag.split("}")[1]
        return FakeRPCReply(self.find_mocked_data_file(rpc_req_ele))

    def get_config(self, source, filter=None):
        rpc_req_ele = "__" + etree.fromstring(filter[1]).tag.split("}")[1]
        return FakeRPCReply(self.find_mocked_data_file(rpc_req_ele))


class FakeRPCReply:
    """Fake RPC Reply."""

    def __init__(self, raw):
        self._raw = raw

    @property
    def xml(self):
        return self._raw
