"""Test fixtures."""
from builtins import super

from collections import namedtuple

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import datetime

import pytest
from napalm_base.test import conftest as parent_conftest

from napalm_base.test.double import BaseTestDouble

from napalm_ros import ros

from struct import pack
from librouteros import Api


@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = ros.ROSDriver
    request.cls.patched_driver = PatchedROSDevice
    request.cls.vendor = 'ros'
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedROSDevice(ros.ROSDriver):
    """ROS device test double."""
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ['paramiko_transport', 'mikoshell', 'api']

    def open(self):
        self.paramiko_transport = FakeParamikoTransport()
        self.mikoshell = FakeMikoShell()
        self._datetime_offset = datetime.datetime.now() - datetime.datetime.now()
        self.api = FakeApi()


class FakeApi(BaseTestDouble):

    def __call__(self, command, **kwargs):
        full_path = self.find_file(self.sanitize_text(command) + '.json')
        return tuple(self.read_json_file(full_path)['data'])

    def close(self):
        pass


class FakeParamikoTransport(BaseTestDouble):
    def open_session(self):
        return FakeParamikoChannel()

    def close(self):
        pass

    def is_active(self):
        return True


class FakeMikoShell(BaseTestDouble):

    def command(self, command, *args, **kwargs):
        full_path = self.find_file(self.sanitize_text(command))
        return self.read_txt_file(full_path).splitlines()

    def exit(self, cmd):
        pass


class FakeParamikoChannel(BaseTestDouble):

    def close(self):
        pass

    def exec_command(self, command):
        self._exec_command = self.find_file(self.sanitize_text(command))

    def makefile(self, *args):
        return StringIO(self.read_txt_file(self._exec_command))

    @staticmethod
    def set_combine_stderr(*args):
        pass

    @staticmethod
    def shutdown(*args):
        pass


WordLength = namedtuple('WordLength', ('integer', 'encoded'))
TypeCast = namedtuple('TypeCast', ('api', 'python'))
AttributeWord = namedtuple('AttributeWord', ('raw', 'key', 'value'))


@pytest.fixture(scope='function')
def lib_default_kwargs():
    return {
            'timeout': 10,
            'port': 8728,
            'saddr': '',
            'subclass': Api,
            }


@pytest.fixture(scope='function')
def bad_length_bytes():
    '''len(length) must be < 5'''
    return b'\xff\xff\xff\xff\xff'


@pytest.fixture(scope='function')
def bad_length_int():
    '''Length must be < 268435456'''
    return 268435456


@pytest.fixture(scope='function', params=(
        WordLength(integer=0, encoded=b'\x00'),
        WordLength(integer=127, encoded=b'\x7f'),
        WordLength(integer=130, encoded=b'\x80\x82'),
        WordLength(integer=2097140, encoded=b'\xdf\xff\xf4'),
        WordLength(integer=268435440, encoded=b'\xef\xff\xff\xf0'),
        ))
def valid_word_length(request):
    return request.param


@pytest.fixture(scope='function', params=(pack('>B', i) for i in range(240, 256)))
def bad_first_length_bytes(request):
    '''First byte of length must be < 240.'''
    return request.param


@pytest.fixture(params=(
            TypeCast(api='yes', python=True),
            TypeCast(api='no', python=False),
            TypeCast(api='string', python='string'),
            TypeCast(api='none', python='none'),
            TypeCast(api='22.2', python='22.2'),
            TypeCast(api='22', python=22),
            TypeCast(api='0', python=0)
        ))
def bidirectional_type_cast(request):
    '''Values used for casting from/to python/api in both directions.'''
    return request.param


@pytest.fixture(params=(
            TypeCast(api='true', python=True),
            TypeCast(api='false', python=False),
        ))
def from_api_type_cast(request):
    '''Values that are casted from api to pythn.'''
    return request.param


@pytest.fixture(params=(
        AttributeWord(raw='=.id=value', key='.id', value='value'),
        AttributeWord(raw='=name=ether1', key='name', value='ether1'),
        AttributeWord(raw='=comment=', key='comment', value=''),
        ))
def attribute_word(request):
    return request.param
