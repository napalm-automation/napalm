import pytest
from collections import namedtuple
from struct import pack
from rosapi import Api

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
