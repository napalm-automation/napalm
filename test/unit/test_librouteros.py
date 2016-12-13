# -*- coding: UTF-8 -*-

import pytest
from mock import patch
from socket import error as SOCKET_ERROR, timeout as SOCKET_TIMEOUT

from rosapi import encode_password, create_transport, ConnectionError, defaults


def test_lib_default_arguments(lib_default_kwargs):
    assert lib_default_kwargs == defaults


def test_password_encoding():
    result = encode_password('259e0bc05acd6f46926dc2f809ed1bba', 'test')
    assert result == '00c7fd865183a43a772dde231f6d0bff13'


def test_non_ascii_password_encoding():
    '''Only ascii characters are allowed in password.'''
    with pytest.raises(UnicodeEncodeError):
        encode_password(token='259e0bc05acd6f46926dc2f809ed1bba', password=u'ąć')


@patch('rosapi.create_connection')
def test_create_transport_calls_create_connection(create_conn_mock):
    create_transport('host', timeout=10, port=111, saddr='saddr')
    create_conn_mock.assert_called_once_with(('host', 111), 10, ('saddr', 0))


@pytest.mark.parametrize('exception', (SOCKET_ERROR, SOCKET_TIMEOUT))
@patch('rosapi.create_connection')
def test_create_transport_raises_ConnectionError(create_conn_mock, exception):
    create_conn_mock.side_effect = exception('error message')
    with pytest.raises(ConnectionError) as error:
        create_transport('host', timeout=10, port=111, saddr='saddr')
    assert str(create_conn_mock.side_effect) in str(error.value)


@patch('rosapi.SocketTransport')
@patch('rosapi.create_connection')
def test_create_transport_calls_SocketTransport(create_conn_mock, transport_mock):
    create_transport('host', timeout=10, port=111, saddr='saddr')
    transport_mock.assert_called_once_with(sock=create_conn_mock.return_value)
