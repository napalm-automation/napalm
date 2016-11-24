# -*- coding: UTF-8 -*-

from socket import create_connection, error as SOCKET_ERROR, timeout as SOCKET_TIMEOUT
from binascii import unhexlify, hexlify
from hashlib import md5
try:
    from collections import ChainMap
except:
    from chainmap import ChainMap

from rosapi.exceptions import TrapError, FatalError, ConnectionError, MultiTrapError
from rosapi.connections import ApiProtocol, SocketTransport
from rosapi.api import Api


defaults = {
            'timeout': 10,
            'port': 8728,
            'saddr': '',
            'subclass': Api,
            }


def connect(host, username, password, **kwargs):
    '''
    Connect and login to routeros device.
    Upon success return a Connection class.

    :param host: Hostname to connecto to. May be ipv4,ipv6,FQDN.
    :param username: Username to login with.
    :param password: Password to login with. Only ASCII characters allowed.
    :param timeout: Socket timeout. Defaults to 10.
    :param port: Destination port to be used. Defaults to 8728.
    :param saddr: Source address to bind to.
    :param subclass: Subclass of Api class. Defaults to Api class from library.
    '''
    arguments = ChainMap(kwargs, defaults)
    transport = create_transport(host, **arguments)
    protocol = ApiProtocol(transport=transport)
    api = arguments['subclass'](protocol=protocol)

    try:
        sentence = api('/login')
        token = sentence[0]['ret']
        encoded = encode_password(token, password)
        api('/login', **{'name': username, 'response': encoded})
    except (ConnectionError, TrapError, FatalError, MultiTrapError):
        transport.close()
        raise

    return api


def create_transport(host, **kwargs):
    try:
        sock = create_connection((host, kwargs['port']), kwargs['timeout'], (kwargs['saddr'], 0))
    except (SOCKET_ERROR, SOCKET_TIMEOUT) as error:
        raise ConnectionError(error)
    return SocketTransport(sock=sock)


def encode_password(token, password):

    token = token.encode('ascii', 'strict')
    token = unhexlify(token)
    password = password.encode('ascii', 'strict')
    md = md5()
    md.update(b'\x00' + password + token)
    password = hexlify(md.digest())
    return '00' + password.decode('ascii', 'strict')
