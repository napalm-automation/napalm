# -*- coding: UTF-8 -*-

import pytest
from socket import SHUT_RDWR, error as SOCKET_ERROR, timeout as SOCKET_TIMEOUT, socket
from mock import MagicMock, patch

from rosapi import connections
from rosapi.exceptions import ConnectionError, FatalError


class Test_Decoder:

    @pytest.mark.parametrize("length,expected", (
        (b'x', 0),  # 120
        (b'\xbf', 1),  # 191
        (b'\xdf', 2),  # 223
        (b'\xef', 3),  # 239
        ))
    def test_determineLength(self, length, expected):
        assert connections.Decoder.determineLength(length) == expected

    def test_determineLength_raises(self, bad_first_length_bytes):
        with pytest.raises(ConnectionError) as error:
            connections.Decoder.determineLength(bad_first_length_bytes)
        assert str(bad_first_length_bytes) in str(error.value)

    def test_decodeLength(self, valid_word_length):
        result = connections.Decoder.decodeLength(valid_word_length.encoded)
        assert result == valid_word_length.integer

    def test_decodeLength_raises(self, bad_length_bytes):
        with pytest.raises(ConnectionError) as error:
            connections.Decoder.decodeLength(bad_length_bytes)
        assert str(bad_length_bytes) in str(error.value)

    def test_decodeSentence(self):
        sentence = b'\x11/ip/address/print\x05first\x06second'
        expected = ('/ip/address/print', 'first', 'second')
        assert connections.Decoder.decodeSentence(sentence) == expected

    def test_decodeSentence_non_ASCII(self):
        '''Word may only contain ASCII characters.'''
        sentence = b'\x11/ip/addres\xc5\x82/print\x05first\x06second'
        with pytest.raises(UnicodeDecodeError):
            connections.Decoder.decodeSentence(sentence)


class Test_Encoder:

    def test_encodeLength(self, valid_word_length):
        result = connections.Encoder.encodeLength(valid_word_length.integer)
        assert result == valid_word_length.encoded

    def test_encodeLength_raises_if_lenghth_is_too_big(self, bad_length_int):
        with pytest.raises(ConnectionError) as error:
            connections.Encoder.encodeLength(bad_length_int)
        assert str(bad_length_int) in str(error.value)

    @patch.object(connections.Encoder, 'encodeLength', return_value=b'len_')
    def test_encodeWord(self, encodeLength_mock):
        assert connections.Encoder.encodeWord('word') == b'len_word'
        assert encodeLength_mock.call_count == 1

    def test_non_ASCII_word_encoding(self):
        '''Word may only contain ASCII characters.'''
        with pytest.raises(UnicodeEncodeError):
            connections.Encoder.encodeWord(u'łą')

    @patch.object(connections.Encoder, 'encodeWord', return_value=b'')
    def test_encodeSentence(self, encodeWord_mock):
        '''
        Assert that:
            \x00 is appended to the sentence
            encodeWord is called == len(sentence)
        '''
        encoded = connections.Encoder.encodeSentence('first', 'second')
        assert encodeWord_mock.call_count == 2
        assert encoded[-1:] == b'\x00'


class Test_ApiProtocol:

    def setup(self):
        self.protocol = connections.ApiProtocol(
                transport=MagicMock(spec=connections.SocketTransport)
                )

    @patch.object(connections.Encoder, 'encodeSentence')
    def test_writeSentence_calls_encodeSentence(self, encodeSentence_mock):
        self.protocol.writeSentence('/ip/address/print', '=key=value')
        encodeSentence_mock.assert_called_once_with('/ip/address/print', '=key=value')

    @patch.object(connections.Encoder, 'encodeSentence')
    def test_writeSentence_calls_transport_write(self, encodeSentence_mock):
        '''Assert that write is called with encoded sentence.'''
        self.protocol.writeSentence('/ip/address/print', '=key=value')
        self.protocol.transport.write.assert_called_once_with(encodeSentence_mock.return_value)

    @patch.object(connections.ApiProtocol, 'decodeSentence', return_value=('!fatal', 'reason'))
    def test_readSentence_raises_FatalError(self, decodeSentence_mock):
        '''Assert that FatalError is raised with its reason.'''
        self.protocol.read_buffer = b'!fatal\x00'
        with pytest.raises(FatalError) as error:
            self.protocol.readSentence()
        assert str(error.value) == 'reason'
        assert self.protocol.transport.close.call_count == 1

    @patch.object(connections.ApiProtocol, 'decodeSentence')
    def test_readSentence_calls_decodeSentence(self, decodeSentence_mock):
        '''Assert that decodeSentence is called without ending \x00.'''
        self.protocol.read_buffer = b'!fatal\x00'
        self.protocol.readSentence()
        decodeSentence_mock.assert_called_once_with(b'!fatal')

    @patch.object(connections.ApiProtocol, 'decodeSentence')
    def test_readSentence_does_not_call_transport_read(self, decodeSentence_mock):
        '''Assert that transport.read is not called when \x00 is present in buffer.'''
        self.protocol.read_buffer = b'!fatal\x00'
        self.protocol.readSentence()
        assert self.protocol.transport.read.call_count == 0

    @pytest.mark.parametrize('side_effect', (
        [b'reply_word\x00'],
        [b'reply_word', b'another_word\x00'],
        [b'reply_word', b'another_word', b'\x00'],
        ))
    @patch.object(connections.ApiProtocol, 'decodeSentence')
    def test_readSentence_calls_transport_read(self, decodeSentence_mock, side_effect):
        '''Assert that transport.read is called untill \x00 is present in buffer.'''
        self.protocol.transport.read.side_effect = side_effect
        self.protocol.readSentence()
        assert self.protocol.transport.read.call_count == len(side_effect)

    def test_close(self):
        self.protocol.close()
        self.protocol.transport.close.assert_called_once_with()


class Test_SocketTransport:

    def setup(self):
        self.transport = connections.SocketTransport(sock=MagicMock(spec=socket))

    def test_calls_shutdown(self):
        self.transport.close()
        self.transport.sock.shutdown.assert_called_once_with(SHUT_RDWR)

    def test_close_shutdown_exception(self):
        self.transport.sock.shutdown.side_effect = SOCKET_ERROR
        self.transport.close()
        self.transport.sock.close.assert_called_once_with()

    def test_close(self):
        self.transport.close()
        self.transport.sock.close.assert_called_once_with()

    def test_calls_sendall(self):
        self.transport.write(b'some message')
        self.transport.sock.sendall.assert_called_once_with(b'some message')

    @pytest.mark.parametrize("exception", (SOCKET_ERROR, SOCKET_TIMEOUT))
    def test_write_raises_socket_errors(self, exception):
        self.transport.sock.sendall.side_effect = exception
        with pytest.raises(ConnectionError):
            self.transport.write(b'some data')

    @pytest.mark.parametrize('length', (0, 3))
    def test_read_raises_when_recv_returns_empty_byte_string(self, length):
        self.transport.sock.recv.return_value = b''
        with pytest.raises(ConnectionError):
            self.transport.read(length)

    def test_read_returns_from_recv(self):
        self.transport.sock.recv.return_value = b'returned'
        assert self.transport.read(1024) == b'returned'

    @pytest.mark.parametrize("exception", (SOCKET_ERROR, SOCKET_TIMEOUT))
    def test_recv_raises_socket_errors(self, exception):
        self.transport.sock.recv.side_effect = exception
        with pytest.raises(ConnectionError):
            self.transport.read(2)
