# -*- coding: UTF-8 -*-

from posixpath import join as pjoin

from rosapi.exceptions import TrapError, MultiTrapError


class Parser:

    api_mapping = {'yes': True, 'true': True, 'no': False, 'false': False}

    @staticmethod
    def apiCast(value):
        '''
        Cast value from API to python.

        :returns: Python equivalent.
        '''
        try:
            casted = int(value)
        except ValueError:
            casted = Parser.api_mapping.get(value, value)
        return casted

    @staticmethod
    def parseWord(word):
        '''
        Split given attribute word to key, value pair.
        Values are casted to python equivalents.

        :param word: API word.
        :returns: Key, value pair.
        '''
        _, key, value = word.split('=', 2)
        value = Parser.apiCast(value)
        return (key, value)


class Composer:

    python_mapping = {True: 'yes', False: 'no'}

    @staticmethod
    def pythonCast(value):
        '''
        Cast value from python to API.

        :returns: Casted to API equivalent.
        '''

        # this is necesary because 1 == True, 0 == False
        if type(value) == int:
            return str(value)
        else:
            return Composer.python_mapping.get(value, str(value))

    @staticmethod
    def composeWord(key, value):
        '''
        Create a attribute word from key, value pair.
        Values are casted to api equivalents.
        '''
        return '={}={}'.format(key, Composer.pythonCast(value))


class Api(Composer, Parser):

    def __init__(self, protocol):
        self.protocol = protocol

    def __call__(self, cmd, **kwargs):
        '''
        Call Api with given command.

        :param cmd: Command word. eg. /ip/address/print
        :param kwargs: Dictionary with optional arguments.
        '''
        words = tuple(self.composeWord(key, value) for key, value in kwargs.items())
        self.protocol.writeSentence(cmd, *words)
        return self._readResponse()

    def _readSentence(self):
        '''
        Read one sentence and parse words.

        :returns: Reply word, dict with attribute words.
        '''
        reply_word, words = self.protocol.readSentence()
        words = dict(self.parseWord(word) for word in words)
        return reply_word, words

    def _readResponse(self):
        '''
        Read untill !done is received.

        :throws TrapError: If one !trap is received.
        :throws MultiTrapError: If > 1 !trap is received.
        :returns: Full response
        '''
        response = []
        reply_word = None
        while reply_word != '!done':
            reply_word, words = self._readSentence()
            response.append((reply_word, words))

        self._trapCheck(response)
        # Remove empty sentences
        return tuple(words for reply_word, words in response if words)

    def close(self):
        self.protocol.close()

    @staticmethod
    def _trapCheck(response):
        traps = tuple(words for reply_word, words in response if reply_word == '!trap')
        if len(traps) > 1:
            traps = tuple(
                    TrapError(message=trap['message'], category=trap.get('category'))
                    for trap in traps
                    )
            raise MultiTrapError(*traps)
        elif len(traps) == 1:
            trap = traps[0]
            raise TrapError(message=trap['message'], category=trap.get('category'))

    @staticmethod
    def joinPath(*path):
        '''
        Join two or more paths forming a command word.
        >>> api.joinPath('/ip', 'address', 'print')
        >>> '/ip/address/print'
        '''
        return pjoin('/', *path).rstrip('/')
