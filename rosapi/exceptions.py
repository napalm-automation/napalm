# -*- coding: UTF-8 -*-


class LibError(Exception):
    '''
    This is a base exception for all other.
    '''


class LoginError(LibError):
    '''
    Login attempt errors.
    '''


class ConnectionError(LibError):
    '''
    Connection related errors.
    '''


class FatalError(LibError):
    '''
    Exception raised when !fatal is received.
    '''


class TrapError(LibError):
    '''
    Exception raised when !trap is received.

    :param int category: Optional integer representing category.
    :param str message: Error message.
    '''

    def __init__(self, message, category=None):
        self.category = category
        self.message = message

    def __str__(self):
        return str(self.message.replace('\r\n', ','))

    def __repr__(self):
        return '{}({!r})'.format(self.__class__.__name__, str(self))


class MultiTrapError(LibError):
    '''
    Exception raised when multiple !trap words have been received in one response.

    :param traps: TrapError instances.
    '''

    def __init__(self, *traps):
        self.traps = traps

    def __str__(self):
        return ', '.join(str(trap) for trap in self.traps)
