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

# Python3 support
from __future__ import print_function
from __future__ import unicode_literals


class ModuleImportError(Exception):
    pass


class ConnectionException(Exception):
    '''
    Unable to connect to the network device.
    '''
    pass


class ConnectAuthError(ConnectionException):
    '''
    Unable to connect to the network device
    due to invalid credentials.
    '''
    pass


class ConnectTimeoutError(ConnectionException):
    '''
    Exception raised when the connection to the
    network device takes too long.
    This may be avoided by adjusting the `timeout`
    argument.
    '''
    pass


class ConnectionClosedException(ConnectionException):
    '''
    The network device closed the connection.
    Raised whenever we try to execute a certain
    function, but we detect that the connection
    is not usable anymore. This can happen for
    various reasons: the network device terminates the
    session or it is dropped by a firewall or
    the server.
    '''
    pass


class ReplaceConfigException(Exception):
    pass


class MergeConfigException(Exception):
    pass


class CommitError(Exception):
    '''
    Raised when unable to commit the candidate config
    into the running config.
    '''
    pass


class LockError(Exception):
    '''
    Unable to lock the candidate config.
    '''
    pass


class UnlockError(Exception):
    '''
    Unable to unlock the candidate config.
    '''
    pass


class SessionLockedException(Exception):
    pass


class CommandTimeoutException(Exception):
    pass


class CommandErrorException(Exception):
    pass


class DriverTemplateNotImplemented(Exception):
    pass


class TemplateNotImplemented(Exception):
    pass


class TemplateRenderException(Exception):
    pass


class ValidationException(Exception):
    pass
