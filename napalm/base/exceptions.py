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


class NapalmException(Exception):
    """
    Base Exception Class.
    """

    pass


class ModuleImportError(NapalmException):
    pass


class ConnectionException(NapalmException):
    """
    Unable to connect to the network device.
    """

    pass


class ConnectAuthError(ConnectionException):
    """
    Unable to connect to the network device
    due to invalid credentials.
    """

    pass


class ConnectTimeoutError(ConnectionException):
    """
    Exception raised when the connection to the
    network device takes too long.
    This may be avoided by adjusting the `timeout`
    argument.
    """

    pass


class ConnectionClosedException(ConnectionException):
    """
    The network device closed the connection.
    Raised whenever we try to execute a certain
    function, but we detect that the connection
    is not usable anymore. This can happen for
    various reasons: the network device terminates the
    session or it is dropped by a firewall or
    the server.
    """

    pass


class ReplaceConfigException(NapalmException):
    pass


class MergeConfigException(NapalmException):
    pass


class CommitError(NapalmException):
    """
    Raised when unable to commit the candidate config
    into the running config.
    """

    pass


class LockError(NapalmException):
    """
    Unable to lock the candidate config.
    """

    pass


class UnlockError(NapalmException):
    """
    Unable to unlock the candidate config.
    """

    pass


class SessionLockedException(NapalmException):
    pass


class CommandTimeoutException(NapalmException):
    pass


class CommandErrorException(NapalmException):
    pass


class DriverTemplateNotImplemented(NapalmException):
    pass


class TemplateNotImplemented(NapalmException):
    pass


class TemplateRenderException(NapalmException):
    pass


class ValidationException(NapalmException):
    pass
