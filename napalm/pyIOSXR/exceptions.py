#!/usr/bin/env python
# coding=utf-8
# Copyright 2015 Netflix. All rights reserved.
# Copyright 2016 BigWaveIT. All rights reserved.
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

"""
Forked from https://github.com/fooelisa/pyiosxr 2019-10-27

Contributors fooelisa, mirceaulinic, et all
"""


class IOSXRException(Exception):
    def __init__(self, msg=None, dev=None):

        super(IOSXRException, self).__init__(msg)
        if dev:
            self._xr = dev
            # release the XML agent
            if self._xr._xml_agent_locker.locked():
                self._xr._xml_agent_locker.release()


class ConnectError(IOSXRException):
    """Exception while openning the connection."""

    def __init__(self, msg=None, dev=None):
        super(ConnectError, self).__init__(msg=msg, dev=dev)
        if dev:
            self._xr = dev
            self._xr._xml_agent_alive = False


class CommitError(IOSXRException):

    """Raised when unable to commit. Mostly due to ERROR 0x41866c00"""

    pass


class LockError(IOSXRException):
    """Throw this exception when unable to lock the config DB."""

    pass


class UnlockError(IOSXRException):
    """Throw this exception when unable to unlock the config DB."""

    pass


class CompareConfigError(IOSXRException):
    """Throw this exception when unable to compare config."""

    pass


class UnknownError(IOSXRException):
    """UnknownError Exception."""

    pass


class InvalidInputError(IOSXRException):
    """InvalidInputError Exception."""

    pass


class XMLCLIError(IOSXRException):
    """XMLCLIError Exception."""

    pass


class InvalidXMLResponse(IOSXRException):
    """Raised when unable to process properly the XML reply from the device."""

    pass


class TimeoutError(IOSXRException):
    """TimeoutError Exception."""

    def __init__(self, msg=None, dev=None):
        super(TimeoutError, self).__init__(msg=msg, dev=dev)
        if dev:
            self._xr = dev
            self._xr._xml_agent_alive = False


class EOFError(IOSXRException):
    """EOFError Exception."""

    pass


class IteratorIDError(IOSXRException):
    """IteratorIDError Exception."""

    pass
