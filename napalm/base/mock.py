# Copyright 2017 Dravetech AB. All rights reserved.
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

from napalm.base.base import NetworkDriver
import napalm.base.exceptions

import inspect
import json
import os
import re


from pydoc import locate


def raise_exception(result):
    exc = locate(result["exception"])
    if exc:
        raise exc(*result.get("args", []), **result.get("kwargs", {}))
    else:
        raise TypeError("Couldn't resolve exception {}", result["exception"])


def is_mocked_method(method):
    mocked_methods = []
    if method.startswith("get_") or method in mocked_methods:
        return True
    return False


def mocked_method(path, name, count):
    parent_method = getattr(NetworkDriver, name)
    parent_method_args = inspect.getfullargspec(parent_method)
    modifier = 0 if "self" not in parent_method_args.args else 1

    def _mocked_method(*args, **kwargs):
        # Check len(args)
        if len(args) + len(kwargs) + modifier > len(parent_method_args.args):
            raise TypeError(
                "{}: expected at most {} arguments, got {}".format(
                    name, len(parent_method_args.args), len(args) + modifier
                )
            )

        # Check kwargs
        unexpected = [x for x in kwargs if x not in parent_method_args.args]
        if unexpected:
            raise TypeError(
                "{} got an unexpected keyword argument '{}'".format(name, unexpected[0])
            )
        return mocked_data(path, name, count)

    return _mocked_method


def mocked_data(path, name, count):
    filename = "{}.{}".format(os.path.join(path, name), count)
    try:
        with open(filename) as f:
            result = json.loads(f.read())
    except IOError:
        raise NotImplementedError("You can provide mocked data in {}".format(filename))

    if "exception" in result:
        raise_exception(result)
    else:
        return result


class MockDevice(object):
    def __init__(self, parent, profile):
        self.parent = parent
        self.profile = profile

    def run_commands(self, commands):
        """Mock for EOS"""
        return list(self.parent.cli(commands).values())[0]

    def show(self, command):
        """Mock for nxos"""
        return self.run_commands([command])


class MockDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Supported optional_args:
            * path(str) - path to where the mocked files are located
            * profile(list) - List of profiles to assign
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.path = optional_args.get("path", "")
        self.profile = optional_args.get("profile", [])
        self.fail_on_open = optional_args.get("fail_on_open", False)

        self.opened = False
        self.calls = {}
        self.device = MockDevice(self, self.profile)

        # None no action, True load_merge, False load_replace
        self.merge = None
        self.filename = None
        self.config = None

    def _count_calls(self, name):
        current_count = self.calls.get(name, 0)
        self.calls[name] = current_count + 1
        return self.calls[name]

    def _raise_if_closed(self):
        if not self.opened:
            raise napalm.base.exceptions.ConnectionClosedException("connection closed")

    def open(self):
        if self.fail_on_open:
            raise napalm.base.exceptions.ConnectionException("You told me to do this")
        self.opened = True

    def close(self):
        self.opened = False

    def is_alive(self):
        return {"is_alive": self.opened}

    def cli(self, commands):
        count = self._count_calls("cli")
        result = {}
        regexp = re.compile("[^a-zA-Z0-9]+")
        for i, c in enumerate(commands):
            sanitized = re.sub(regexp, "_", c)
            name = "cli.{}.{}".format(count, sanitized)
            filename = "{}.{}".format(os.path.join(self.path, name), i)
            with open(filename, "r") as f:
                result[c] = f.read()
        return result

    def load_merge_candidate(self, filename=None, config=None):
        count = self._count_calls("load_merge_candidate")
        self._raise_if_closed()
        self.merge = True
        self.filename = filename
        self.config = config
        mocked_data(self.path, "load_merge_candidate", count)

    def load_replace_candidate(self, filename=None, config=None):
        count = self._count_calls("load_replace_candidate")
        self._raise_if_closed()
        self.merge = False
        self.filename = filename
        self.config = config
        mocked_data(self.path, "load_replace_candidate", count)

    def compare_config(self, filename=None, config=None):
        count = self._count_calls("compare_config")
        self._raise_if_closed()
        return mocked_data(self.path, "compare_config", count)["diff"]

    def commit_config(self):
        count = self._count_calls("commit_config")
        self._raise_if_closed()
        self.merge = None
        self.filename = None
        self.config = None
        mocked_data(self.path, "commit_config", count)

    def discard_config(self):
        count = self._count_calls("commit_config")
        self._raise_if_closed()
        self.merge = None
        self.filename = None
        self.config = None
        mocked_data(self.path, "discard_config", count)

    def _rpc(self, get):
        """This one is only useful for junos."""
        return list(self.cli([get]).values())[0]

    def __getattribute__(self, name):
        if is_mocked_method(name):
            self._raise_if_closed()
            count = self._count_calls(name)
            return mocked_method(self.path, name, count)
        else:
            return object.__getattribute__(self, name)
