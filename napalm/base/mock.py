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
from typing import Optional, List, Dict, Union, Any, Callable

from napalm.base.base import NetworkDriver
import napalm.base.exceptions

import inspect
import json
import os
import re


from pydoc import locate

from napalm.base import models


def raise_exception(result):  # type: ignore
    exc = locate(result["exception"])
    if exc:
        raise exc(*result.get("args", []), **result.get("kwargs", {}))
    else:
        raise TypeError("Couldn't resolve exception {}", result["exception"])


def is_mocked_method(method: str) -> bool:
    mocked_methods = ["traceroute", "ping"]
    if method.startswith("get_") or method in mocked_methods:
        return True
    return False


def mocked_method(path: str, name: str, count: int) -> Callable:
    parent_method = getattr(NetworkDriver, name)
    parent_method_args = inspect.getfullargspec(parent_method)
    modifier = 0 if "self" not in parent_method_args.args else 1

    def _mocked_method(*args, **kwargs):  # type: ignore
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


def mocked_data(path: str, name: str, count: int) -> Union[Dict, List]:
    filename = "{}.{}".format(os.path.join(path, name), count)
    try:
        with open(filename) as f:
            result = json.loads(f.read())
    except IOError:
        raise NotImplementedError("You can provide mocked data in {}".format(filename))

    if "exception" in result:
        raise_exception(result)
        assert False
    else:
        return result


class MockDevice(object):
    def __init__(self, parent: NetworkDriver, profile: str) -> None:
        self.parent = parent
        self.profile = profile

    def run_commands(self, commands: List[str]) -> str:
        """Mock for EOS"""
        return_value = list(self.parent.cli(commands).values())[0]
        assert isinstance(return_value, str)
        return return_value

    def show(self, command: str) -> str:
        """Mock for nxos"""
        return self.run_commands([command])


class MockDriver(NetworkDriver):
    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        timeout: int = 60,
        optional_args: Optional[Dict] = None,
    ) -> None:
        """
        Supported optional_args:
            * path(str) - path to where the mocked files are located
            * profile(list) - List of profiles to assign
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        if not optional_args:
            optional_args = {}
        self.path = optional_args.get("path", "")
        self.profile = optional_args.get("profile", [])
        self.fail_on_open = optional_args.get("fail_on_open", False)

        self.opened = False
        self.calls: Dict[str, int] = {}
        self.device = MockDevice(self, self.profile)

        # None no action, True load_merge, False load_replace
        self.merge: Optional[bool] = None
        self.filename: Optional[str] = None
        self.config: Optional[str] = None
        self._pending_commits = False

    def _count_calls(self, name: str) -> int:
        current_count = self.calls.get(name, 0)
        self.calls[name] = current_count + 1
        return self.calls[name]

    def _raise_if_closed(self) -> None:
        if not self.opened:
            raise napalm.base.exceptions.ConnectionClosedException("connection closed")

    def open(self) -> None:
        if self.fail_on_open:
            raise napalm.base.exceptions.ConnectionException("You told me to do this")
        self.opened = True

    def close(self) -> None:
        self.opened = False

    def is_alive(self) -> models.AliveDict:
        return {"is_alive": self.opened}

    def cli(
        self, commands: List[str], encoding: str = "text"
    ) -> Dict[str, Union[str, Dict[str, Any]]]:
        count = self._count_calls("cli")
        result = {}
        regexp = re.compile("[^a-zA-Z0-9]+")
        for i, c in enumerate(commands):
            sanitized = re.sub(regexp, "_", c)
            name = "cli.{}.{}".format(count, sanitized)
            filename = "{}.{}".format(os.path.join(self.path, name), i)
            with open(filename, "r") as f:
                result[c] = f.read()
        return result  # type: ignore

    def load_merge_candidate(
        self, filename: Optional[str] = None, config: Optional[str] = None
    ) -> None:
        count = self._count_calls("load_merge_candidate")
        self._raise_if_closed()
        self.merge = True
        self.filename = filename
        self.config = config
        mocked_data(self.path, "load_merge_candidate", count)

    def load_replace_candidate(
        self, filename: Optional[str] = None, config: Optional[str] = None
    ) -> None:
        count = self._count_calls("load_replace_candidate")
        self._raise_if_closed()
        self.merge = False
        self.filename = filename
        self.config = config
        mocked_data(self.path, "load_replace_candidate", count)

    def compare_config(
        self, filename: Optional[str] = None, config: Optional[str] = None
    ) -> str:
        count = self._count_calls("compare_config")
        self._raise_if_closed()
        mocked = mocked_data(self.path, "compare_config", count)
        assert isinstance(mocked, dict)
        return mocked["diff"]

    def commit_config(self, message: str = "", revert_in: Optional[int] = None) -> None:
        count = self._count_calls("commit_config")
        self._raise_if_closed()
        if revert_in is not None:
            if self.has_pending_commit():
                raise napalm.base.exceptions.CommitError(
                    "Pending commit confirm already in process!"
                )
            else:
                self._pending_commits = True
        self.merge = None
        self.filename = None
        self.config = None
        mocked_data(self.path, "commit_config", count)

    def discard_config(self) -> None:
        count = self._count_calls("discard_config")
        self._raise_if_closed()
        self.merge = None
        self.filename = None
        self.config = None
        mocked_data(self.path, "discard_config", count)

    def confirm_commit(self) -> None:
        count = self._count_calls("confirm_commit")
        self._raise_if_closed()
        self.merge = None
        self.filename = None
        self.config = None
        self._pending_commits = False
        mocked_data(self.path, "confirm_commit", count)

    def has_pending_commit(self) -> bool:
        return self._pending_commits

    def rollback(self) -> None:
        self.config_session = None
        self._pending_commits = False

    def _rpc(self, get: str) -> str:
        """This one is only useful for junos."""
        return_value = list(self.cli([get]).values())[0]
        assert isinstance(return_value, str)
        return return_value

    def __getattribute__(self, name: str) -> Callable:
        if is_mocked_method(name):
            self._raise_if_closed()
            count = self._count_calls(name)
            return mocked_method(self.path, name, count)
        else:
            return object.__getattribute__(self, name)
