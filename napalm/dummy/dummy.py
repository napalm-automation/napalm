# -*- coding: utf-8 -*-
# Copyright 2018 NAPALM Automation. All rights reserved.
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

'''
NAPALM Driver for DOS (Dummy Operating System).
'''

from __future__ import unicode_literals

# Python stdlib
import os
import copy
import json
import difflib

# Import local modules
from napalm.base import NetworkDriver


class _DummyDriverMeta(type):
    '''
    Metclass for the DummyDriver.
    '''
    def __new__(cls, name, bases, dct):
        curdir = os.path.dirname(os.path.realpath(__file__))
        for subdir_name in os.listdir(curdir):
            meth = str(subdir_name.replace('test_', '', 1))
            if meth in dct:
                # Skip if method is already defined
                continue
            subdir_path = os.path.join(curdir, subdir_name)
            if not os.path.isdir(subdir_path):
                continue
            meth_ret_file = os.path.join(subdir_path, 'normal', 'expected_result.json')
            if not os.path.isfile(meth_ret_file):
                # Skip if expected_result.json doesn't exist
                continue
            with open(meth_ret_file, 'r') as fh_:
                expected_result_json = fh_.read()

            def _meth_ret(cls, *args, **kwargs):
                return copy.deepcopy(json.loads(expected_result_json))
            dct[meth] = _meth_ret
        return type.__new__(cls, name, bases, dct)


class DummyDriver(NetworkDriver):
    '''
    Dummy network driver class, that doesn't actually return anything useful,
    but just returns some data from the tests (the tests will surely pass).
    '''

    __metaclass__ = _DummyDriverMeta

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        '''
        Initialise the dummy driver.
        '''
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.optional_args = optional_args
        self.profile = ['dummy']
        self.running_config = '''
set system ntp beer 1.2.3.4
router 1234
  neighbour 5.6.7.8
'''
        self.candiate_config = self.running_config

    def open(self):
        '''
        Let's imagine we're opening a connection.
        '''
        self.device = None
        return

    def close(self):
        '''
        Let's imagine now that we're also closing it.
        '''
        return

    def is_alive(self):
        '''
        Always up, always on. Guaranteed.
        '''
        return {
            'is_alive': True
        }

    def load_replace_candidate(self, filename=None, config=None):
        '''
        Replace the entire config. All of it.
        '''
        if filename:
            with open(filename) as fh_:
                config = fh_.read()
        self.candiate_config = config

    def load_merge_candidate(self, filename=None, config=None):
        '''
        This one just a little bit.
        '''
        if filename:
            with open(filename) as fh_:
                config = fh_.read()
        self.candiate_config += config

    def compare_config(self):
        '''
        Not much to compare, but let's return something though.
        '''
        return difflib.unified_diff(self.candiate_config, self.running_config)

    def commit_config(self, message=''):
        '''
        Commit the config change.
        '''
        self.running_config = self.candiate_config

    def discard_config(self):
        '''
        I think I changed my mind.
        '''
        self.candiate_config = self.running_config

    def rollback(self):
        '''
        Nope, it b0rked.
        '''
        self.candiate_config = self.running_config

    def get_config(self, retrieve='all'):
        '''
        Return the config(s).
        '''
        return {
            'running': self.running_config,
            'startup': self.running_config,
            'candidate': self.candiate_config
        }

    def cli(self, commands):
        '''
        Execute a couple of commands on the CLI.
        '''
        return {cmd: 'Output for "{}"'.format(cmd) for cmd in commands}
