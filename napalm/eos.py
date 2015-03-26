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

from pyEOS import EOS
from pyEOS.exceptions import CommandError, ConfigReplaceError

from base import NetworkDriver

from exceptions import MergeConfigException, ReplaceConfigException


class EOSDriver(NetworkDriver):

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.device = EOS(hostname, username, password, use_ssl=True)
        self.config_replace = False
        self.candidate_configuration = list()

    def open(self):
        self.device.open()

    def close(self):
        self.device.close()

    def load_replace_candidate(self, filename=None, config=None):
        self.config_replace = True
        self.device.load_candidate_config(filename=filename, config=config)

    def load_merge_candidate(self, filename=None, config=None):
        self.config_replace = False

        if filename is None:
            self.candidate_configuration = config
        else:
            with open(filename) as f:
                self.candidate_configuration = f.read()

        self.candidate_configuration = self.candidate_configuration.split('\n')
        if 'configure' is not self.candidate_configuration[0]:
           self.candidate_configuration.insert(0, 'configure')
        if 'end' is not self.candidate_configuration[-1]:
           self.candidate_configuration.append('end')

        # If you send empty commands the whole thing breaks so we have to remove them
        i = 0
        for line in self.candidate_configuration:
            if line == '':
                self.candidate_configuration.pop(i)
            i += 1

    def compare_config(self):
        if self.config_replace:
            return self.device.compare_config()
        else:
            return '\n'.join(self.candidate_configuration)

    def _commit_replace(self):
        try:
            self.device.replace_config()
        except ConfigReplaceError as e:
            raise ReplaceConfigException(e.message)

    def _commit_merge(self):
        # We load the original config so we can rollback if something goes bad
        self.device.original_config = self.device.get_config(format='text')
        try:
            self.device.run_commands(self.candidate_configuration)
        except CommandError as e:
            self.rollback()
            raise MergeConfigException(e.message)

    def commit_config(self):
        if self.config_replace:
            self._commit_replace()
        else:
            self._commit_merge()

        self.device.run_commands(['write memory'])

    def discard_config(self):
        self.device.load_candidate_config(config=self.device.get_config(format='text'))

    def rollback(self):
        self.device.rollback()
        self.device.run_commands(['write memory'])
        self.device.load_candidate_config(config=self.device.get_config(format='text'))
