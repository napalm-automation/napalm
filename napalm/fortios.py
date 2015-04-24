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

from pyFG.fortios import FortiOS, FortiConfig
from pyFG.exceptions import FailedCommit, CommandExecutionException

from base import NetworkDriver
from exceptions import ReplaceConfigException, MergeConfigException


class FortiOSDriver(NetworkDriver):

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.device = FortiOS(hostname, username=username, password=password)
        self.config_replace = False

    def open(self):
        self.device.open()

    def close(self):
        self.device.close()

    def _load_config(self, filename, config):
        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()

        self.device.load_config(in_candidate=True, config_text=configuration)

    def load_replace_candidate(self, filename=None, config=None):
        self.config_replace = True

        self.device.candidate_config = FortiConfig('candidate')
        self.device.running_config = FortiConfig('running')

        self._load_config(filename, config)

        self.device.load_config(empty_candidate=True)

    def load_merge_candidate(self, filename=None, config=None):
        self.config_replace = False

        self.device.candidate_config = FortiConfig('candidate')
        self.device.running_config = FortiConfig('running')

        self._load_config(filename, config)

        for block in self.device.candidate_config.get_block_names():
            try:
                self.device.load_config(path=block, empty_candidate=True)
            except CommandExecutionException as e:
                raise MergeConfigException(e.message)

    def compare_config(self):
        return self.device.compare_config()

    def commit_config(self):
        try:
            self.device.execute_command('execute backup config flash commit_with_napalm')
            self.device.commit()
            self.discard_config()
        except FailedCommit as e:
            if self.config_replace:
                raise ReplaceConfigException(e.message)
            else:
                raise MergeConfigException(e.message)

    def discard_config(self):
        self.device.candidate_config = FortiConfig('candidate')
        self.device.load_config(in_candidate=True)

    def rollback(self):
        output = self.device.execute_command('fnsysctl ls -l data2/config')
        rollback_file = output[-2].split()[-1]
        rollback_config = self.device.execute_command('fnsysctl cat data2/config/%s' % rollback_file)

        self.device.load_config(empty_candidate=True)
        self.load_replace_candidate(config=rollback_config)
        self.device.candidate_config['vpn certificate local']['Fortinet_CA_SSLProxy'].del_param('private-key')
        self.device.candidate_config['vpn certificate local']['Fortinet_CA_SSLProxy'].del_param('certificate')
        self.device.candidate_config['vpn certificate local']['Fortinet_SSLProxy'].del_param('private-key')
        self.device.candidate_config['vpn certificate local']['Fortinet_SSLProxy'].del_param('certificate')
        self.device.commit()