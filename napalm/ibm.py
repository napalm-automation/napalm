#
# Copyright 2015 Kamil Derynski, Opera Software ASA
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

from base import NetworkDriver
from exceptions import ReplaceConfigException, MergeConfigException
from bnclient import bnclient
import difflib
import sys
from StringIO import StringIO


class IBMDriver(NetworkDriver):

    def __init__(self, hostname, username, password, timeout=60):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.argv = ['', '-u', username, '-p', password, hostname]
        self.bnc = bnclient.bnclient(self.argv)
        self.config_replace = False
        self.config = {"running": "", "candidate": "", "rollback": ""}
        self.filename_running = "/tmp/" + hostname + "-running.conf"
        self.filename_candidate = None
        self.filename_rollback = "/tmp/" + hostname + "-rollback.conf"
        self.error = StringIO()

    def str2argv(self, str=''):
        return str.split(' ')

    def open(self):
        self.bnc.connect(self.timeout)
        self.bnc.sendhello()
        self._get_config(self.filename_rollback)

    def close(self):
        self.bnc.close()

    def _bnc_cmd(self, file, operation, error_option):
        cmd = "-o edit-config -t running -f "
        cmd += file
        cmd += " -d " + operation
        cmd += " -r " + error_option
        return cmd

    def _write_memory(self):
        cmd = "-o copy-config -t startup -s running"
        return cmd

    def _send_rpc(self, cmd):
        self.error = StringIO()
        old_stdout = sys.stdout
        sys.stdout = self.error
        self.bnc.sendrpc(self.str2argv(cmd))
        sys.stdout = old_stdout

    def _get_config(self, filename):
        self.bnc.sendrpc(self.str2argv("-o get -f " + filename))

    def _load_config(self, filename, config):
        self._get_config(self.filename_rollback)
        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()
                self.config['candidate'] = configuration
                self.filename_candidate = filename
                f.close()

    def load_replace_candidate(self, filename=None, config=None):
        self.config_replace = True
        self._load_config(filename, config)

    def load_merge_candidate(self, filename=None, config=None):
        self.config_replace = False
        self._load_config(filename, config)

    def compare_config(self):
        result = ''
        if self.config_replace:
            self._get_config(self.filename_running)
            with open(self.filename_running, 'r') as running:
                with open(self.filename_candidate, 'r') as candidate:
                    diff = difflib.unified_diff(
                        running.readlines(),
                        candidate.readlines(),
                        fromfile='running',
                        tofile='candidate',
                    )
            for line in diff:
                for prefix in ('---', '+++', '@@'):
                    if line.startswith(prefix):
                        break
                else:
                    result += line
        else:
            result = self.config['candidate']
        return str(result).strip()

    def _commit_replace(self):
        cmd = self._bnc_cmd(self.filename_candidate, "replace", "continue-on-error")
        self._send_rpc(cmd)
        if self.error.getvalue():
            self.rollback()
            raise ReplaceConfigException(self.error.getvalue())

    def _commit_merge(self):
        cmd = self._bnc_cmd(self.filename_candidate, "merge", "rollback-on-error")
        self._send_rpc(cmd)
        if self.error.getvalue():
            self.discard_config()
            raise MergeConfigException(self.error.getvalue())

    def commit_config(self):
        if self.config_replace:
            self._commit_replace()
        else:
            self._commit_merge()
        cmd = self._write_memory()
        self._send_rpc(cmd)

    def discard_config(self):
        self.filename_candidate = self.filename_running
        self.config['candidate'] = self.config['running']

    def rollback(self):
        cmd = self._bnc_cmd(self.filename_rollback, "replace", "rollback-on-error")
        self._send_rpc(cmd)
        cmd = self._write_memory()
        self._send_rpc(cmd)
