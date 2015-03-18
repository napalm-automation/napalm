# Copyright 2014 Spotify AB. All rights reserved.
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

from pyIOSXR import IOSXR

from base import NetworkDriver


class IOSXRDriver(NetworkDriver):

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.device = IOSXR(hostname, username, password)

    def open(self):
        self.device.open()

    def close(self):
        self.device.close()

    def load_replace_candidate(self, filename=None, config=None):
	self.replace = True
        self.device.load_candidate_config(filename=filename, config=config)

    def load_merge_candidate(self, filename=None, config=None):
        self.device.load_candidate_config(filename=filename, config=config)

    def compare_config(self):
	if self.replace:
            return self.device.compare_replace_config()
	else:
            return self.device.compare_config()

    def commit_config(self):
	if self.replace:
	    self.device.commit_replace_config()
	else:
            self.device.commit_config()

    def discard_config(self):
        self.device.discard_config()

    def rollback(self):
        self.device.rollback()

