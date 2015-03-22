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


class NetworkDriver:
    def __init__(self, hostname, username, password):
        """
        This is the base class you have to inherit from when writing your own Network Driver to manage any device. You
        will, in addition, have to override all the methods specified on this class. Make sure you follow the guidelines
        for every method and that you return the correct data.

        :param hostname: (str) IP or FQDN of the device you want to connect to.
        :param username: (str) Username you want to use
        :param password: (str) Password
        :return:
        """
        raise NotImplementedError

    def open(self):
        """
        Opens a connection to the device.

        :return: None
        """
        raise NotImplementedError

    def close(self):
        """
        Closes the connection to the device.
        :return: None
        """
        raise NotImplementedError

    def load_replace_candidate(self, filename=None, config=None):
        """
        Populates the attribute candidate_config with the desired configuration. You can populate it from a file or
        from a string. If you send both a filename and a string containing the configuration, the file takes precedence.

        :param filename: Path to the file containing the desired configuration. By default is None.
        :param config: String containing the desired configuration.
        """
        raise NotImplementedError

    def load_merge_candidate(self, filename=None, config=None):
        """
        Populates the attribute candidate_config with the desired configuration. You can populate it from a file or
        from a string. If you send both a filename and a string containing the configuration, the file takes precedence.

        :param filename: Path to the file containing the desired configuration. By default is None.
        :param config: String containing the desired configuration.
        """
        raise NotImplementedError

    def compare_config(self):
        """

        :return: A string showing the difference between the running_config and the candidate_config. The running_config is
            loaded automatically just before doing the comparison so there is no need for you to do it.
        """
        raise NotImplementedError

    def commit_config(self):
        """
        Applies the configuration loaded with the method load_candidate_config on the device. Note that the current
        configuration of the device is replaced with the new configuration.
        """
        raise NotImplementedError

    def discard_config(self):
        """
        Discards the configuration loaded into the candidate.
        """
        raise NotImplementedError

    def rollback(self):
        """
        If changes have been made, revert changes to the original state.
        """
        raise NotImplementedError
