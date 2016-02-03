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

from napalm import exceptions
import difflib
import models


class TestConfigNetworkDriver:

    @classmethod
    def tearDownClass(cls):
        cls.device.load_replace_candidate(filename='%s/initial.conf' % cls.vendor)
        cls.device.commit_config()
        cls.device.close()

    @staticmethod
    def read_file(filename):
        with open(filename, 'r') as f:
            return f.read().strip()

    @staticmethod
    def print_diff_strings(orig, new):
        for line in difflib.context_diff(orig.splitlines(), new.splitlines()):
            print line

    def test_replacing_and_committing_config(self):
        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        self.device.commit_config()

        # The diff should be empty as the configuration has been committed already
        diff = self.device.compare_config()

        # Reverting changes
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
        self.device.commit_config()

        self.assertEqual(len(diff), 0)

    def test_replacing_config_with_typo(self):
        result = False
        try:
            self.device.load_replace_candidate(filename='%s/new_typo.conf' % self.vendor)
            self.device.commit_config()
        except exceptions.ReplaceConfigException:
            self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
            diff = self.device.compare_config()
            self.device.discard_config()
            result = True and len(diff) == 0
        self.assertTrue(result)

    def test_replacing_config_and_diff_and_discard(self):
        intended_diff = self.read_file('%s/new_good.diff' % self.vendor)

        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        commit_diff = self.device.compare_config()
        self.device.discard_config()
        discard_diff = self.device.compare_config()
        self.device.discard_config()

        result = (commit_diff == intended_diff) and (discard_diff == '')
        self.assertTrue(result)

    def test_replacing_config_and_rollback(self):
        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        orig_diff = self.device.compare_config()
        self.device.commit_config()

        # Now we rollback changes
        replace_config_diff = self.device.compare_config()
        self.device.rollback()

        # We try to load again the config. If the rollback was successful new diff should be like the first one
        self.device.load_replace_candidate(filename='%s/new_good.conf' % self.vendor)
        last_diff = self.device.compare_config()
        self.device.discard_config()

        result = (orig_diff == last_diff) and ( len(replace_config_diff) == 0 )

        self.assertTrue(result)

    def test_merge_configuration(self):
        intended_diff = self.read_file('%s/merge_good.diff' % self.vendor)

        self.device.load_merge_candidate(filename='%s/merge_good.conf' % self.vendor)
        self.device.commit_config()

        # Reverting changes
        self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
        diff = self.device.compare_config()
        self.device.commit_config()

        self.assertEqual(diff, intended_diff)

    def test_merge_configuration_typo_and_rollback(self):
        result = False
        try:
            self.device.load_merge_candidate(filename='%s/merge_typo.conf' % self.vendor)
            diff = self.device.compare_config()
            self.device.commit_config()
            raise Exception("We shouldn't be here")
        except exceptions.MergeConfigException:
            # We load the original config as candidate. If the commit failed cleanly the compare_config should be empty
            self.device.load_replace_candidate(filename='%s/initial.conf' % self.vendor)
            result = self.device.compare_config() == ''
            self.device.discard_config()

        self.assertTrue(result)


class TestGettersNetworkDriver:
    @staticmethod
    def _test_model(model, data):
        same_keys = set(model.keys()) == set(data.keys())

        if not same_keys:
            print "model_keys: {}\ndata_keys: {}".format(model.keys(), data.keys())

        correct_class = True
        for key, instance_class in model.iteritems():
            same_class = isinstance(data[key], instance_class)
            correct_class = correct_class and same_class

            if not same_class:
                print "key: {}\nmodel_class: {}\ndata_class: {}".format(key, instance_class, data[key].__class__)

        return correct_class and same_keys

    def test_get_facts(self):
        facts = self.device.get_facts()
        result = self._test_model(models.facts, facts)
        self.assertTrue(result)

    def test_get_interfaces(self):
        get_interfaces = self.device.get_interfaces()
        result = len(get_interfaces) > 0

        for interface, interface_data in get_interfaces.iteritems():
            result = result and self._test_model(models.interface, interface_data)

        self.assertTrue(result)

    def test_get_lldp_neighbors(self):
        get_lldp_neighbors = self.device.get_lldp_neighbors()
        result = len(get_lldp_neighbors) > 0

        for interface, neighbor_list in get_lldp_neighbors.iteritems():
            for neighbor in neighbor_list:
                result = result and self._test_model(models.lldp_neighbors, neighbor)

        self.assertTrue(result)

    def test_get_interfaces_counters(self):
        get_interfaces_counters = self.device.get_interfaces_counters()
        result = len(self.device.get_interfaces_counters()) > 0

        for interface, interface_data in get_interfaces_counters.iteritems():
            result = result and self._test_model(models.interface_counters, interface_data)

        self.assertTrue(result)

    def test_get_environment(self):
        environment = self.device.get_environment()
        result = len(environment) > 0

        for fan, fan_data in environment['fans'].iteritems():
            result = result and self._test_model(models.fan, fan_data)

        for power, power_data in environment['power'].iteritems():
            result = result and self._test_model(models.power, power_data)

        for temperature, temperature_data in environment['temperature'].iteritems():
            result = result and self._test_model(models.temperature, temperature_data)

        for cpu, cpu_data in environment['cpu'].iteritems():
            result = result and self._test_model(models.cpu, cpu_data)

        result = result and self._test_model(models.memory, environment['memory'])

        self.assertTrue(result)

    def test_get_bgp_neighbors(self):
        get_bgp_neighbors = self.device.get_bgp_neighbors()
        result = 'global' in get_bgp_neighbors.keys()

        if not result:
            print('global is not part of the returned vrfs')
        else:
            for vrf, vrf_data in get_bgp_neighbors.iteritems():
                result = result and isinstance(vrf_data['router_id'], unicode)
                if not result:
                    print('router_id is not unicode')

                for peer, peer_data in vrf_data['peers'].iteritems():
                    result = result and self._test_model(models.peer, peer_data)

                    for af, af_data in peer_data['address_family'].iteritems():
                        result = result and self._test_model(models.af, af_data)

            self.assertTrue(result)

    def test_get_lldp_neighbors_detail(self):

        get_lldp_neighbors_detail = self.device.get_lldp_neighbors_detail()

        result = len(get_lldp_neighbors_detail) > 0

        for interface, neighbor_list in get_lldp_neighbors.iteritems():
            for neighbor in neighbor_list:
                result = result and self._test_model(models.lldp_neighbors_detail, neighbor)

        self.assertTrue(result)
