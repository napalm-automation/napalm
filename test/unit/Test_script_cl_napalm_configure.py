import unittest
from napalm import get_network_driver
from napalm.clitools import cl_napalm_configure as script


class Test_script_cl_napalm_configure(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.hostname = 'localhost'
        cls.username = 'vagrant'
        cls.password = 'vagrant'
        cls.vendor = 'eos'
        cls.optional_args = {'port': 12443}
        cls.optional_args_string = "port=12443, asd=asd"

    def setUp(self):
        initial_config = '{}/initial.conf'.format(self.vendor)

        driver = get_network_driver(self.vendor)
        device = driver(self.hostname, self.username, self.password, timeout=60, optional_args=self.optional_args)
        device.open()
        device.load_replace_candidate(filename=initial_config)
        device.commit_config()
        device.close()

    def test_dry_run(self):
        strategy = 'merge'
        config_file = '{}/merge_good.conf'.format(self.vendor)
        dry_run = True

        o_result = script.run(self.vendor, self.hostname, self.username, self.password, strategy,
                              self.optional_args_string, config_file, dry_run)
        not_empty_result = len(o_result)
        n_result = script.run(self.vendor, self.hostname, self.username, self.password, strategy,
                              self.optional_args_string, config_file, dry_run)

        self.assertTrue(o_result == n_result and not_empty_result)

    def test_merge_config(self):
        strategy = 'merge'
        config_file = '{}/merge_good.conf'.format(self.vendor)
        dry_run = False

        o_result = script.run(self.vendor, self.hostname, self.username, self.password, strategy,
                              self.optional_args_string, config_file, dry_run)
        not_empty_result = len(o_result)
        n_result = script.run(self.vendor, self.hostname, self.username, self.password, strategy,
                              self.optional_args_string, config_file, dry_run)

        self.assertTrue(o_result != n_result and not_empty_result)

    def test_replace_config(self):
        strategy = 'replace'
        config_file = '{}/new_good.conf'.format(self.vendor)
        dry_run = False

        o_result = script.run(self.vendor, self.hostname, self.username, self.password, strategy,
                              self.optional_args_string, config_file, dry_run)
        not_empty_result = len(o_result)
        n_result = script.run(self.vendor, self.hostname, self.username, self.password, strategy,
                              self.optional_args_string, config_file, dry_run)

        self.assertTrue(o_result != n_result and not_empty_result)
