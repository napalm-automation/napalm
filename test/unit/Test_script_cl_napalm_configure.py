import unittest
from napalm import get_network_driver
from napalm.clitools import cl_napalm_configure as script


class Test_script_cl_napalm_configure(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.hostname = '192.168.56.201'
        cls.username = 'vagrant'
        cls.password = 'vagrant'
        cls.vendor = 'eos'
        cls.__restore_initial_config(cls.vendor, cls.hostname, cls.username, cls.password)

    @staticmethod
    def __restore_initial_config(vendor, hostname, username, password):
        initial_config = '{}/initial.conf'.format(vendor)

        driver = get_network_driver(vendor)
        device = driver(hostname, username, password, timeout=60)
        device.open()
        device.load_replace_candidate(filename=initial_config)
        device.commit_config()
        device.close()

    def test_dry_run(self):
        strategy = 'merge'
        config_file = '{}/merge_good.conf'.format(self.vendor)
        dry_run = True

        o_result = script.run(self.vendor, self.hostname, self.username, self.password, strategy, config_file, dry_run)
        not_empty_result = len(o_result)
        n_result = script.run(self.vendor, self.hostname, self.username, self.password, strategy, config_file, dry_run)

        self.assertTrue(o_result == n_result and not_empty_result)

    def test_merge_config(self):
        strategy = 'merge'
        config_file = '{}/merge_good.conf'.format(self.vendor)
        dry_run = False

        o_result = script.run(self.vendor, self.hostname, self.username, self.password, strategy, config_file, dry_run)
        not_empty_result = len(o_result)
        n_result = script.run(self.vendor, self.hostname, self.username, self.password, strategy, config_file, dry_run)

        # Go back to initial config
        self.__restore_initial_config(self.vendor, self.hostname, self.username, self.password)
        self.assertTrue(o_result != n_result and not_empty_result)

    def test_replace_config(self):
        strategy = 'replace'
        config_file = '{}/new_good.conf'.format(self.vendor)
        dry_run = False

        o_result = script.run(self.vendor, self.hostname, self.username, self.password, strategy, config_file, dry_run)
        not_empty_result = len(o_result)
        n_result = script.run(self.vendor, self.hostname, self.username, self.password, strategy, config_file, dry_run)

        # Go back to initial config
        self.__restore_initial_config(self.vendor, self.hostname, self.username, self.password)
        self.assertTrue(o_result != n_result and not_empty_result)
