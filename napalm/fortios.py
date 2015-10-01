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

from utils.string_parsers import colon_separated_string_to_dict, convert_uptime_string_seconds


def execute_get(device, cmd, separator=':', auto=False):
    output = device.execute_command(cmd)

    if auto:
        if ':' in output[0]:
            separator=':'
        elif '\t' in output[0]:
            separator='\t'
        else:
            raise Exception('Unknown separator for block:\n{}'.format(output))

    return colon_separated_string_to_dict('\n'.join(output), separator)


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

    def get_facts(self):
        system_status = execute_get(self.device, 'get system status')
        performance_status = execute_get(self.device, 'get system performance status')

        interfaces = execute_get(self.device, 'get system interface | grep ==')
        interface_list = [x.split()[2] for x in interfaces.keys()]

        domain = execute_get(self.device, 'get system dns | grep domain')['domain']

        return {
            'vendor': 'Fortigate',
            'os_version': system_status['Version'].split(',')[0].split()[1],
            'uptime': convert_uptime_string_seconds(performance_status['Uptime']),
            'serial_number': system_status['Serial-Number'],
            'model': system_status['Version'].split(',')[0].split()[0],
            'hostname': system_status['Hostname'],
            'fqdn': '{}.{}'.format(system_status['Hostname'], domain),
            'interface_list': interface_list
        }

    @staticmethod
    def _get_tab_separated_interfaces(output):
        interface_statistics = {
            'is_up': ('up' in output['State'] and 'up' or 'down'),
            'speed': output['Speed'],
            'mac_adddress': output['Current_HWaddr']
        }
        return interface_statistics

    @staticmethod
    def _get_unsupported_interfaces():
        return {
            'is_up': None,
            'is_enabled': None,
            'description': None,
            'last_flapped': None,
            'mode': None,
            'speed': None,
            'mac_address': None
        }

    def get_interfaces(self):
        interface_statistics = dict()
        self.device.load_config('system interface')
        for iface in self.get_facts()['interface_list']:
            try:
                hw_output = execute_get(self.device, 'diagnose hardware deviceinfo nic {}'.format(iface), auto=True)
                ifs = self._get_tab_separated_interfaces(hw_output)

                ifs['is_enabled'] = self.device.running_config['system interface'][iface].get_param('status') != 'down'
                ifs['description'] = self.device.running_config['system interface'][iface].get_param('description')
                ifs['last_flapped'] = None
                #ifs['mode'] = 'routed'
                ifs['last_flapped'] = None
                interface_statistics[iface] = ifs
            except CommandExecutionException:
                interface_statistics[iface] = self._get_unsupported_interfaces()

        return interface_statistics

    # def get_bgp_neighbors(self):
    #     bgp_sum = self.device.execute_command('get router info bgp sum')
    #     re_neigh = re.compile("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")
    #     neighbors = {n.split()[0]: n.split()[1:] for n in bgp_sum if re.match(re_neigh, n)}
    #
    #     peers = dict()
    #
    #     self.device.load_config('router bgp')
    #
    #     for neighbor, parameters in neighbors.iteritems():
    #         neigh_conf = self.device.running_config['router bgp']['neighbor']['{}'.format(neighbor)]
    #         peers[neighbor] = dict()
    #         peers[neighbor]['remote_as'] = int(neigh_conf.get_param('remote-as'))
    #         peers[neighbor]['is_enabled'] = neigh_conf.get_param('shutdown') != 'enable' or False
    #         peers[neighbor]['is_up'] = 'never' != parameters[7] or False
    #         peers[neighbor]['uptime'] = convert_uptime_string_seconds(parameters[7])
    #         peers[neighbor]['accepted_prefixes'] = int(self.device.execute_command('get router info bgp neighbor {} | grep "accepted prefixes"'.format(neighbor))[0].split()[0])
    #         peers[neighbor]['sent_prefixes'] = int(self.device.execute_command('get router info bgp neighbor {} | grep "announced prefixes"'.format(neighbor))[0].split()[0])
    #
    #         received = self.device.execute_command('get router info bgp neighbors {} received-routes | grep prefixes'.format(neighbor))[0].split()
    #         if len(received) > 0:
    #             peers[neighbor]['received_prefixes'] = int(received[-1])
    #         else:
    #             # Soft-reconfig is not enabled
    #             peers[neighbor]['received_prefixes'] = 0
    #
    #     return {
    #         'default': {
    #             'local_as': int(bgp_sum[0].split()[7]),
    #             'router_id': bgp_sum[0].split()[3],
    #             'peers': peers
    #         }
    #     }

    def get_lldp_neighbors(self):
        return {}
