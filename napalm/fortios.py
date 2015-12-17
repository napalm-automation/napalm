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
import re
from pyFG.fortios import FortiOS, FortiConfig, logger
from pyFG.exceptions import FailedCommit, CommandExecutionException
from base import NetworkDriver
from exceptions import ReplaceConfigException, MergeConfigException
from napalm.utils.string_parsers import colon_separated_string_to_dict, convert_uptime_string_seconds


def execute_get(device, cmd, separator=':', auto=False):
    output = device.execute_command(cmd)

    if auto:
        if ':' in output[0]:
            separator = ':'
        elif '\t' in output[0]:
            separator = '\t'
        else:
            raise Exception('Unknown separator for block:\n{}'.format(output))

    return colon_separated_string_to_dict('\n'.join(output), separator)


class FortiOSDriver(NetworkDriver):
    def __init__(self, hostname, username, password, timeout=60):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.device = FortiOS(hostname, username=username, password=password, timeout=timeout)
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
            'vendor': unicode('Fortigate'),
            'os_version': unicode(system_status['Version'].split(',')[0].split()[1]),
            'uptime': convert_uptime_string_seconds(performance_status['Uptime']),
            'serial_number': unicode(system_status['Serial-Number']),
            'model': unicode(system_status['Version'].split(',')[0].split()[0]),
            'hostname': unicode(system_status['Hostname']),
            'fqdn': u'{}.{}'.format(system_status['Hostname'], domain),
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
        cmd_prefix = ''
        try:
            cmd_data = self.device.execute_command('diagnose hardware deviceinfo nic')
        except CommandExecutionException:
            cmd_data = self.device.execute_command('conf global\n diagnose hardware deviceinfo nic ')
            cmd_prefix = 'conf global\n'
        
        interface_list = [x.replace('\t', '') for x in cmd_data if x.startswith('\t')]
        interface_statistics = {}
        for interface in interface_list:
            if_data = self.device.execute_command(cmd_prefix + 'diagnose hardware deviceinfo nic {}'.format(interface))
            parsed_data = {}
            if interface.startswith('mgmt'):
                for line in if_data:
                    if line.startswith('Speed'):
                        if line.split('\t')[-1].split(' ')[0].isdigit():
                            parsed_data['speed'] = int(line.split('\t')[-1].split(' ')[0])
                        else:
                            parsed_data['speed'] = -1
                    elif line.startswith('Link'):
                        parsed_data['is_up'] = line.split('\t')[-1] is 'up'
                    elif line.startswith('Current_HWaddr'):
                        parsed_data['mac_address'] = unicode(line.split('\t')[-1])
                parsed_data['is_enabled'] = True
                parsed_data['description'] = u''
                parsed_data['last_flapped'] = -1.0
            else:
                for line in if_data:
                    if line.startswith('Admin'):
                        parsed_data['is_enabled'] = line.split(':')[-1] is 'up'
                    elif line.startswith('PHY Status'):
                        parsed_data['is_up'] = line.split(':')[-1] is 'up'
                    elif line.startswith('PHY Speed'):
                        parsed_data['speed'] = int(line.split(':')[-1])
                    elif line.startswith('Current_HWaddr'):
                        parsed_data['mac_address'] = unicode(line.split(' ')[-1])
                parsed_data['description'] = u''
                parsed_data['last_flapped'] = -1.0
            interface_statistics[interface] = parsed_data
        return interface_statistics

    @staticmethod
    def _search_line_in_lines(search, lines):
        for l in lines:
            if search in l:
                return l

    def get_bgp_neighbors(self):

        families = ['ipv4', 'ipv6']
        terms = dict({'accepted_prefixes': 'accepted', 'sent_prefixes': 'announced'})
        command_sum = 'get router info bgp sum'
        command_detail = 'get router info bgp neighbor {}'
        command_received = 'get router info bgp neighbors {} received-routes | grep prefixes '
        peers = dict()

        bgp_sum = self.device.execute_command(command_sum)
        re_neigh = re.compile("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")
        neighbors = {n.split()[0]: n.split()[1:] for n in bgp_sum if re.match(re_neigh, n)}

        self.device.load_config('router bgp')

        for neighbor, parameters in neighbors.iteritems():
            logger.debug('NEW PEER')
            neigh_conf = self.device.running_config['router bgp']['neighbor']['{}'.format(neighbor)]

            neighbor_dict = peers.get(neighbor, dict())

            if not neighbor_dict:
                neighbor_dict['local_as'] = int(bgp_sum[0].split()[7])
                neighbor_dict['remote_as'] = int(neigh_conf.get_param('remote-as'))
                neighbor_dict['is_up'] = 'never' != parameters[7] or False
                neighbor_dict['is_enabled'] = neigh_conf.get_param('shutdown') != 'enable' or False
                neighbor_dict['description'] = u''
                neighbor_dict['uptime'] = convert_uptime_string_seconds(parameters[7])
                neighbor_dict['address_family'] = dict()
                neighbor_dict['address_family']['ipv4'] = dict()
                neighbor_dict['address_family']['ipv6'] = dict()

            detail_output = [x.lower() for x in self.device.execute_command(command_detail.format(neighbor))]
            m = re.search('remote router id (.+?)\n', '\n'.join(detail_output))
            if m:
                neighbor_dict['remote_id'] = unicode(m.group(1))
            else:
                raise Exception('cannot find remote router id for %s' % neighbor)

            for family in families:
                # find block
                x = detail_output.index(' for address family: {} unicast'.format(family))
                block = detail_output[x:]

                for term, fortiname in terms.iteritems():
                    text = self._search_line_in_lines('%s prefixes' % fortiname, block)
                    t = [int(s) for s in text.split() if s.isdigit()][0]
                    neighbor_dict['address_family'][family][term] = t

                received = self.device.execute_command(
                    command_received.format(neighbor))[0].split()
                if len(received) > 0:
                    neighbor_dict['address_family'][family]['received_prefixes'] = received[-1]
                else:
                    # Soft-reconfig is not enabled
                    neighbor_dict['address_family'][family]['received_prefixes'] = 0
            peers[neighbor] = neighbor_dict

        return {
            'global': {
                'router_id': unicode(bgp_sum[0].split()[3]),
                'peers': peers
            }
        }

    def get_interfaces_counters(self):
        cmd = self.device.execute_command('fnsysctl ifconfig')
        if_name = None
        interface_counters = dict()
        for line in cmd:
            data = line.split('\t')
            if (data[0] == '' or data[0] == ' ') and len(data) == 1:
                continue
            elif data[0] != '':
                if_name = data[0]
                interface_counters[if_name] = dict()
            elif (data[1].startswith('RX packets') or data[1].startswith('TX packets')) and if_name:
                if_data = data[1].split(' ')
                direction = if_data[0].lower()
                interface_counters[if_name][direction + '_unicast_packets'] = int(if_data[1].split(':')[1])
                interface_counters[if_name][direction + '_errors'] = int(if_data[2].split(':')[1])
                interface_counters[if_name][direction + '_discards'] = int(if_data[2].split(':')[1])
                interface_counters[if_name][direction + '_multicast_packets'] = -1
                interface_counters[if_name][direction + '_broadcast_packets'] = -1
            elif data[1].startswith('RX bytes'):
                if_data = data[1].split(' ')
                interface_counters[if_name]['rx_octets'] = int(if_data[1].split(':')[1])
                try:
                    interface_counters[if_name]['tx_octets'] = int(if_data[6].split(':')[1])
                except IndexError:
                    interface_counters[if_name]['tx_octets'] = int(if_data[7].split(':')[1])
        return interface_counters

    def get_lldp_neighbors(self):
        return {}

    def get_environment(self):

        def parse_string(line):
            return re.sub(' +', ' ', line.lower())

        def search_disabled(line):
            m = re.search("(.+?) (.+?) alarm=(.+?) \(scanning disabled\)", line)
            return m.group(2)

        def search_normal(line):
            m = re.search("(.+?) (.+?) alarm=(.+?) value=(.+?) threshold_status=(.+?)", line)
            return m

        def get_fans(fan_lines):
            output = dict()
            for fan_line in fan_lines:
                if 'disabled' in fan_line:
                    name = search_disabled(fan_line)
                    output[name] = dict(status=False)
                    continue

                m = search_normal(fan_line)
                output[m.group(2)] = dict(status=True)
            return output

        def get_cpu(cpu_lines):
            output = dict()
            for l in cpu_lines:
                m = re.search('(.+?) states: (.+?)% user (.+?)% system (.+?)% nice (.+?)% idle', l)
                cpuname = m.group(1)
                idle = m.group(5)
                output[cpuname] = {
                    '%usage': 100.0 - int(idle)
                }
            return output

        def get_memory(memory_line):
            total, used = int(memory_line[1]) >> 20, int(memory_line[2]) >> 20  # convert from byte to MB
            return dict(available_ram=total, used_ram=used)

        def get_temperature(temperature_lines, detail_block):
            output = dict()
            for temp_line in temperature_lines:
                if 'disabled' in temp_line:
                    sensor_name = search_disabled(temp_line)
                    output[sensor_name] = {'is_alert': False, 'is_critical': False, 'temperature': 0.0}
                    continue

                m = search_normal(temp_line)
                sensor_name, temp_value, status = m.group(2), m.group(4), int(m.group(5))
                is_alert = True if status == 1 else False

                # find block
                fullline = self._search_line_in_lines(sensor_name, detail_block)
                index_line = detail_block.index(fullline)
                sensor_block = detail_block[index_line:]

                v = int(self._search_line_in_lines('upper_non_recoverable', sensor_block).split('=')[1])

                output[sensor_name] = dict(temperature=float(temp_value), is_alert=is_alert,
                                           is_critical=True if v > temp_value else False)

            return output

        out = dict()

        sensors_block = [parse_string(x) for x in self.device.execute_command('execute sensor detail') if x]

        # temp
        temp_lines = [x for x in sensors_block if any([True for y in ['dts', 'temp', 'adt7490'] if y in x])]
        out['temperature'] = get_temperature(temp_lines, sensors_block)

        # fans
        out['fans'] = get_fans([x for x in sensors_block if 'fan' in x and 'temp' not in x])

        # cpu
        out['cpu'] = get_cpu(
            [x for x in self.device.execute_command('get system performance status | grep CPU')[1:] if x])

        # memory
        memory_command = 'diag hard sys mem | grep Mem:'
        t = [x for x in re.split('\s+', self.device.execute_command(memory_command)[0]) if x]
        out['memory'] = get_memory(t)

        # power, not implemented
        sensors = [x.split()[1] for x in sensors_block if x.split()[0].isdigit()]
        psus = {x for x in sensors if x.startswith('ps')}
        out['power'] = {t: {'status': True, 'capacity': -1.0, 'output': -1.0} for t in psus}

        return out

