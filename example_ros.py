#!/usr/bin/python
#
#
#
import sys
import pprint
#
import napalm_ros

if len(sys.argv) == 5:
	_, ros_host, ros_user, ros_pass, ros_community = sys.argv
else:
	sys.stderr.write('Usage: {} <hostname> <username> <password> <snmp_community>\n'.format(sys.argv[0]))
	sys.exit(0)

foo = napalm_ros.ROSDriver(hostname=ros_host, username=ros_user, password=ros_pass, optional_args=dict(snmp_community=ros_community))

foo.open()
print vars(foo)

print 'foo.get_arp_table()'
try:
	pprint.pprint(foo.get_arp_table())
except NotImplementedError as e:
	print e.message

print 'foo.get_bgp_neighbors()'
try:
	pprint.pprint(foo.get_bgp_neighbors())
except NotImplementedError as e:
	print e.message

print 'foo.get_bgp_neighbors_detail()'
try:
	pprint.pprint(foo.get_bgp_neighbors_detail())
except NotImplementedError as e:
	print e.message

print 'foo.get_environment()'
try:
	pprint.pprint(foo.get_environment())
except NotImplementedError as e:
	print e.message

print 'foo.get_facts()'
try:
	pprint.pprint(foo.get_facts())
except NotImplementedError as e:
	print e.message

print 'foo.get_interfaces()'
try:
	pprint.pprint(foo.get_interfaces())
except NotImplementedError as e:
	print e.message

print 'foo.get_interfaces_counters()'
try:
	pprint.pprint(foo.get_interfaces_counters())
except NotImplementedError as e:
	print e.message

print 'foo.get_interfaces_ip()'
try:
	pprint.pprint(foo.get_interfaces_ip())
except NotImplementedError as e:
	print e.message

print 'foo.get_lldp_neighbors()'
try:
	pprint.pprint(foo.get_lldp_neighbors())
except NotImplementedError as e:
	print e.message

print 'foo.get_lldp_neighbors_detail()'
try:
	pprint.pprint(foo.get_lldp_neighbors_detail(interface=''))
except NotImplementedError as e:
	print e.message

print 'foo.get_mac_address_table()'
try:
	pprint.pprint(foo.get_mac_address_table())
except NotImplementedError as e:
	print e.message

print 'foo.get_ntp_peers()'
try:
	pprint.pprint(foo.get_ntp_peers())
except NotImplementedError as e:
	print e.message

print 'foo.get_route_to()'
try:
	pprint.pprint(foo.get_route_to(destination='', protocol=''))
except NotImplementedError as e:
	print e.message

print 'foo.get_snmp_information()'
try:
	pprint.pprint(foo.get_snmp_information())
except NotImplementedError as e:
	print e.message

print 'foo.get_users()'
try:
	print foo.get_users()
except NotImplementedError as e:
	print e.message

print 'foo.ping()'
try:
	pprint.pprint(foo.ping('8.8.8.23', count=2))
except NotImplementedError as e:
	print e.message

print 'foo.traceroute()'
try:
	pprint.pprint(foo.traceroute('8.8.8.8'))
except NotImplementedError as e:
	print e.message

foo.close()
print vars(foo)
