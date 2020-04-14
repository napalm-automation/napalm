Context Manager
===============

In the previous tutorial we used the methods ``open()`` to connect to the device and ``close()`` to disconnect.
Using those methods are useful if you want to do complex or asynchronous code. However, for most situations you should
try to stick with the context manager. It handles opening and closing the session automatically and it's the
pythonic way:

.. code-block:: python

>>> from napalm import get_network_driver
>>> driver = get_network_driver('eos')
>>> with driver('localhost', 'vagrant', 'vagrant', optional_args={'port': 12443}) as device:
...     print(device.get_facts())
...     print(device.get_interfaces_counters())
...
{'os_version': u'4.15.2.1F-2759627.41521F', 'uptime': 2010, 'interface_list': [u'Ethernet1', u'Ethernet2', u'Management1'], 'vendor': u'Arista', 'serial_number': u'', 'model': u'vEOS', 'hostname': u'NEWHOSTNAME', 'fqdn': u'NEWHOSTNAME'}
{u'Ethernet2': {'tx_multicast_packets': 1028, 'tx_discards': 0, 'tx_octets': 130744, 'tx_errors': 0, 'rx_octets': 0, 'tx_unicast_packets': 0, 'rx_errors': 0, 'tx_broadcast_packets': 0, 'rx_multicast_packets': 0, 'rx_broadcast_packets': 0, 'rx_discards': 0, 'rx_unicast_packets': 0}, u'Management1': {'tx_multicast_packets': 0, 'tx_discards': 0, 'tx_octets': 99664, 'tx_errors': 0, 'rx_octets': 105000, 'tx_unicast_packets': 773, 'rx_errors': 0, 'tx_broadcast_packets': 0, 'rx_multicast_packets': 0, 'rx_broadcast_packets': 0, 'rx_discards': 0, 'rx_unicast_packets': 0}, u'Ethernet1': {'tx_multicast_packets': 1027, 'tx_discards': 0, 'tx_octets': 130077, 'tx_errors': 0, 'rx_octets': 0, 'tx_unicast_packets': 0, 'rx_errors': 0, 'tx_broadcast_packets': 0, 'rx_multicast_packets': 0, 'rx_broadcast_packets': 0, 'rx_discards': 0, 'rx_unicast_packets': 0}}
