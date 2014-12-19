Usage
=====

Connecting
----------

```
from drivers.eos import EOSDriver

arista = EOSDriver('10.48.71.3', 'admin', 'sp0tify')
arista.open()

Getting facts
-------------

facts = arista.get_facts()

>>> facts.vendor
'Arista'
>>> facts.hostname
u'config01'
>>> facts.fqdn
u'config01.lab.spotify.net'
>>> facts.hardware_model
u'DCS-7150S-64-CL-F'
>>> facts.serial_number
u'JPE14023449'
>>> facts.os_version
u'4.14.5F'
>>> facts.interfaces
[u'Ethernet8', u'Ethernet9', u'Ethernet2', u'Ethernet3', u'Ethernet1', u'Ethernet6', u'Ethernet7', u'Ethernet4', u'Ethernet5', u'Ethernet52/1', u'Ethernet52/3', u'Ethernet52/2', u'Ethernet52/4', u'Ethernet34', u'Ethernet22', u'Ethernet50/4', u'Ethernet50/3', u'Ethernet50/2', u'Ethernet50/1', u'Ethernet51/4', u'Ethernet51/2', u'Ethernet51/3', u'Ethernet51/1', u'Ethernet38', u'Ethernet39', u'Ethernet18', u'Ethernet19', u'Ethernet32', u'Ethernet15', u'Ethernet16', u'Ethernet31', u'Ethernet49/1', u'Ethernet37', u'Ethernet49/3', u'Ethernet35', u'Ethernet10', u'Ethernet14', u'Ethernet49/2', u'Ethernet33', u'Ethernet49/4', u'Ethernet30', u'Management1', u'Ethernet17', u'Ethernet48', u'Ethernet47', u'Ethernet36', u'Ethernet45', u'Ethernet44', u'Ethernet43', u'Ethernet42', u'Ethernet41', u'Ethernet40', u'Ethernet29', u'Ethernet28', u'Ethernet11', u'Ethernet12', u'Ethernet46', u'Ethernet21', u'Ethernet20', u'Ethernet23', u'Ethernet13', u'Ethernet25', u'Ethernet24', u'Ethernet27', u'Ethernet26']
```

Getting BGP information
-----------------------

```
>>> for instance in arista.get_bgp_neighbors():
...     print instance
...     for neigh in instance.bgp_neighbors:
...         print '    ', neigh
...
BGP Instance: vrf=default, asn=123, router_id=10.48.71.3
     BGP Neighbor: ip=2.1.3.5, asn=345, state=Idle
     BGP Neighbor: ip=1.1.1.1, asn=1, state=Idle
     BGP Neighbor: ip=2.1.3.4, asn=345, state=Idle
BGP Instance: vrf=test, asn=23, router_id=192.12.4.1
     BGP Neighbor: ip=192.12.4.6, asn=94, state=Connect
```
