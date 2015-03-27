NAPALM
======
NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support) is python library that implements a set of functions to interact with different vendors using a unified API.

NAPALM supports several methods to connect to the devices, to manipulate configuration and to retrieve data.

Supported Network Operating Systems
-----------------------------------

 * eos - Using [pyEOS](https://github.com/spotify/pyeos). You need version 4.14.6M or superior.
 * junos - Using [junos-eznc](https://github.com/Juniper/py-junos-eznc)
 * iosxr - Using [pyIOSXR](https://github.com/fooelisa/pyiosxr)

Documentation
=============

See the [Read the Docs](http://napalm.readthedocs.org)

Install
=======

To install, execute:

``
   pip install napalm
``

Ansible
=======

There is an ansible module provided by this API. Make sure you read the documentation and you understand how it works before trying to use it.