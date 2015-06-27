NAPALM
======
NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support) is python library that implements a set of functions to interact with different vendors using a unified API.

![NAPALM logo](static/logo.png?raw=true "NAPALM logo")

NAPALM supports several methods to connect to the devices, to manipulate configuration and to retrieve data.

Supported Network Operating Systems
-----------------------------------
 * EOS - Using [pyEOS](https://github.com/spotify/pyeos). You need version 4.14.6M or superior.
 * JunOS - Using [junos-eznc](https://github.com/Juniper/py-junos-eznc)
 * IOS-XR - Using [pyIOSXR](https://github.com/fooelisa/pyiosxr)
 * FortiOS - Using [pyFG](https://github.com/spotify/pyfg)

|   | EOS  | JunOS  | IOS-XR  | FortiOS  |
|---|---|---|---|---|
| **Name** | eos | junos | iosxr | fortios |
| **Config Management** | Full  | Full  | Full  | Full |
| **Atomic Changes** | Yes | Yes | Yes | No |
| **Rollback** | Yes | Yes | Yes | Yes |

Documentation
=============
Before using the library, please, read the documentation (link below). Specially the "caveats" section:

See the [Read the Docs](http://napalm.readthedocs.org)

You can also watch a [live demo](https://youtu.be/93q-dHC0u0I) of NAPALM to see what it is and what it can do for you.


Install
=======
To install, execute:

``
   pip install napalm
``

Ansible
=======
There is an ansible module provided by this API. Make sure you read the documentation and you understand how it works before trying to use it.

Mailing List
=======
If you have any questions, join the users' mailing list at [napalm-automation@googlegroups.com](mailto:napalm-automation@googlegroups.com) and if you are developer and want to contribute to NAPALM feel free to join to the developers' mailing list at [napalm-dev@googlegroups.com](mailto:napalm-dev@googlegroups.com)

Authors
=======
 * David Barroso ([dbarroso@spotify.com](mailto:dbarroso@spotify.com))
 * Elisa Jasinska ([elisa@bigwaveit.org](mailto:elisa@bigwaveit.org))

