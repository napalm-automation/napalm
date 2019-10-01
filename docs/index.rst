.. napalm documentation master file, created by
   sphinx-quickstart on Tue March 26 12:11:44 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to NAPALM's documentation!
==================================

NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support) is a Python library that implements a set of functions to interact with different network device Operating Systems using a unified API.

NAPALM supports several methods to connect to the devices, to manipulate configurations or to retrieve data.

Supported Network Operating Systems:
------------------------------------

* Arista EOS
* Cisco IOS
* Cisco IOS-XR
* Cisco NX-OS
* Juniper JunOS

Extras
______

In addition to the core drivers napalm also supports community driven drivers. You can find more information about them here: :ref:`contributing-drivers`

Selecting the right driver
--------------------------

You can select the driver you need by doing the following:

.. code-block:: python

   >>> from napalm import get_network_driver
   >>> get_network_driver('eos')
   <class napalm.eos.eos.EOSDriver at 0x10ebad6d0>
   >>> get_network_driver('iosxr')
   <class napalm.iosxr.iosxr.IOSXRDriver at 0x10ec90050>
   >>> get_network_driver('junos')
   <class napalm.junos.junos.JunOSDriver at 0x10f8f61f0>
   >>> get_network_driver('nxos')
   <class napalm.nxos.nxos.NXOSDriver at 0x10f9304c8>
   >>> get_network_driver('ios')
   <class napalm.ios.ios.IOSDriver at 0x10f9b0738>


Documentation
=============

.. toctree::
   :maxdepth: 2

   installation/index
   tutorials/index
   validate/index
   support/index
   cli
   base
   yang
   logs
   integrations/index
   contributing/index
   development/index
   hackathons/index
