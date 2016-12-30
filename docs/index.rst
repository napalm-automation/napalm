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
* Fortinet Fortios
* IBM
* Juniper JunOS
* Mikrotik RouterOS
* Palo Alto NOS
* Pluribus
* Vyos 

You can select the driver you need by doing the following:

.. code-block:: python

   >>> from napalm_base import get_network_driver
   >>> get_network_driver('eos')
   <class napalm_eos.eos.EOSDriver at 0x10ebad6d0>
   >>> get_network_driver('iosxr')
   <class napalm_iosxr.iosxr.IOSXRDriver at 0x10ec90050>
   >>> get_network_driver('junos')
   <class napalm_junos.junos.JunOSDriver at 0x10f96f328>
   >>> get_network_driver('fortios')
   <class napalm_fortios.fortios.FortiOSDriver at 0x10f96fc18>
   >>> get_network_driver('ibm')
   <class napalm_ibm.ibm.IBMDriver at 0x10f8f61f0>
   >>> get_network_driver('nxos')
   <class napalm_nxos.nxos.NXOSDriver at 0x10f9304c8>
   >>> get_network_driver('ios')
   <class napalm_ios.ios.IOSDriver at 0x10f9b0738>
   >>> get_network_driver('pluribus')
   <class napalm_pluribus.pluribus.PluribusDriver at 0x80103e530>


Check the tutorials to see how to use the library in more detail, Supported Devices will provide you with detailed support information and caveats and the NetworkDriver section explains which methods are available for you to use.

Documentation
=============

.. toctree::
   :maxdepth: 2

   installation
   tutorials/index
   validate/index
   support/index
   cli
   base
   contributing/index
   development/index
   hackathons/index
