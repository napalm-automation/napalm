.. napalm documentation master file, created by
   sphinx-quickstart on Tue March 26 12:11:44 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to NAPALM's documentation!
==================================

NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support) is python library that implements a common set of functions to interact with different network Operating Systems using a unified API.

NAPALM supports several methods to connect to the devices, to manipulate configuration or to retrieve data.

Supported Network Operating System:

 * eos
 * junos
 * iosxr

You can get the driver you need by doing the following::

    >>> from napalm import get_network_driver
    >>> get_network_driver('eos')
    <class napalm.eos.EOSDriver at 0x106fc1a78>
    >>> get_network_driver('iosxr')
    <class napalm.iosxr.IOSXRDriver at 0x10706c738>
    >>> get_network_driver('junos')
    <class napalm.junos.JunOSDriver at 0x107861bb0>

Check the tutorials to see how to use the library and the driver section to check which methods are available and some notes regarding each driver.

Tutorials
=========

.. toctree::
   :maxdepth: 1

   first_steps_config

Drivers
=======

.. toctree::
   :maxdepth: 2

   base
   eos
