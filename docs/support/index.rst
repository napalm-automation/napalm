Supported Devices
=================

General support matrix
----------------------


=====================   ==========  =============   ============ ==============  =============  ============  ============  ===============
_                       EOS         JunOS           IOS-XR       FortiOS         IBM            NXOS          IOS           Pluribus
=====================   ==========  =============   ============ ==============  =============  ============  ============  ===============
**Module Name**         napalm-eos  napalm-junos    napalm-iosxr napalm-fortios  napalm-ibm     napalm-nxos   napalm-ios    napalm-pluribus
**Driver Name**         eos         junos           iosxr        fortios         ibm            nxos          ios           pluribus
**Structured data**     Yes         Yes             No           No              Yes            Yes           No            No
**Minimum version**     4.15.0F     12.1            5.1.0        5.2.0           ???            6.1           12.4(20)T     N/A
**Backend library**     `pyeapi`_   `junos-eznc`_   `pyIOSXR`_   `pyFG`_         `bnclient`_    `pycsco`_     `netmiko`_    `pyPluribus`_
**Caveats**             :doc:`eos`                               :doc:`fortios`  :doc:`ibm`     :doc:`nxos`   :doc:`ios`
=====================   ==========  =============   ============ ==============  =============  ============  ============  ===============

.. _pyeapi: https://github.com/arista-eosplus/pyeapi
.. _junos-eznc: https://github.com/Juniper/py-junos-eznc
.. _pyIOSXR: https://github.com/fooelisa/pyiosxr
.. _pyFG: https://github.com/spotify/pyfg
.. _bnclient: https://github.com/kderynski/blade-netconf-python-client
.. _pycsco: https://github.com/jedelman8/pycsco
.. _netmiko: https://github.com/ktbyers/netmiko
.. _pyPluribus: https://github.com/mirceaulinic/pypluribus


.. warning:: Please, make sure you understand the caveats for your particular platforms before using the library.


Configuration support matrix
----------------------------

=====================   ==========  =====   ==========  ==============  =============  ==============  ==============  ==============
_                       EOS         JunOS   IOS-XR      FortiOS         IBM            NXOS            IOS             Pluribus
=====================   ==========  =====   ==========  ==============  =============  ==============  ==============  ==============
**Config. replace**     Yes         Yes     Yes         Yes             Yes [#c3]_     Yes             Yes             No
**Config. merge**       Yes         Yes     Yes         Yes             Yes            Yes             Yes             No
**Compare config**      Yes         Yes     Yes [#c1]_  Yes [#c1]_      Yes [#c1]_     Yes [#c4]_      Yes             No
**Atomic Changes**      Yes         Yes     Yes         No [#c2]_       No [#c2]_      Yes/No [#c5]_   Yes             Yes
**Rollback**            Yes [#c2]_  Yes     Yes         Yes             Yes [#c2]_     Yes/No [#c5]_   Yes             No
=====================   ==========  =====   ==========  ==============  =============  ==============  ==============  ==============

.. [#c1] Hand-crafted by the API as the device doesn't support the feature.
.. [#c2] Not supported but emulated. Check caveats.
.. [#c3] Check the caveats, this is a dangerous operation in this device.
.. [#c4] For merges, the diff is simply the merge config itself. See caveats.
.. [#c5] No for merges. See caveats.

.. warning:: Before building a workflow to deploy configuration it is important you understand what the table above means;
            what are atomic changes and which devices support it, what does replacing or merging configuration mean, etc.
            The key to success is to test your workflow and to try to break things on a lab first.

.. include:: _include/getters_support_table.rst

Other methods
-------------

.. |yes|   unicode:: U+02705 .. Yes
.. |no|    unicode:: U+0274C .. No

============================== =====  =====   ======  =======  ======  ======  =====  =========
_                               EOS   JunOS   IOS-XR  FortiOS  IBM     NXOS    IOS    Pluribus
============================== =====  =====   ======  =======  ======  ======  =====  =========
**load_template**              |yes|  |yes|   |yes|   |yes|    |yes|   |yes|   |yes|  |yes|
**traceroute**                 |yes|  |yes|   |yes|   |no|     |no|    |yes|   |no|   |yes|
============================== =====  =====   ======  =======  ======  ======  =====  =========

Available configuration templates
---------------------------------

* :code:`set_hostname` (JunOS, IOS-XR, IOS) - Configures the hostname of the device.
* :code:`set_ntp_peers` (JunOS, IOS-XR, EOS, NXOS, IOS) - Configures NTP peers of the device.
* :code:`delete_ntp_peers` (JunOS, IOS-XR, EOS, NXOS, IOS): Removes NTP peers form device's configuration.
* :code:`set_probes` (JunOS, IOS-XR): Configures RPM/SLA probes.
* :code:`schedule_probes` (IOS-XR): On Cisco devices, after defining the SLA probes, it is mandatory to schedule them. Defined also for JunOS as empty template, for consistency reasons.
* :code:`delete_probes` (JunOS, IOS-XR): Removes RPM/SLA probes.

Caveats
-------

.. toctree::
   :maxdepth: 1

   eos
   fortios
   ibm
   nxos
   ios

Optional arguments
------------------

NAPALM supports passing certain optional arguments to some drivers. To do that you have to pass a dictionary via the
:code:`optional_args` parameter when creating the object::

    >>> from napalm import get_network_driver
    >>> driver = get_network_driver('eos')
    >>> optional_args = {'my_optional_arg1': 'my_value1', 'my_optional_arg2': 'my_value2'}
    >>> device = driver('192.168.76.10', 'dbarroso', 'this_is_not_a_secure_password', optional_args=optional_args)
    >>> device.open()

List of supported optional arguments
____________________________________

* :code:`fortios_vdom` (fortios) - VDOM to connect to.
* :code:`port` (eos, iosxr, junos, ios) - Allows you to specify a port other than the default.
* :code:`config_lock` (iosxr, junos) - Lock the config during open() (default: True).
* :code:`dest_file_system` (ios) - Destination file system for SCP transfers (default: 'flash:').
* :code:`auto_rollback_on_error` (ios) - Disable automatic rollback (certain versions of IOS support configure replace, but not rollback on error) (default: True).
* :code:`global_delay_factor` (ios) - Allow for additional delay in command execution (default: .5).


Adding optional arguments to NAPALM drivers
___________________________________________

If you are a developer and want to add an optional argument to a driver, please, follow this pattern when naming the
argument; :code:`$driver_name-$usage` if the argument applies only to a particular driver. For example, the optional
argument :code:`fortios_vdom` is used only by the FortiOS driver to select a particular vdom. Otherwise, just name it
:code:`$driver_name-$usage`. For example the :code:`port` optional argument.
