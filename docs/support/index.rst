Supported Devices
=================

General support matrix
----------------------



  =====================   ==========  =============   ============ ==============  ============  ============  ===============  =========================  ==============  ==============
  _                       EOS         JunOS           IOS-XR       FortiOS         NXOS          IOS           Pluribus         PANOS                      MikroTik        VyOS
  =====================   ==========  =============   ============ ==============  ============  ============  ===============  =========================  ==============  ==============
  **Module Name**         napalm-eos  napalm-junos    napalm-iosxr napalm-fortios  napalm-nxos   napalm-ios    napalm-pluribus  napalm-panos               napalm-ros      napalm-vyos
  **Driver Name**         eos         junos           iosxr        fortios         nxos          ios           pluribus         panos                      ros             vyos
  **Structured data**     Yes         Yes             No           No              Yes           No            No               Yes                        Yes             Yes
  **Minimum version**     4.15.0F     12.1            5.1.0        5.2.0           6.1 [#g1]_    12.4(20)T     N/A              7.0                        3.30            1.1.6
  **Backend library**     `pyeapi`_   `junos-eznc`_   `pyIOSXR`_   `pyFG`_         `pycsco`_     `netmiko`_    `pyPluribus`_    `netmiko`_, `pan-python`_  `librouteros`_  `netmiko`_
  **Caveats**             :doc:`eos`                               :doc:`fortios`  :doc:`nxos`   :doc:`ios`                     :doc:`panos`                               :doc:`vyos`
  =====================   ==========  =============   ============ ==============  ============  ============  ===============  =========================  ==============  ==============

.. _pyeapi: https://github.com/arista-eosplus/pyeapi
.. _junos-eznc: https://github.com/Juniper/py-junos-eznc
.. _pyIOSXR: https://github.com/fooelisa/pyiosxr
.. _pyFG: https://github.com/spotify/pyfg
.. _pycsco: https://github.com/jedelman8/pycsco
.. _netmiko: https://github.com/ktbyers/netmiko
.. _pyPluribus: https://github.com/mirceaulinic/pypluribus
.. _pan-python: https://github.com/kevinsteves/pan-python
.. _librouteros: https://github.com/luqasz/librouteros

.. [#g1] NX-API support on the Nexus 5k, 6k and 7k families was introduced in version 7.2

.. warning:: Please, make sure you understand the caveats for your particular platforms before using the library.


Configuration support matrix
----------------------------

=====================   ==========  =====   ==========  ==============  ==============  ==============  ==============  ============== ======== ========
_                       EOS         JunOS   IOS-XR      FortiOS         NXOS            IOS             Pluribus        PANOS          MikroTik VyOS
=====================   ==========  =====   ==========  ==============  ==============  ==============  ==============  ============== ======== ========
**Config. replace**     Yes         Yes     Yes         Yes             Yes             Yes             No              Yes            No       Yes
**Config. merge**       Yes         Yes     Yes         Yes             Yes             Yes             No              Yes            No       Yes
**Compare config**      Yes         Yes     Yes [#c1]_  Yes [#c1]_      Yes [#c4]_      Yes             No              Yes            No       Yes
**Atomic Changes**      Yes         Yes     Yes         No [#c2]_       Yes/No [#c5]_   Yes             Yes             Yes/No [#c5]_  No       Yes
**Rollback**            Yes [#c2]_  Yes     Yes         Yes             Yes/No [#c5]_   Yes             No              Yes            No       Yes
=====================   ==========  =====   ==========  ==============  ==============  ==============  ==============  ============== ======== ======== 

.. [#c1] Hand-crafted by the API as the device doesn't support the feature.
.. [#c2] Not supported but emulated. Check caveats.
.. [#c3] Check the caveats, this is a dangerous operation in this device.
.. [#c4] For merges, the diff is simply the merge config itself. See caveats.
.. [#c5] No for merges. See caveats.

.. warning:: Before building a workflow to deploy configuration it is important you understand what the table above means;
            what are atomic changes and which devices support it, what does replacing or merging configuration mean, etc.
            The key to success is to test your workflow and to try to break things on a lab first.

Getters support matrix
----------------------

.. note:: The following table is built automatically. Everytime there is a release of a supported driver a built is triggered. The result of the tests are aggreggated on the following table.

.. include:: matrix.rst


Other methods
-------------

.. |yes|   unicode:: U+02705 .. Yes
.. |no|    unicode:: U+0274C .. No

============================== =====  =====   ======  =======  ======  =====  =========  ========= ======== ========
_                               EOS   JunOS   IOS-XR  FortiOS  NXOS    IOS    Pluribus   PANOS     MikroTik VyOS
============================== =====  =====   ======  =======  ======  =====  =========  ========= ======== ========
**load_template**              |yes|  |yes|   |yes|   |yes|    |yes|   |yes|  |yes|      |yes|     |no|	    |yes|
**ping**                       |no|   |no|    |no|    |no|     |no|    |yes|  |no|       |no|      |yes|    |yes|
**traceroute**                 |yes|  |yes|   |yes|   |no|     |yes|   |yes|  |yes|      |no|      |no|     |no|
============================== =====  =====   ======  =======  ======  =====  =========  ========= ======== ========

Available configuration templates
---------------------------------

* :code:`set_hostname` (JunOS, IOS-XR, IOS, PANOS) - Configures the hostname of the device.
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
   panos
   vyos

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
* :code:`port` (eos, iosxr, junos, ios, ros, vyos) - Allows you to specify a port other than the default.
* :code:`config_lock` (iosxr, junos) - Lock the config during open() (default: True).
* :code:`dest_file_system` (ios) - Destination file system for SCP transfers (default: 'flash:').
* :code:`auto_rollback_on_error` (ios) - Disable automatic rollback (certain versions of IOS support configure replace, but not rollback on error) (default: True).
* :code:`global_delay_factor` (ios) - Allow for additional delay in command execution (default: 1).
* :code:`nxos_protocol` (nxos) - Protocol to connect with.  Only 'https' and 'http' allowed (default: 'http').
* :code:`enable_password` (eos) - Password required to enter privileged exec (enable) (default: '').
* :code:`allow_agent` (ios, panos) - Paramiko argument, enable connecting to the SSH agent (default: 'False').
* :code:`use_keys` (ios, panos) - Paramiko argument, enable searching for discoverable private key files in ~/.ssh/ (default: 'False').
* :code:`key_file` (vyos) - Netmiko/Paramiko argument, path to a private key file (default: 'False').
* :code:`api_key` (panos) - Allow to specify the API key instead of username/password (default: '').


Adding optional arguments to NAPALM drivers
___________________________________________

If you are a developer and want to add an optional argument to a driver, please, follow this pattern when naming the
argument; :code:`$driver_name-$usage` if the argument applies only to a particular driver. For example, the optional
argument :code:`fortios_vdom` is used only by the FortiOS driver to select a particular vdom. Otherwise, just name it
:code:`$driver_name-$usage`. For example the :code:`port` optional argument.
