.. _supported-devices:

Supported Devices
=================

General support matrix
----------------------



  =====================   ==========  =============   ============ ============  ============ ============
  _                       EOS         Junos           IOS-XR       NX-OS         NX-OS SSH    IOS
  =====================   ==========  =============   ============ ============  ============ ============
  **Driver Name**         eos         junos           iosxr        nxos          nxos_ssh     ios
  **Structured data**     Yes         Yes             No           Yes           No           No
  **Minimum version**     4.15.0F     12.1            5.1.0        6.1 [#g1]_                 12.4(20)T
  **Backend library**     `pyeapi`_   `junos-eznc`_   `pyIOSXR`_   `pynxos`_     `netmiko`_   `netmiko`_
  **Caveats**             :doc:`eos`                               :doc:`nxos`   :doc:`nxos`  :doc:`ios`
  =====================   ==========  =============   ============ ============  ============ ============

.. _pyeapi: https://github.com/arista-eosplus/pyeapi
.. _junos-eznc: https://github.com/Juniper/py-junos-eznc
.. _pyIOSXR: https://github.com/fooelisa/pyiosxr
.. _pynxos: https://github.com/networktocode/pynxos
.. _netmiko: https://github.com/ktbyers/netmiko

.. [#g1] NX-API support on the Nexus 5k, 6k and 7k families was introduced in version 7.2

.. warning:: Please, make sure you understand the caveats for your particular platforms before using the library.


Configuration support matrix
----------------------------

=====================   ==========  =====   ==========  ==============  ==============
_                       EOS         Junos   IOS-XR      NX-OS           IOS
=====================   ==========  =====   ==========  ==============  ==============
**Config. replace**     Yes         Yes     Yes         Yes             Yes
**Config. merge**       Yes         Yes     Yes         Yes             Yes
**Compare config**      Yes         Yes     Yes [#c1]_  Yes [#c4]_      Yes
**Atomic Changes**      Yes         Yes     Yes         Yes/No [#c5]_   Yes/No [#c5]_
**Rollback**            Yes [#c2]_  Yes     Yes         Yes/No [#c5]_   Yes
=====================   ==========  =====   ==========  ==============  ==============

.. [#c1] Hand-crafted by the API as the device doesn't support the feature.
.. [#c2] Not supported but emulated. Check caveats.
.. [#c4] For merges, the diff is very simplistic. See caveats.
.. [#c5] No for merges. See caveats.

.. warning:: Before building a workflow to deploy configuration it is important you understand what the table above means;
            what are atomic changes and which devices support it, what does replacing or merging configuration mean, etc.
            The key to success is to test your workflow and to try to break things on a lab first.

Getters support matrix
----------------------

.. note:: The following table is built automatically. Every time there is a release of a supported driver a built is triggered. The result of the tests are aggregated on the following table.

.. include:: matrix.rst


Other methods
-------------

.. |yes|   unicode:: U+02705 .. Yes
.. |no|    unicode:: U+0274C .. No

============================== =====  =====   ======  ======  =====
_                              EOS    Junos   IOS-XR  NX-OS   IOS
============================== =====  =====   ======  ======  =====
**load_template**              |yes|  |yes|   |yes|   |yes|   |yes|
**ping**                       |yes|  |yes|   |no|    |yes|   |yes|
**traceroute**                 |yes|  |yes|   |yes|   |yes|   |yes|
============================== =====  =====   ======  ======  =====

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
   ios
   nxos

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

* :code:`allow_agent` (ios, iosxr, nxos_ssh) - Paramiko argument, enable connecting to the SSH agent (default: ``False``).
* :code:`alt_host_keys` (ios, iosxr, nxos_ssh) - If ``True``, host keys will be loaded from the file specified in ``alt_key_file``.
* :code:`alt_key_file` (ios, iosxr, nxos_ssh) - SSH host key file to use (if ``alt_host_keys`` is ``True``).
* :code:`auto_rollback_on_error` (ios) - Disable automatic rollback (certain versions of IOS support configure replace, but not rollback on error) (default: ``True``).
* :code:`config_lock` (iosxr, junos) - Lock the config during open() (default: ``False``).
* :code:`lock_disable` (junos) - Disable all configuration locking for management by an external system (default: ``False``).
* :code:`canonical_int` (ios) - Convert operational interface's returned name to canonical name (fully expanded name) (default: ``False``).
* :code:`dest_file_system` (ios) - Destination file system for SCP transfers (default: ``flash:``).
* :code:`enable_password` (eos) - Password required to enter privileged exec (enable) (default: ``''``).
* :code:`global_delay_factor` (ios, nxos_ssh) - Allow for additional delay in command execution (default: ``1``).
* :code:`ignore_warning` (junos) - Allows to set `ignore_warning` when loading configuration to avoid exceptions via junos-pyez. (default: ``False``).
* :code:`keepalive` (iosxr, junos) - SSH keepalive interval, in seconds (default: ``30`` seconds).
* :code:`key_file` (ios, iosxr, junos, nxos_ssh) - Path to a private key file. (default: ``False``).
* :code:`port` (eos, ios, iosxr, junos, nxos, nxos_ssh) - Allows you to specify a port other than the default.
* :code:`secret` (ios, nxos_ssh) - Password required to enter privileged exec (enable) (default: ``''``).
* :code:`ssh_config_file` (ios, iosxr, junos, nxos_ssh) - File name of OpenSSH configuration file.
* :code:`ssh_strict` (ios, iosxr, nxos_ssh) - Automatically reject unknown SSH host keys (default: ``False``, which means unknown SSH host keys will be accepted).
* :code:`ssl_verify` (nxos) - Requests argument, enable the SSL certificates verification. See requests ssl-cert-verification for valide values (default: ``None`` equivalent to ``False``).
* :code:`transport` (eos, ios, nxos) - Protocol to connect with (see `The transport argument`_ for more information).
* :code:`use_keys` (ios, iosxr, nxos_ssh) - Paramiko argument, enable searching for discoverable private key files in ``~/.ssh/`` (default: ``False``).
* :code:`eos_autoComplete` (eos) - Allows to set `autoComplete` when running commands. (default: ``None`` equivalent to ``False``)

The transport argument
______________________

Certain drivers support providing an alternate transport in the :code:`optional_args`, overriding the default protocol to connect with. Allowed transports are therefore device/library dependant:

=============== ====================  ====================  ===================
_               EOS                   NXOS                  IOS
=============== ====================  ====================  ===================
**Default**     ``https``             ``https``             ``ssh``
**Supported**   ``http``, ``https``   ``http``, ``https``   ``telnet``, ``ssh``
=============== ====================  ====================  ===================
