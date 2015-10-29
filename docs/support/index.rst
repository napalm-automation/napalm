Supported Devices
=================

General support matrix
----------------------


=====================   ==========  =============   =========== ==============  =============
_                       EOS         JunOS           IOS-XR      FortiOS         IBM
=====================   ==========  =============   =========== ==============  =============
**Driver Name**         eos         junos           iosxr       fortios         ibm
**Structured data**     Yes         Yes             No          No              Yes
**Minimum version**     4.15.0F     12.1            5.1.0       5.2.0           ???
**Backend library**     `pyeapi`_   `junos-eznc`_   `pyIOSXR`_   `pyFG`_        `bnclient`_
**Caveats**             :doc:`eos`                              :doc:`fortios`  :doc:`ibm`
=====================   ==========  =============   =========== ==============  =============

.. _pyeapi: https://github.com/arista-eosplus/pyeapi
.. _junos-eznc: https://github.com/Juniper/py-junos-eznc
.. _pyIOSXR: https://github.com/fooelisa/pyiosxr
.. _pyFG: https://github.com/spotify/pyfg
.. _bnclient: ???


.. warning:: Please, make sure you understand the caveats for your particular platforms before using the library.


Configuration support matrix
----------------------------

=====================   ==========  =====   ==========  ==============  =============
_                       EOS         JunOS   IOS-XR      FortiOS         IBM
=====================   ==========  =====   ==========  ==============  =============
**Config. replace**     Yes         Yes     Yes         Yes             Yes [#c3]_
**Config. merge**       Yes         Yes     Yes         Yes             Yes
**Compare config**      Yes         Yes     Yes [#c1]_  Yes [#c1]_      Yes [#c1]_
**Atomic Changes**      Yes         Yes     Yes         No [#c2]_       No [#c2]_
**Rollback**            Yes [#c2]_  Yes     Yes         Yes             Yes [#c2]_
=====================   ==========  =====   ==========  ==============  =============

.. [#c1] Hand-crafted by the API as the device doesn't support the feature.
.. [#c2] Not supported but emulated. Check caveats.
.. [#c3] Check the caveats, this is a dangerous operation in this device.

.. warning:: Before building a workflow to deploy configuration it is important you understand what the table above means;
            what are atomic changes and which devices support it, what does replacing or merging configuration mean, etc.
            The key to success is to test your workflow and to try to break things on a lab first.

Getters support matrix
----------------------

.. |yes|   unicode:: U+02705 .. Yes
.. |no|    unicode:: U+0274C .. No

======================  =====  =====   ======  =======  ======
_                       EOS    JunOS   IOS-XR  FortiOS  IBM
======================  =====  =====   ======  =======  ======
**get_facts**           |yes|  |yes|   |yes|   |yes|    |no|
**get_interfaces**      |yes|  |yes|   |yes|   |yes|    |no|
**get_lldp_neighbors**  |yes|  |yes|   |yes|   |yes|    |no|
======================  =====  =====   ======  =======  ======

Caveats
-------

.. toctree::
   :maxdepth: 1

   eos
   fortios
   ibm