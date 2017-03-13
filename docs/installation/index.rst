Installation
============


Full installation
-----------------

If you want to fully install NAPALM you can do it by executing:

``
pip install napalm
``

That will install all the drivers currently available.


Partial Installation
--------------------

If you want to install just a subset of the available modules you can just pick them as follows:

``
pip install napalm-eos napalm-junos
``

That will install only the `eos` and the `junos` drivers. If you want to remove or add a module later on you can just use `pip` to do it:

``
pip uninstall napalm-junos
pip install napalm-ios
``

Check the ['Supported Network Operating Systems'](http://napalm.readthedocs.io/en/latest/support/index.html) section for more information about supported modules.


Upgrading
---------

We plan to upgrade napalm as fast as possible. Adding new methods and bugfixes. To upgrade napalm it's a simple as repeating the steps you performed while installing but adding the `-U` flag. For example:

``
pip install napalm -U
``

or:

``
pip install napalm-eos napalm-junos -U
``

Dependencies
------------

Althought dependencies for the transport libraries are solved by `pip`, on some operating systems there are some particular requirements:

.. toctree::
   :maxdepth: 1

   junos
   iosxr
   ios
   panos
   pluribus
   vyos
