Installation
============

Full installation
-----------------

You can install napalm with pip:

.. code-block:: bash

    pip install napalm

That will install all the core drivers currently available.

.. note::

    Beginning with release 4.0.0 and later, NAPALM offers support for Python
    3.7+ only.

.. note::

    Beginning with release 3.0.0 and later, NAPALM offers support for Python
    3.6+ only.


OS Package Managers
-------------------

Some execution environments offer napalm through a system-level package manager. Installing with pip outside of a user profile or virtualenv/venv is inadvisable in these cases.

FreeBSD
~~~~~~~

.. code-block:: bash

    pkg install net-mgmt/py-napalm

This will install napalm and all drivers and dependencies for the default version(s) of python. To install for a specific version, python X.Y, if supported:

.. code-block:: bash

    pkg install pyXY-napalm


Dependencies
------------

Although dependencies for the transport libraries are solved by ``pip``, on some operating systems there are some particular requirements:

.. toctree::
   :maxdepth: 1

   ios
   iosxr
   junos


.. _supported devices: ../support/index.html
