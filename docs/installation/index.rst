Installation
============


Full installation
-----------------

If you want to fully install NAPALM you can do it by executing:

.. code-block:: bash
    
    pip install napalm

That will install all the drivers currently available.


Partial Installation
--------------------

If you want to install just a subset of the available modules you can just pick them as follows:

.. code-block:: bash

    pip install --install-option="eos" --install-option="junos" napalm

That will install only the ``eos`` and the ``junos`` drivers. If you want to add an extra driver later you can use ``pip --force-reinstall -U`` to do it:

.. code-block:: bash

    pip install --install-option="ios" --force-reinstall -U napalm


Note you can pass those options to a requirements file as well:

.. code-block:: bash

    # requrements.txt
    napalm --install-option="ios" --install-option="eos"


Check the `supported devices`_ section for more information on supported drivers.

Dependencies
------------

Although dependencies for the transport libraries are solved by ``pip``, on some operating systems there are some particular requirements:

.. toctree::
   :maxdepth: 1

   ios
   iosxr
   junos


.. _supported devices: ../support/index.html
