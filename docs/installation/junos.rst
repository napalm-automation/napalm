napalm-junos dependencies
=========================


Ubuntu and Debian
-----------------

.. code-block:: bash

    sudo apt-get install -y --force-yes libxslt1-dev libssl-dev libffi-dev python-dev python-cffi

RedHat and CentOS
-----------------

.. code-block:: bash

    sudo yum install -y python-pip python-devel libxml2-devel libxslt-devel gcc openssl openssl-devel libffi-devel

FreeBSD
-------

.. code-block:: bash

    sudo pkg_add -r py27-pip libxml2 libxslt
