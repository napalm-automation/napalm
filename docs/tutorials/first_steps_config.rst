First Steps Manipulating Config
===============================

NAPALM tries to provide a common interface and mechanisms to push configuration and retrieve state data from network devices. This method is very useful in combination with tools like `Ansible <http://www.ansible.com>`_, which in turn allows you to manage a set of devices independent of their network OS.

Connecting to the Device
------------------------

Use the appropriate network driver to connect to the device::

    >>> from napalm import get_network_driver
    >>> driver = get_network_driver('eos')
    >>> device = driver('192.168.76.10', 'dbarroso', 'this_is_not_a_secure_password')
    >>> device.open()

Configurations can be replaced entirely or merged into the existing device config.
You can load configuration either from a string or from a file.

Replacing the Configuration
---------------------------

To replace the configuration do the following::

    >>> device.load_replace_candidate(filename='test/unit/eos/new_good.conf')

Note that the changes have not been applied yet. Before applying the configuration you can check the changes::

    >>> print device.compare_config()
    + hostname pyeos-unittest-changed
    - hostname pyeos-unittest
    router bgp 65000
       vrf test
         + neighbor 1.1.1.2 maximum-routes 12000
         + neighbor 1.1.1.2 remote-as 1
         - neighbor 1.1.1.1 remote-as 1
         - neighbor 1.1.1.1 maximum-routes 12000
       vrf test2
         + neighbor 2.2.2.3 remote-as 2
         + neighbor 2.2.2.3 maximum-routes 12000
         - neighbor 2.2.2.2 remote-as 2
         - neighbor 2.2.2.2 maximum-routes 12000
    interface Ethernet2
    + description ble
    - description bla

If you are happy with the changes you can commit them::

    >>> device.commit_config()

On the contrary, if you don't want the changes you can discard them::

    >>> device.discard_config()

Merging Configuration
---------------------

Merging configuration is similar, but you need to load the configuration with the merge method::

    >>> device.load_merge_candidate(config='hostname test\ninterface Ethernet2\ndescription bla')
    >>> print device.compare_config()
    configure
    hostname test
    interface Ethernet2
    description bla
    end

If you are happy with the changes you can commit them::

    >>> device.commit_config()

On the contrary, if you don't want the changes you can discard them::

    >>> device.discard_config()

Rollback Changes
----------------

If for some reason you committed the changes and you want to rollback::

    >>> device.rollback()

Commit confirmed (auto rollback)
--------------------------------

If you are operating on remote devices without out of band network access and/or there is a risk that you could lose access to your device after commit, you can use commit confirmed functionality. You have to provide an additional argument (confirmed) to commit_config() method. It defines how long (in minutes) device will wait for your confirmation. You can confirm the change by executing commit_confirm(). A device will rollback changes by itself if confirmation is not sent or confirmation message can not reach the device. For example, device will wait 5 minutes for confirmation, after that changes will be reverted::

    >>> device.commit_config(confirmed=5)
    >>> device.commit_confirm()

.. note:: Not all devices support commit confirmed functionality. It may be dependent on device capabilities and/or support for commit confirmed inside particular napalm driver.

Disconnecting
-------------

To close the session with the device just do::

    >>> device.close()
