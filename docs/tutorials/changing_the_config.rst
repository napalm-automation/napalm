Changing the Configuration
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

    >>> print(device.compare_config())
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
    >>> print(device.compare_config())
    configure
    hostname test
    interface Ethernet2
    description bla
    end

If you are happy with the changes you can commit them::

    >>> device.commit_config()

On the contrary, if you don't want the changes you can discard them::

    >>> device.discard_config()

Committing the Configuration with a Required Confirmation
---------------------------------------------------------

For certain platforms, you can also commit the configuration and set a revert timer. If you do not confirm the commit, by executing confirm_commit(), before the revert timer expires, then the configuration will be automatically rolled back to its previous state (and the candidate configuration will be discarded)::

    # Load new candidate config
    >>> device.load_replace_candidate(filename=filename)

    # Look at the pending changes
    >>> print(device.compare_config())
    @@ -5,6 +5,8 @@
    transceiver qsfp default-mode 4x10G
    !
    hostname arista9-napalm
    +!
    +ntp server 130.126.24.24
    !
    spanning-tree mode rapid-pvst
    !

    # Commit the changes with a 300 second revert timer.
    device.commit_config(revert_in=300)

    # You can now use the has_pending_commit() method to check for an in-process commit-confirm
    >>> device.has_pending_commit()                                                                              
    True

    # To confirm the commit (i.e. ensure the change is permanently committed).
    >>> device.confirm_commit()

    # At this point there should be no pending commits.
    >>> device.has_pending_commit()
    False

Immediately Canceling a Pending Commit-Confirm
----------------------------------------------

Alternatively, to immediately cancel a pending commit_config with the revert timer set, you can execute the rollback() method::

    >>> device.load_replace_candidate(filename=filename)
    >>> device.commit_config(revert_in=300)
    >>> device.has_pending_commit()
    True
    
    >>> device.rollback()
    >>> device.has_pending_commit()
    False 

    # At this point, our change would have been rolled-back (the change in this case added an 'ntp server').
    >>> output = device.get_config()["running"]
    >>> "ntp" in output
    False

Allowing the Revert Timer to Expire
-----------------------------------

Finally, you can cancel a pending commit-confirm by letting the revert timer expire::

    >>> device.load_replace_candidate(filename=filename)
    >>> device.commit_config(revert_in=60)
    >>> device.has_pending_commit()
    True

    # Sleeping 80 seconds
    >>> time.sleep(80)

    # The device has automatically rolled-back the config to its previous state.
    >>> device.has_pending_commit()                                                                                     
    False

Rollback Changes
----------------

If for some reason you committed the changes and you want to rollback::

    >>> device.rollback()

Disconnecting
-------------

To close the session with the device just do::

    >>> device.close()
