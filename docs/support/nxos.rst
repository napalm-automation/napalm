NXOS
----

Notes on configuration replacement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



Config files aren't aren't normal config files but special "checkpoint" files.
That's because on NXOS the only way to replace a config without reboot is to rollback to a checkpoint (which could be a file).
These files explicitly list a lot of normally implicit config lines, some of them starting with ``!#``.
The ``!#`` part isn't necessary for the rollback to work, but leaving these lines out can cause erratic behavior.
See the "Known gotchas" section below.

Prerequisites
_____________

Your device must be running NXOS 6.1. The features ``nxapi`` server ``scp-server`` must be enabled.
On the device and any checkpoint file you push, you must have the lines::

  feature scp-server
  feature nxapi


Getting a base checkpoint file
______________________________

An example of a checkpoint file can be seen in ``test/unit/nxos/new_good.conf``.
You can get a checkpoint file representing your device's current config by running the ``_get_checkpoint_file()``
function in the ``napalm.nxos`` driver::

  device.open()
  checkpoint = device._get_checkpoint_file()
  print(checkpoint)
  device.close()


Known gotchas
_____________

- Leaving out a ``shutdown`` or ``no shutdown`` line will cause the switch to toggle the up/down state of an interface, depending on it's current state.

- ``!#switchport trunk allowed vlan 1-4094`` is required even if the switchport is in ``switchport mode access``. However if ``!#switchport trunk allowed vlan 1-4094`` is included with ``no switchport``, the configuration replacement will fail.

- Vlans are listed vertically. For example ``vlan 1, 10, 20, 30`` will fail. To succeed, you need:
  ::

      vlan 1
      vlan 10
      vlan 20
      vlan 30

Diffs
_____

Diffs for config replacement are a list of commands that would be needed to take the device from it's current state
to the desired config state. See ``test/unit/nxos/new_good.diff`` as an example.

Notes on configuration merging
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Merges are currently implemented by simply applying the the merge config line by line.
This doesn't use the checkpoint/rollback functionality.
As a result, merges are **not atomic**.

Diffs
_____

Diffs for merges are simply the lines in the merge candidate config. `Netutils <https://netutils.readthedocs.io/en/latest/>`__ is used for creating the merge diff between the candidate and running configurations.
One caveat of using netutils diff of configurations is that the diff is performed offline and not online in the device.

Example assuming that the device config contains:

.. code-block::

    interface loopback0
      ip address 10.1.4.4/32
      ip router ospf 100 area 0.0.0.1

Then what you will get with the diff:

.. code-block:: python

    candidate_cfg = """
    interface loopback0
      ip address 10.1.4.5/32
      ip router ospf 100 area 0.0.0.1
    """

    nxos1.load_merge_candidate(config=candidate_cfg)

    print(nxos1.compare_config())
    interface loopback0
      ip address 10.1.4.5/32
