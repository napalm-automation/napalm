IOS
---


Prerequisites
_____________

IOS has no native API to play with, that's the reason why we used the Netmiko library to interact with it.
Having Netmiko installed in your working box is a prerequisite.

netmiko >= 0.3.0

Full ios driver support requires configuration rollback on error::

    Cisco IOS requirements for 'Configuration Rollback Confirmed Change' feature.
    12.2(33)SRC
    12.2(33)SB
    12.4(20)T
    12.2(33)SXI


Downgraded ios driver support (i.e. no auto rollback on configuration error for replace operation)::

    Cisco IOS requirements for 'Configuration Replace and Configuration Rollback' feature.
    12.3(7)T
    12.2(25)S
    12.3(14)T
    12.2(27)SBC
    12.2(31)SB2
    12.2(33)SRA
    12.2(33)SXH
    12.2(33)SB


Note, to disable auto rollback you must add the `auto_rollback_on_error=False` optional argument.



Archive
_______

IOSDriver requires that the `archive` functionality be enabled to perform auto-rollback on error. Make sure it's enabled and set to local on device flash/hdd::

    archive
      path bootflash:archive
      write-memory


Configuration file
------------------

IOS requires config file to begin with a `version` eg. `15.0` and `end` marker at the end of the file. Otherwise IOS will reject `configure replace` operation.


Notes
_______

* Will automatically enable secure copy ('ip scp server enable') on the network device. This is a configuration change.

* During various operations, NAPALM ios driver will turn off the prompting for confirmations (`file prompt quiet`). It should re-enable prompting before exiting the device (`no file prompt quiet`).

* `write mem` is not performed on the device. Consequently, commit() commits the config to running-config, but does not save it to start-config.

