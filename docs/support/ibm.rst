IBM Networking Operating System
-------------------------------

Rollback
~~~~~~~~

Rollback is simply implemented by reading current running configuration before any load actions. Rollback function executes load replace and commit.


Atomic Changes
~~~~~~~~~~~~~~

IBM plugin uses netconf to load configuration on to device. It seems that configuration is executed line by line but we can be sure that all lines will be executed. There are three options for error handling: stop-on-error, continue-on-error and rollback-on-error. Plugin uses rollback-on-error option in case of merge operation. However replace operation uses continue-on-error option. In case of typo in configuration, device will inform plugin about error but execute all the rest lines. Plugin will revert configuration using rollback function from the plugin. I do not use rollback-on-error for replace operation because in case of error device is left without any configuration. It seems like a bug. It will be investigated further. Moreover it seems that replace option wipe out whole configuration on device at the first step, so this option is good for provisioning of new device and it is not recommended for device in production.
