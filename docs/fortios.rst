FortiOS
-------

Rollback
~~~~~~~~

To make sure the rollback feature works either use only this API to do changes or remember to save your rollback points on the CLI with the command::

    execute backup config flash your_message

Atomic Changes
~~~~~~~~~~~~~~

FortiOS' plugin will use the "batch" feature. All commands will not go at the same time but all of them will be processed. The sad true is that FortiOS doesn't have any proper tool to apply large chunks of configuration.