FortiOS
-------

Rollback
~~~~~~~~

To make sure the rollback feature works either use only this API to do changes or remember to save your rollback points on the CLI with the command::

    execute backup config flash your_message

Atomic Changes
~~~~~~~~~~~~~~

FortiOS' plugin will use the "batch" feature. All commands will not go at the same time but all of them will be processed. The sad true is that FortiOS doesn't have any proper tool to apply large chunks of configuration.

Known Issues
~~~~~~~~~~~~

Beginning in FortiOS version 5.2, a Fortigate bug was introduced that generates an `EOFError` in `paramiko/transport.py` during the SSH key exchange. Full details of the `paramiko` issue documented [here](https://github.com/paramiko/paramiko/issues/687#issuecomment-196577317). Current workaround is to edit the [preferred key exchange algorithms](https://github.com/paramiko/paramiko/blob/74ba0149347bfeb2f83ddd46672a2912aea51f23/paramiko/transport.py#L125-L130) in `paramiko/transport.py`. Either move `diffie-hellman-group1-sha1` below `diffie-hellman-group-exchange-sha1` or delete `diffie-hellman-group1-sha1`. 
