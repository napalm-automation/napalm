EOS
---

Minimum Version
~~~~~~~~~~~~~~~

To be able to support the ``compare_config``, ``load_merge_candidate`` or ``load_replace_candidate`` methods you will require to run at least EOS version `4.15.0F`.

Multi-line/HEREDOC
~~~~~~~~~~~~~~~~~~
EOS configuration is loaded via ``pyeapi.eapilib.Node.run_commands()``, which by itself cannot handle multi-line commands
such as ``banner motd``.  The helper function ``EOSDriver._load_config()`` will attempt to detect HEREDOC commands in the
input configuration and convert them into a dictionary that eAPI understands

Rollback
~~~~~~~~

The rollback feature is supported only when committing from the API. In reality, what the API does during the commit operation is as follows::

    copy startup-config flash:rollback-0

And the rollback does::

    configure replace flash:rollback-0

This means that the rollback will be fine as long as you only use this library. If you are going to do changes outside this API don't forget to mark your last rollback point manually.
