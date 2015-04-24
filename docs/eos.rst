EOS
----

Rollback
~~~~~~~~

The rollback feature is supported only when committing from the API. In reality, what the API does during the commit operation is as follows::

    copy startup-config flash:rollback-0

And the rollback does::

    configure replace flash:rollback-0

This means that the rollback will be fine as long as you only use this library. If you are going to do changes outside this API don't forget to mark your last rollback point manually.
