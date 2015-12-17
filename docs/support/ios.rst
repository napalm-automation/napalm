IOS
---


Prerequisites
_____________

IOS has no native API to play with, that's the reason why we used the Netmiko library to interact with it.
Having Netmiko installed in your working box is a prerequisite.

Notes on configuration comparing
________________________________

Using the ``compare_config()`` method, we'll have in return a list of commands that will be merged with the current configuration. 
Since no configuration replacement's been implremented, this is the only comparison we can obtain.

Notes on configuration merging
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Merges are currently implemented by simply applying the the merge config line by line.
As a result, merges are **not atomic**.

Notes on configuration rollback
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There is no magic here. Since IOS doesn't support any checkpoint config, what we can do is removing all the commands from the previous commit.
The 'no' keyword will be added to each command and it will be sent again. The system is smart enough to understand parent/child commands.

Anyway, there might be some problems with commands like **description abc 123** since the command to remove would be **no description** but the system
would send **no description abc 123** instead.


