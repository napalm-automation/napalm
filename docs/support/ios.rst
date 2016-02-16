IOS
---


Prerequisites
_____________

IOS has no native API to play with, that's the reason why we used the Netmiko library to interact with it.
Having Netmiko installed in your working box is a prerequisite.

Archive
_______

IOSDriver relies on the 'archive' functionality to be able to manipulate configuration, make sure it's enabled::

    archive
      path bootflash:archive
      write-memory
