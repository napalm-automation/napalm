IOS
---


Prerequisites
_____________

IOS has no native API to play with, that's the reason why we used the Netmiko library to interact with it.
Having Netmiko installed in your working box is a prerequisite.

netmiko >= 1.4.1    (Check current napalm-ios/requirements.txt for latest Netmiko requirement)

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

IOSDriver requires that the `archive` functionality be enabled to perform auto-rollback on error. Make sure it's enabled and set to a local filesystem (for example 'flash:' or 'bootflash:'::

    archive
      path flash:archive
      write-memory


Configuration file
------------------

* IOS requires config file to begin with a `version` eg. `15.0` and `end` marker at the end of the file. Otherwise IOS will reject `configure replace` operation.
* For the diff to work properly, indentation of your candidate file has to exactly match the indentation in the running config.
* Finish blocks with `!` as with the running config, otherweise, some IOS version might not be able to generate the diff properly.


Banner
------------------

IOS requires that the banner use the EXT character (ASCII 3). This looks like a cntl-C in the file, but as a single character. It is NOT a separate '^' + 'C' character, but an ASCII3 character::

    banner motd ^C
        my banner test
    ^C

    >>> ext_char = chr(3)
    >>> with open("my_config.conf", "a") as f:
    ...   f.write("banner motd {}\n".format(ext_char))
    ...   f.write("my banner test\n")
    ...   f.write("{}\n".format(ext_char))
    ... 
    >>> quit()

Configure replace operations will reject a file with a banner unless it uses the ASCII character. Note, this likely also implies you cannot just copy-and-paste what you see on the screen.

In vim insert, you can also type <ctrl>+V, release only the V, then type C



Notes
_______

* Will automatically enable secure copy ('ip scp server enable') on the network device. This is a configuration change.

* During various operations, NAPALM ios driver will turn off the prompting for confirmations (`file prompt quiet`). It should re-enable prompting before exiting the device (`no file prompt quiet`).

* The NAPALM-ios driver supports all Netmiko arguments as either standard arguments (hostname, username, password, timeout) or as optional_args (everything else).  

