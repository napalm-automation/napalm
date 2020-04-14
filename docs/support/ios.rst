IOS
---


Prerequisites
_____________

IOS has no native API to play with, that's the reason why we used the Netmiko library to interact with it.
Having Netmiko installed in your working box is a prerequisite.

Check napalm-ios/requirements.txt for Netmiko version requirement

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
__________________

* IOS requires config file to begin with a `version` eg. `15.0` and `end` marker at the end of the file. Otherwise IOS will reject `configure replace` operation.
* For the diff to work properly, indentation of your candidate file has to exactly match the indentation in the running config.
* Finish blocks with `!` as with the running config, otherwise, some IOS version might not be able to generate the diff properly.


Self-Signed Certificate (and the hidden tab character)
______________________________________________________

Cisco IOS adds a tab character into the self-signed certificate. This exists on the quit line::

    crypto pki certificate chain TP-self-signed-1429897839
     certificate self-signed 01
      3082022B 30820194 A0030201 02020101 300D0609 2A864886 F70D0101 05050030
      ...
      ...
      ...
      9353BD17 C345E1D7 71AFD125 D23D7940 2DECBE8E 46553314 396ACC63 34839EF7
      3C056A00 7E129168 F0CD3692 F53C62
      	quit

The quit line reads as follows::

    >>> for char in line:
    ...   print("{}: {}".format(repr(char), ord(char)))
    ...
    ' ': 32     # space
    ' ': 32     # space
    '\t': 9     # tab
    'q': 113
    'u': 117
    'i': 105
    't': 116
    '\n': 10

This implies that you will not generally be able to copy-and-paste the self-signed certificate. As when you copy-and-paste it, the tab character gets converted to spaces.

You will need to transfer the config file directly from the device (for example, SCP the config file) or you will need to manually construct the quit line exactly right.

Cisco IOS is very particular about the self-signed certificate and will reject replace operations with an invalid certificate. Cisco IOS will also reject replace operations that are missing a certificate (when the current configuration has a self-signed certificate).


Banner
______

IOS requires that the banner use the ETX character (ASCII 3). This looks like a cntl-C in the file, but as a single character. It is NOT a separate '^' + 'C' character, but an ASCII3 character::

    banner motd ^C
        my banner test
    ^C

    >>> etx_char = chr(3)
    >>> with open("my_config.conf", "a") as f:
    ...   f.write("banner motd {}\n".format(etx_char))
    ...   f.write("my banner test\n")
    ...   f.write("{}\n".format(etx_char))
    ...
    >>> quit()

Configure replace operations will reject a file with a banner unless it uses the ASCII character. Note, this likely also implies you cannot just copy-and-paste what you see on the screen.

In vim insert, you can also type <ctrl>+V, release only the V, then type C


File Operation Prompts
______________________

By default IOS will prompt for confirmation on file operations. These prompts need to be disabled before the NAPALM-ios driver performs any such operation on the device.
This can be controlled using the `auto_file_prompt` optional arguement:

* `auto_file_prompt=True` (default): NAPALM will automatically add `file prompt quiet` to the device configuration before performing file operations,
  and un-configure it again afterwards. If the device already had the command in its configuration then it will be silently removed as a result, and
  this change will not show up in the output of `compare_config()`.

* `auto_file_prompt=False`: Disable the above automated behaviour. The managed device must have `file prompt quiet` in its running-config already,
  otherwise a `CommandErrorException` will be raised when file operations are attempted.

SCP File Transfers
__________________

The NAPALM-ios driver requires SCP to be enabled on the managed device. SCP
server functionality is disabled in IOS by default, and is configured using
`ip scp server enable`.

If an operation requiring a file transfer is attempted, but the necessary
configuration is not present, a `CommandErrorException` will be raised.

Notes
_____

* The NAPALM-ios driver supports all Netmiko arguments as either standard arguments (hostname, username, password, timeout) or as optional_args (everything else).
