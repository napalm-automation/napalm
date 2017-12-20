Recording and Replaying executions
==================================

NAPALM can record a session and replay it later on. This is interesting for building test cases or writing reproducible tutorials.

To record a session you only have to set the appropriate ``optional_args``::

    eos_configuration = {
        'hostname': '127.0.0.1',
        'username': 'vagrant',
        'password': 'vagrant',
        'optional_args': {'port': 12443,
                          'recorder_mode': "record",            # this
                          'recorder_path': "./test_recorder"}   # and this
    }

    eos = get_network_driver("eos")
    d = eos(**eos_configuration)

    d.open()
    pprint.pprint(d.get_facts())
    pprint.pprint(d.get_interfaces())
    pprint.pprint(d.cli(["show version"]))

    pprint.pprint(d.cli(["wrong command"]))


The code above is basically going to run as usual but it's going to also generate a bunch of files::

    ➜  napalm git:(recorder) ✗ ls test_recorder
    metadata.yaml       run_commands.1.yaml run_commands.2.yaml run_commands.3.yaml run_commands.4.yaml run_commands.5.yaml

    ➜  napalm git:(recorder) ✗ cat test_recorder/run_commands.4.yaml
    call:
      args:
      - - show version
      func: run_commands
      kwargs:
        encoding: text
    result:
    - output: "Arista vEOS\nHardware version:    \nSerial number:       \nSystem MAC address:
        \ 0800.27b6.7499\n\nSoftware image version: 4.15.2.1F\nArchitecture:           i386\nInternal
        build version: 4.15.2.1F-2759627.41521F\nInternal build ID:      8404cfa4-04c4-4008-838b-faf3f77ef6b8\n\nUptime:
        \                57 minutes\nTotal memory:           1897596 kB\nFree memory:
        \           115320 kB\n\n"
    ➜  napalm git:(recorder) ✗ cat test_recorder/run_commands.5.yaml
    call:
      args:
      - - wrong command
      func: run_commands
      kwargs:
        encoding: text
    result: !pyeapiCommandError;1
      code: 1002
      kwargs:
        command_error: 'Invalid input (at token 0: ''wrong'')'
        commands:
        - enable
        - wrong command
        output:
        - output: ''
        - errors:
          - 'Invalid input (at token 0: ''wrong'')'
          output: '% Invalid input (at token 0: ''wrong'')

    '
      message: 'CLI command 2 of 2 ''wrong command'' failed: invalid command'

In this case this is an EOS devices which means we are using ``pyeapi`` to interact with the devices. As you can see you can inspect the contents of the generated files and see what calls where made to ``pyeapi`` and what information was returned. Errors are also properly stored.

If you want to replay that script without requiring a device it is as simple as just setting again the appropriate ``optional_args``::

    (napalm) ➜  napalm git:(recorder) ✗ python
    Python 3.6.3 (default, Oct  4 2017, 06:09:15)
    [GCC 4.2.1 Compatible Apple LLVM 9.0.0 (clang-900.0.37)] on darwin
    Type "help", "copyright", "credits" or "license" for more information.
    >>> from napalm import get_network_driver
    >>> import pprint
    >>>
    >>> eos_configuration = {
    ...     'hostname': '127.0.0.1',
    ...     'username': 'fake',
    ...     'password': 'wrong',
    ...     'optional_args': {'port': 123,
    ...                       'recorder_mode': "replay",            # this
    ...                       'recorder_path': "./test_recorder"}   # and this
    ... }
    >>> eos = get_network_driver("eos")
    >>> d = eos(**eos_configuration)
    >>>
    >>> d.open()
    >>> pprint.pprint(d.get_facts())
    {'fqdn': 'localhost',
     'hostname': 'localhost',
     'interface_list': ['Ethernet1', 'Ethernet2', 'Management1'],
     'model': 'vEOS',
     'os_version': '4.15.2.1F-2759627.41521F',
     'serial_number': '',
     'uptime': 436623,
     'vendor': 'Arista'}
    >>> pprint.pprint(d.get_interfaces())
    {'Ethernet1': {'description': '',
                   'is_enabled': True,
                   'is_up': True,
                   'last_flapped': 1513349248.876508,
                   'mac_address': '08:00:27:12:84:6F',
                   'speed': 0},
     'Ethernet2': {'description': '',
                   'is_enabled': True,
                   'is_up': True,
                   'last_flapped': 1513349248.8766859,
                   'mac_address': '08:00:27:2E:C6:C7',
                   'speed': 0},
     'Management1': {'description': '',
                     'is_enabled': True,
                     'is_up': True,
                     'last_flapped': 1513349263.057069,
                     'mac_address': '08:00:27:7D:44:C1',
                     'speed': 1000}}
    >>> pprint.pprint(d.cli(["show version"]))
    {'show version': 'Arista vEOS\n'
                     'Hardware version:    \n'
                     'Serial number:       \n'
                     'System MAC address:  0800.27b6.7499\n'
                     '\n'
                     'Software image version: 4.15.2.1F\n'
                     'Architecture:           i386\n'
                     'Internal build version: 4.15.2.1F-2759627.41521F\n'
                     'Internal build ID:      '
                     '8404cfa4-04c4-4008-838b-faf3f77ef6b8\n'
                     '\n'
                     'Uptime:                 57 minutes\n'
                     'Total memory:           1897596 kB\n'
                     'Free memory:            115320 kB\n'
                     '\n'}
    >>> pprint.pprint(d.cli(["wrong command"]))
    Traceback (most recent call last):
      File "/Users/dbarroso/workspace/napalm/napalm/napalm/eos/eos.py", line 642, in cli
        [command], encoding='text')[0].get('output')
      File "/Users/dbarroso/workspace/napalm/napalm/napalm/base/recorder.py", line 58, in wrapper
        return replay(cls, func, *args, **kwargs)
      File "/Users/dbarroso/workspace/napalm/napalm/napalm/base/recorder.py", line 102, in replay
        raise data["result"]
    pyeapi.eapilib.CommandError: Error [1002]: CLI command 2 of 2 'wrong command' failed: invalid command [Invalid input (at token 0: 'wrong')]

    During handling of the above exception, another exception occurred:

    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "/Users/dbarroso/workspace/napalm/napalm/napalm/eos/eos.py", line 650, in cli
        raise CommandErrorException(str(cli_output))
    napalm.base.exceptions.CommandErrorException: {'wrong command': 'Invalid command: "wrong command"'}

As you can see even the error is reproduced :)
