Command Line Tool
=================

NAPALM ships with a very simple cli tool so you can use napalm straight from the CLI. It's use is quite simple and you can see the help with ``--help``::

    $ napalm --help
    usage: napalm [-h] [--user USER] [--password PASSWORD] --vendor VENDOR
                  [--optional_args OPTIONAL_ARGS] [--debug]
                  hostname {configure,call,validate} ...

    Command line tool to handle configuration on devices using NAPALM.The script
    will print the diff on the screen

    positional arguments:
      hostname              Host where you want to deploy the configuration.

    optional arguments:
      -h, --help            show this help message and exit
      --user USER, -u USER  User for authenticating to the host. Default: user
                            running the script.
      --password PASSWORD, -p PASSWORD
                            Password for authenticating to the host.If you do not
                            provide a password in the CLI you will be prompted.
      --vendor VENDOR, -v VENDOR
                            Host Operating System.
      --optional_args OPTIONAL_ARGS, -o OPTIONAL_ARGS
                            String with comma separated key=value pairs passed via
                            optional_args to the driver.
      --debug               Enables debug mode; more verbosity.

    actions:
      {configure,call,validate}
        configure           Perform a configuration operation
        call                Call a napalm method
        validate            Validate configuration/state

    Automate all the things!!!

You can mostly do three things:

1. Configure the device (dry-run with diff supported)
2. Call any method (like ``get_interfaces`` or ``ping``)
3. Validate configuration/state

Let's see a few examples::

    # napalm --user vagrant --password vagrant --vendor eos --optional_args "port=12443" localhost configure new_config.txt --strategy merge --dry-run
    @@ -8,7 +8,7 @@
     !
     transceiver qsfp default-mode 4x10G
     !
    -hostname myhost
    +hostname a-new-hostname
     !
     spanning-tree mode mstp
     !
    @@ -20,6 +20,7 @@
     username vagrant privilege 15 role network-admin secret 5 $1$gxUZF/4Q$FoUvji7hq0HpJGxc67PJM0
     !
     interface Ethernet1
    +   description "TBD"
     !
     interface Ethernet2
     !
    $ napalm --user vagrant --password vagrant --vendor eos --optional_args "port=12443" localhost call get_interfaces
    {
        "Ethernet2": {
            "is_enabled": true,
            "description": "",
            "last_flapped": 1502731278.4344141,
            "is_up": true,
            "mac_address": "08:00:27:3D:83:34",
            "speed": 0
        },
        "Management1": {
            "is_enabled": true,
            "description": "",
            "last_flapped": 1502731294.598835,
            "is_up": true,
            "mac_address": "08:00:27:7D:44:C1",
            "speed": 1000
        },
        "Ethernet1": {
            "is_enabled": true,
            "description": "",
            "last_flapped": 1502731278.4342606,
            "is_up": true,
            "mac_address": "08:00:27:E6:4C:E9",
            "speed": 0
        }
    }
    $ napalm --user vagrant --password vagrant --vendor eos --optional_args "port=12443" localhost call ping --method-kwargs "destination='127.0.0.1'"
    {
        "success": {
            "packet_loss": 0,
            "rtt_stddev": 0.011,
            "rtt_min": 0.005,
            "results": [
                {
                    "rtt": 0.035,
                    "ip_address": "127.0.0.1"
                },
                {
                    "rtt": 0.008,
                    "ip_address": "127.0.0.1"
                },
                {
                    "rtt": 0.006,
                    "ip_address": "127.0.0.1"
                },
                {
                    "rtt": 0.005,
                    "ip_address": "127.0.0.1"
                },
                {
                    "rtt": 0.007,
                    "ip_address": "127.0.0.1"
                }
            ],
            "rtt_avg": 0.012,
            "rtt_max": 0.035,
            "probes_sent": 5
        }
    }
    $ napalm --user vagrant --password vagrant --vendor eos --optional_args "port=12443" localhost call cli --method-kwargs "commands=['show  version']"
    {
        "show  version": "Arista vEOS\nHardware version:    \nSerial number:       \nSystem MAC address:  0800.2761.b6ba\n\nSoftware image version: 4.15.2.1F\nArchitecture:           i386\nInternal build version: 4.15.2.1F-2759627.41521F\nInternal build ID:      8404cfa4-04c4-4008-838b-faf3f77ef6b8\n\nUptime:                 19 hours and 46 minutes\nTotal memory:           1897596 kB\nFree memory:            117196 kB\n\n"
    }


Debug Mode
----------

The debugging mode is also quite useful and it's recommended you use it to report and issue.::

    $ napalm --debug --user vagrant --password vagrant --vendor eos --optional_args "port=12443" localhost configure new_config.txt --strategy merge --dry-run
    2017-08-15 15:14:23,527 - napalm - DEBUG - Starting napalm's debugging tool
    2017-08-15 15:14:23,527 - napalm - DEBUG - Gathering napalm packages
    2017-08-15 15:14:23,541 - napalm - DEBUG - napalm-ansible==0.7.0
    2017-08-15 15:14:23,542 - napalm - DEBUG - napalm==2.0.0
    2017-08-15 15:14:23,542 - napalm - DEBUG - get_network_driver - Calling with args: ('eos',), {}
    2017-08-15 15:14:23,551 - napalm - DEBUG - get_network_driver - Successful
    2017-08-15 15:14:23,551 - napalm - DEBUG - __init__ - Calling with args: (<class 'napalm.eos.eos.EOSDriver'>, 'localhost', 'vagrant'), {'password': u'*******', 'optional_args': {u'port': 12443}, 'timeout': 60}
    2017-08-15 15:14:23,551 - napalm - DEBUG - __init__ - Successful
    2017-08-15 15:14:23,551 - napalm - DEBUG - pre_connection_tests - Calling with args: (<napalm.eos.eos.EOSDriver object at 0x105d58bd0>,), {}
    2017-08-15 15:14:23,551 - napalm - DEBUG - open - Calling with args: (<napalm.eos.eos.EOSDriver object at 0x105d58bd0>,), {}
    2017-08-15 15:14:23,586 - napalm - DEBUG - open - Successful
    2017-08-15 15:14:23,586 - napalm - DEBUG - connection_tests - Calling with args: (<napalm.eos.eos.EOSDriver object at 0x105d58bd0>,), {}
    2017-08-15 15:14:23,587 - napalm - DEBUG - get_facts - Calling with args: (<napalm.eos.eos.EOSDriver object at 0x105d58bd0>,), {}
    2017-08-15 15:14:23,622 - napalm - DEBUG - Gathered facts:
    {
        "os_version": "4.15.2.1F-2759627.41521F",
        "uptime": 71636,
        "interface_list": [
            "Ethernet1",
            "Ethernet2",
            "Management1"
        ],
        "vendor": "Arista",
        "serial_number": "",
        "model": "vEOS",
        "hostname": "myhost",
        "fqdn": "myhost"
    }
    {
        "os_version": "4.15.2.1F-2759627.41521F",
        "uptime": 71636,
        "interface_list": [
            "Ethernet1",
            "Ethernet2",
            "Management1"
        ],
        "vendor": "Arista",
        "serial_number": "",
        "model": "vEOS",
        "hostname": "myhost",
        "fqdn": "myhost"
    }
    2017-08-15 15:14:23,622 - napalm - DEBUG - get_facts - Successful
    2017-08-15 15:14:23,622 - napalm - DEBUG - load_merge_candidate - Calling with args: (<napalm.eos.eos.EOSDriver object at 0x105d58bd0>,), {'filename': 'new_config.txt'}
    2017-08-15 15:14:23,894 - napalm - ERROR - load_merge_candidate - Failed: Error [1000]: CLI command 3 of 5 'hostname a_new-hostname' failed: could not run command [ Host name is invalid. Host name must contain only alphanumeric characters, '.' and '-'.
    It must begin and end with an alphanumeric character.]

    ================= Traceback =================

    Traceback (most recent call last):
      File "/Users/dbarroso/.virtualenvs/napalm/bin/napalm", line 11, in <module>
        load_entry_point('napalm', 'console_scripts', 'napalm')()
      File "/Users/dbarroso/workspace/napalm/napalm/napalm.base/clitools/cl_napalm.py", line 285, in main
        run_tests(args)
      File "/Users/dbarroso/workspace/napalm/napalm/napalm.base/clitools/cl_napalm.py", line 270, in run_tests
        configuration_change(device, args.config_file, args.strategy, args.dry_run)
      File "/Users/dbarroso/workspace/napalm/napalm/napalm.base/clitools/cl_napalm.py", line 224, in configuration_change
        strategy_method(device, filename=config_file)
      File "/Users/dbarroso/workspace/napalm/napalm/napalm.base/clitools/cl_napalm.py", line 27, in wrapper
        r = func(*args, **kwargs)
      File "/Users/dbarroso/workspace/napalm/napalm/napalm.base/clitools/cl_napalm.py", line 202, in call_load_merge_candidate
        return device.load_merge_candidate(*args, **kwargs)
      File "/Users/dbarroso/workspace/napalm/napalm-eos/napalm.eos/eos.py", line 176, in load_merge_candidate
        self._load_config(filename, config, False)
      File "/Users/dbarroso/workspace/napalm/napalm-eos/napalm.eos/eos.py", line 168, in _load_config
        raise MergeConfigException(e.message)
    napalm.base.exceptions.MergeConfigException: Error [1000]: CLI command 3 of 5 'hostname a_new-hostname' failed: could not run command [ Host name is invalid. Host name must contain only alphanumeric characters, '.' and '-'.
    It must begin and end with an alphanumeric character.]
