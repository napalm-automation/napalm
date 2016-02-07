Command Line Tool
=================

NAPALM ships with a simple CLI tool to help you deploying configuration to your devices directly from the shell.
It might be convenient for simple bash scripts or provisioning tools that rely on a shell.

The usage is very simple. For example, let's do a dry run (changes will not be applied) and check the changes between
my current configuration and a new candidate configuration:

.. code-block:: diff

    # cl_napalm_configure --user vagrant --vendor eos --strategy replace --optional_args 'port=12443' --dry-run new_good.conf localhost
    Enter password:
    @@ -2,30 +2,38 @@
     !
     ! boot system flash:/vEOS-lab.swi
     !
    -event-handler dhclient
    -   trigger on-boot
    -   action bash sudo /mnt/flash/initialize_ma1.sh
    +transceiver qsfp default-mode 4x10G
     !
    -transceiver qsfp default-mode 4x10G
    +hostname pyeos-unittest-changed
     !
     spanning-tree mode mstp
     !
     aaa authorization exec default local
     !
    -aaa root secret 5 $1$b4KXboe4$yeTwqHOKscsF07WGoOnZ0.
    +no aaa root
     !
    -username admin privilege 15 role network-admin secret 5 $1$nT3t1LkI$1f.SG5YaRo6h4LlhIKgTK.
    -username vagrant privilege 15 role network-admin secret 5 $1$589CDTZ0$9S4LGAiCpxHCOC17jECxt1
    +username admin privilege 15 role network-admin secret 5 $1$RT/92Zg9$J8wD1qPAdQBcOhv4fefyt.
    +username vagrant privilege 15 role network-admin secret 5 $1$Lw2STh4k$bPEDVVTY2e7lf.vNlnNEO0
     !
     interface Ethernet1
     !
     interface Ethernet2
    +   description ble
     !
     interface Management1
        ip address 10.0.2.15/24
     !
     no ip routing
     !
    +router bgp 65000
    +   vrf test
    +      neighbor 1.1.1.2 remote-as 1
    +      neighbor 1.1.1.2 maximum-routes 12000
    +   !
    +   vrf test2
    +      neighbor 2.2.2.3 remote-as 2
    +      neighbor 2.2.2.3 maximum-routes 12000
    +!
     management api http-commands
        no shutdown
     !
    #

We got the diff back. Now let's try a partial configuration instead. However, this time we will directly apply the
configuration and we will also be passing the password directly as an argument:

.. code-block:: diff

    # cl_napalm_configure --user vagrant --password vagrant --vendor eos --strategy merge --optional_args 'port=12443' merge_good.conf localhost
    @@ -7,6 +7,8 @@
        action bash sudo /mnt/flash/initialize_ma1.sh
     !
     transceiver qsfp default-mode 4x10G
    +!
    +hostname NEWHOSTNAME
     !
     spanning-tree mode mstp
     !
    @@ -20,6 +22,7 @@
     interface Ethernet1
     !
     interface Ethernet2
    +   description BLALALAL
     !
     interface Management1
        ip address 10.0.2.15/24
    #

We got the diff back in the stdout. If we try to run the command we should get an empty string:

.. code-block:: diff

    # cl_napalm_configure --user vagrant --password vagrant --vendor eos --strategy merge --optional_args 'port=12443' merge_good.conf localhost
    #

Errors are detected as well::

    # cl_napalm_configure --user vagrant --password vagrant --vendor eos --strategy merge --optional_args 'port=12443' merge_typo.conf localhost
    Traceback (most recent call last):
      File "/Users/dbarroso/.virtualenvs/test/bin/cl_napalm_configure", line 9, in <module>
        load_entry_point('napalm==0.50.3', 'console_scripts', 'cl_napalm_configure')()
      File "/Users/dbarroso/.virtualenvs/test/lib/python2.7/site-packages/napalm-0.50.3-py2.7.egg/napalm/clitools/cl_napalm_configure.py", line 139, in main
        args.optional_args, args.config_file, args.dry_run))
      File "/Users/dbarroso/.virtualenvs/test/lib/python2.7/site-packages/napalm-0.50.3-py2.7.egg/napalm/clitools/cl_napalm_configure.py", line 131, in run
        return diff
      File "/Users/dbarroso/.virtualenvs/test/lib/python2.7/site-packages/napalm-0.50.3-py2.7.egg/napalm/base.py", line 46, in __exit__
        self.__raise_clean_exception(exc_type, exc_value, exc_traceback)
      File "/Users/dbarroso/.virtualenvs/test/lib/python2.7/site-packages/napalm-0.50.3-py2.7.egg/napalm/clitools/cl_napalm_configure.py", line 119, in run
        strategy_method(filename=config_file)
      File "/Users/dbarroso/.virtualenvs/test/lib/python2.7/site-packages/napalm-0.50.3-py2.7.egg/napalm/eos.py", line 95, in load_merge_candidate
        self._load_config(filename, config, False)
      File "/Users/dbarroso/.virtualenvs/test/lib/python2.7/site-packages/napalm-0.50.3-py2.7.egg/napalm/eos.py", line 89, in _load_config
        raise MergeConfigException(e.message)
    napalm.exceptions.MergeConfigException: Error [1002]: CLI command 5 of 5 'descriptin BLALALAL' failed: invalid command

For more information, run ``cl_napalm_configure --help``.
