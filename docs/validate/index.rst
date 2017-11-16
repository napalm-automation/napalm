Validating deployments
======================

Let's say you just deployed a few devices and you want to validate your deployment. To do that, you
can write a YAML file describing the state you expect your devices to be in and tell napalm to
retrieve the state of the device and build a compliance report for you.

As always, with napalm, doing this is very easy even across multiple vendors : )

.. note:: Note that this is meant to validate **state**, meaning live data from the device, not
    the configuration. Because that something is configured doesn't mean it looks as you want.


Documentation
-------------

Writing validators files that can be interpreted by napalm is very easy. You have to start by
telling napalm how to retrieve that piece of information by using as key the name of the getter and
then write the desired state using the same format the getter would retrieve it. For example::

    ---
    - get_facts:
        os_version: 7.0(3)I2(2d)
        interface_list:
          _mode: strict
          list:
            - Vlan5
            - Vlan100
        hostname: n9k2

    - get_environment:
        memory:
          used_ram: '<15.0'
        cpu:
          0/RP0/CPU0
            '%usage': '<15.0'

    - get_bgp_neighbors:
        default:
          router_id: 192.0.2.2
          peers:
            _mode: strict
            192.0.2.2:
              is_enabled: true
              address_family:
                ipv4:
                  sent_prefixes: 5
                  received_prefixes: '<10'
                ipv6:
                  sent_prefixes: 2
                  received_prefixes: '<5'

    - get_interfaces_ip:
        Ethernet2/1:
          ipv4:
            192.0.2.1:
              prefix_length: 30
    
    - ping:
        _name: ping_google
        _kwargs:
          destination: 8.8.8.8
          source: 192.168.1.1
        success:
          packet_loss: 0
        _mode: strict
    
    - ping:
        _name: something_else
        _kwargs:
          destination: 10.8.2.8
          source: 192.168.1.1
        success:
          packet_loss: 0
        _mode: strict


A few notes:

    * You don't have to validate the entire state of the device, you might want to validate certain
      information only. For example, with the getter ``get_interfaces_ip`` we are only validating
      that the interface ``Ethernet2/1`` has the IP address ``192.0.2.1/30``. If there are other
      interfaces or if that same interface has more IP's, it's ok.
    * You can also have a more strict validation. For example, if we go to ``get_bgp_neighbors``,
      we want to validate there that the ``default`` vrf has *only* the BGP neighbor ``192.0.2.2``.
      We do that by specifying at that level ``_mode: strict``. Note that the strict mode is
      specific to a level (you can add it to as many levels as you want). So, going back the the
      example, we are validating that only that BGP neighbor is present on that vrf but we are not
      validating that other vrfs don't exist. We are not validating all the data inside the BGP
      neighbor either, we are only validating the ones we specified.
    * Lists of objects to be validated require an extra key ``list``. You can see an example with
      the ``get_facts`` getter. Lists can be strict as well. In this case, we want to make sure the
      device has only those two interfaces.
    * We can also use comparison on the conditions of numerical validate. For example, if you want 
      to validate there that the ``cpu``and ``memory`` into ``get_environment`` are ``15%`` or less.
      We can use writing comparison operators such as ``<15.0`` or ``>10.0`` in this case.
    * Some methods require extra arguments, for example ``ping``. You can pass arguments to those
      methods using the magic keyword ``_kwargs``. In addition, an optional keyword ``_name`` can
      be specified to override the name in the report. Useful for having a more descriptive report
      or for getters than can be run multiple times

Example
-------

Let's say we have two devices, one running ``eos`` and another one running ``junos``. A typical
script could start like this::

    from napalm import get_network_driver
    import pprint
    
    eos_driver = get_network_driver("eos")
    eos_config = {
        "hostname": "localhost",
        "username": "vagrant",
        "password": "vagrant",
        "optional_args": {"port": 12443},
    }
    
    junos_driver = get_network_driver("junos")
    junos_config = {
        "hostname": "localhost",
        "username": "vagrant",
        "password": "",
        "optional_args": {"port": 12203},
    }

Now, let's validate that the devices are running a specific version and that the management IP is
the one we expect. Let's start by writing the validator files.

 * ``validate-eos.yml``::

    ---
    - get_facts:
        os_version: 4.17
    
    - get_interfaces_ip:
        Management1:
            ipv4:
                10.0.2.14:
                    prefix_length: 24
                _mode: strict

 * ``validate-junos.yml``::

    ---
    - get_facts:
        os_version: 12.1X47
    
    - get_interfaces_ip:
        ge-0/0/0.0:
            ipv4:
                10.0.2.15:
                    prefix_length: 24
                _mode: strict

.. note:: You can use regular expressions to validate values.

As you can see we are validating that the OS running is the one we want and that the management
interfaces have only the IP we expect it to have. Now we can validate the devices like this::

    >>> with eos_driver(**eos_config) as eos:
    ...     pprint.pprint(eos.compliance_report("validate-eos.yml"))
    ...
    {u'complies': False,
     u'skipped': [],
     'get_facts': {u'complies': False,
                   u'extra': [],
                   u'missing': [],
                   u'present': {'os_version': {u'actual_value': u'4.15.2.1F-2759627.41521F',
                                               u'complies': False,
                                               u'nested': False}}},
     'get_interfaces_ip': {u'complies': True,
                           u'extra': [],
                           u'missing': [],
                           u'present': {'Management1': {u'complies': True,
                                                        u'nested': True}}}}

Let's take a look first to the report. The first thing we have to note is the first key
``complies`` which is telling us that overall, the device is not compliant. Now we can dig in on
the rest of the report. The ``get_interfaces_ip`` part seems to be complying just fine, however,
the ``get_facts`` is complaining about something. If we keep digging we will see that the
``os_version`` key we were looking for is present but it's not complying as its actual value
is not the one we specified; it is ``4.15.2.1F-2759627.41521F``.

Now let's do the same for junos::

    >>> with junos_driver(**junos_config) as junos:
    ...     pprint.pprint(junos.compliance_report("validate-junos.yml"))
    ...
    {u'complies': True,
     u'skipped': [],
     'get_facts': {u'complies': True,
                   u'extra': [],
                   u'missing': [],
                   u'present': {'os_version': {u'complies': True,
                                               u'nested': False}}},
     'get_interfaces_ip': {u'complies': True,
                           u'extra': [],
                           u'missing': [],
                           u'present': {'ge-0/0/0.0': {u'complies': True,
                                                       u'nested': True}}}}

This is great, this device is fully compliant. We can check the outer ``complies`` key is set to
``True``. However, let's see what happens if someone adds and extra IP to ``ge-0/0/0.0``::

    >>> with junos_driver(**junos_config) as junos:
    ...     pprint.pprint(junos.compliance_report("validate-junos.yml"))
    ...
    {u'complies': False,
     u'skipped': [],
     'get_facts': {u'complies': True,
                   u'extra': [],
                   u'missing': [],
                   u'present': {'os_version': {u'complies': True,
                                               u'nested': False}}},
     'get_interfaces_ip': {u'complies': False,
                           u'extra': [],
                           u'missing': [],
                           u'present': {'ge-0/0/0.0': {u'complies': False,
                                                       u'diff': {u'complies': False,
                                                                 u'extra': [],
                                                                 u'missing': [],
                                                                 u'present': {'ipv4': {u'complies': False,
                                                                                       u'diff': {u'complies': False,
                                                                                                 u'extra': [u'172.20.0.1'],
                                                                                                 u'missing': [],
                                                                                                 u'present': {'10.0.2.15': {u'complies': True,
                                                                                                                            u'nested': True}}},
                                                                                       u'nested': True}}},
                                                       u'nested': True}}}}

After adding the extra IP it seems the device is not compliant anymore. Let's see what happened:

* Outer ``complies`` key is telling us something is wrong.
* ``get_facts`` is fine.
* ``get_interfaces_ip`` is telling us something interesting. Note that is saying that
  ``ge-0/0/0.0`` has indeed the IPv4 address ``10.0.2.15`` as noted by being ``present`` and with
  the inner ``complies`` set to ``True``. However, it's telling us that there is an ``extra`` IP
  ``172.20.0.1``.

The output might be a bit complex for humans but it's predictable and very easy to parse so it's
great if you want to integrate it with your documentation/reports by using simple ``jinja2``
templates.

Skipped tasks
_____________

In cases where a method is not implemented, the validation will be skipped and the result will not count towards the result. The report will let you know a method wasn't executed in the following manner::

    ...
    "skipped": [ "method_not_implemented", ],
    "method_not_implemented": {
        "reason": "NotImplemented",
        "skipped": True,
        }
    ...

``skipped`` will report the list of methods that were skipped. For details about the reason you can dig into the method's report.

CLI & Ansible
-------------

If you prefer, you can also make use of the validate functionality via the CLI with the command ``cl_napalm_validate`` or with ansible plugin. You can find more information about them here:

* CLI - https://github.com/napalm-automation/napalm/pull/168
* Ansible - https://github.com/napalm-automation/napalm-ansible/blob/master/library/napalm_validate.py


Why this and what's next
------------------------

As mentioned in the introduction, this is interesting to validate state. You could, for example,
very easily check that your BGP neighbors are configured and that the state is up. It becomes even more
interesting if you can build the validator file from data from your inventory. That way you could
deploy your network and verify it matches your expectations all the time without human intervention.

Something else you could do is write the validation file manually prior to a maintenance based on
some gathered data from the network and on your expectations. You could, then, perform your changes
and use this tool to verify the state of the network is exactly the one you wanted. No more
forgetting things or writing one-offs scripts to validate deployments.
