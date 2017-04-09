Parsers
^^^^^^^

Parsers are responsible for mapping native configuration/show_commands to a YANG model.

Special fields
==============

When parsing attributes, some fields may depend on the parser you are using but some
will be available regardless. Some may be even be mandatory.

mode
----

* **Mandatory**: Yes
* **Description**: Which parsing/translation action to use for this particular field.
* **Example**: Parse the description field with a simple regular expression::

    _process:
        mode: search
        regexp: "description (?P<value>.*)"
        from: "{{ bookmarks.interface[interface_key] }}"

when
----

* **Mandatory**: No
* **Description**: The evaluation of this field will determine if the action is executed or
  skipped. This action is probably not very useful when parsing but it's available if you need it.
* **Example**: Configure ``switchport`` on IOS devices only if the interface is not a Loopback
  or a Management interface::

    ipv4:
        _process: unnecessary
        config:
            _process: unnecessary
            enabled:
                _process:
                    - mode: element
                      value: "    no switchport\n"
                      negate: "    switchport\n"
                      in: "interface.{{ interface_key }}"
                      when: "{{ model and interface_key[0:4] not in ['Mana', 'Loop'] }}"

from
----

* **Mandatory**: Yes
* **Description**: Configuration to read. In combination with ``bookmarks`` provides the content we
  are operating with.
* **Example**: Get IP addresses from both both interfaces and subinterfaces::

    address:
        _process:
            mode: xpath
            xpath: "family/inet/address"
            key: name
            from: "{{ bookmarks['parent'] }}"

Special Variables
=================

.. _yang_special_field_keys:

keys
----

When traversing lists, you will have all the relevant keys for the object available, including on nested
lists. Let's see it with an example, let's say we are currently parsing
``interfaces/interface["et1"]/subinterfaces/subinterface["0"].ipv4.addresses.address["10.0.0.1"]``.
At this particular point you will have the following keys available:

* **address_key** - ``10.0.0.1``
* **subinterface_key** - ``0``
* **interface_key** - ``et1``
* **parent_key** - ``0``

When a list is traversed you will always have available a key with name ``$(attribute)_key``. In
addition, you will have ``parent_key`` as the key of the immediate parent object. In the example
above, ``parent_key`` will correspond to ``0`` as it's the immediate parent of the address object.

.. _yang_special_field_bookmarks:

bookmarks
---------

Bookmarks are points of interest in the configuration. Usually, you will be gathering blocks of
configurations and parsing on those but sometimes, the configuration you need might be somewhere
else. For those cases, you will be able to access those with the bookmarks. Using the same example
as before,
``interfaces/interface["et1"]/subinterfaces/subinterface["0"].ipv4.addresses.address["10.0.0.1"]``,
you will have the following bookmarks:

* ``bookmarks.interfaces`` - The root of the configuration
* ``bookmarks.interface["et1"]`` - The block of configuration that corresponds to the interface
  ``et1``
* ``bookmarks.subinterface["0"]`` - The block of configuration that corresponds to the subinterface
  ``0`` of ``et1``.
* ``bookmarks.address["10.0.0.1"]`` - The block of configuration for the address belonging to the
  subinterface.
* ``bookmarks.parent`` - The block of configuration for the immediate parent, in this case, the
  subinterface ``0``.

Note you can use keys instead and do ``bookmarks.subinterface[parent_key]`` or
``bookmarks.subinterface[subinterface_key]``.

extra_vars
----------

Some actions let's you provide additional information for later use. Those will be stored on the
``extra_vars`` dictionary. For example::

    address:
        _process:
            mode: block
            regexp: "(?P<block>ip address (?P<key>(?P<ip>.*))\\/(?P<prefix>\\d+))(?P<secondary> secondary)*"
            from: "{{ bookmarks['parent'] }}"
        config:
            _process: unnecessary
            ip:
                _process:
                    mode: value
                    value: "{{ extra_vars.ip }}"

The first regexp captures a bunch of vars that later can be used by just reading them from
``extra_Vars``.


Metadata
=========

The metadata tells the profile how to process that module and how to get the necessary data from
the device. For example::

    ---
    metadata:
        parser: XMLParser
        execute:
            - method: _rpc
              args:
                  get: "<get-configuration/>"

* **execute** is a list of calls to do to from the device to extract the data.

  * **method** is the method from the device to call.
  * **args** are arguments that will be passed to the method.

In addition, some methods like ``parse_config`` and ``parse_state`` may have mechanisms to pass the
information needed to the parser instead of relying on a live device to obtain it. For parsers, you
will just have to pass a string with the same information the profile is trying to gather.
