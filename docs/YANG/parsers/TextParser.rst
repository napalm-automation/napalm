TextParser
==========

Will apply regular expressions to text to extract data from it.

To explain how this parser works, let's use the following configuration::

    interface Ethernet1
        no switchport
    !
    interface Ethernet1.1
        description blah
    !
    interface Loopback1
        no switchport
        ip address 192.168.0.1/24
        ip address 192.168.1.1/24 secondary
    !

.. note:: The regular expressions on this parser have the ``MULTILINE`` and ``IGNORECASE`` flags turned on.

List - block
------------

Using a regular expression it divides the configuration in blocks where each block is relevant for
a different element of the list.

Arguments:

 * **regexp** (mandatory) - Regular expression to apply. Note that it must capture two things at least;
   ``block``, which will be the entire block of configuration relevant for the interface and
   ``key``, which will be the key of the element.


Example 1

  Capture the interfaces::

    _process:
        mode: block
        regexp: "(?P<block>interface (?P<key>(\\w|-)*\\d+)\n(?:.|\n)*?^!$)"
        from: "{{ bookmarks.interfaces }}"

  So the regexp is basically doing two things. Capturing each block of text that starts with
  ``interface (a word)(a number)\n`` (no dots allowed as a dot means it's subinterface) and then
  finishing in ``!``. It's also getting the ``key``. So after this step we will have a list like::

    - key: Ethernet1
      block: interface Ethernet1
                no switchport
             !
    - key: Loopback1
      block: interface Loopback1
                no switchport
                ip address 192.168.0.1/24
                ip address 192.168.1.1/24 secondary
             !

  Note that ``Ethernet1.1`` is missing as it's not matching the key.

Example 2

  As we process ``Ethernet1`` we will want it's subinterfaces so we can use a similar regexp as
  before but looking for a ``dot`` in the key, using the ``interface_key (Ethernet1)`` as part
  of the regexp. We also have to make sure in the from we went back to the root of the config::

    subinterface:
        _process:
            mode: block
            regexp: "(?P<block>interface {{interface_key}}\\.(?P<key>\\d+)\\n(?:.|\\n)*?^!$)"
            from: "{{ bookmarks.interfaces }}"


Example 3.

  Sometimes we can get easily more information in one go than just the ``key`` and the ``block``. For
  those cases we can capture more groups and they will be stored in the ``extra_vars`` dictionary::

        address:
            _process:
                mode: block
                regexp: "(?P<block>ip address (?P<key>(?P<ip>.*))\\/(?P<prefix>\\d+))(?P<secondary> secondary)*"
                from: "{{ bookmarks['parent'] }}"

Leaf - search
-------------

Extract ``value`` from a regexp.

Arguments:

* **regexp** (mandatory) - Regular expression to apply. Note the regular expression has to capture the ``value``
  at least but it can capture others if you want.
* **default** (optional) - Value to assign if the regexp returns nothing.

Example.

  Get the description of an interface::

    description:
        _process:
            mode: search
            regexp: "description (?P<value>.*)"
            from: "{{ bookmarks.interface[interface_key] }}"

Leaf - value
------------

Apply a user-defined value to the object.

Arguments:

* **value** (mandatory): What value to apply

Example.

  Evaluate a value we already extracted and set model to ``True`` if is not ``None``::

    secondary:
        _process:
            mode: value
            value: "{{ extra_vars.secondary != None }}"

Leaf - is_absent
----------------

Works exactly like search but if the evaluation is ``None``, it will return ``True``.

Example.

  Check if an interface is an IP interface or not::

    ipv4:
        _process: unnecessary
        config:
            _process: unnecessary
            enabled:
                _process:
                    mode: is_absent
                    regexp: "(?P<value>^\\W*switchport$)"
                    from: "{{ bookmarks['parent'] }}"

Leaf - is_present
-----------------

Works exactly like search but if the evaluation is ``None``, it will return ``False``.

Example.

  Check if an interface is enabled::

    enabled:
        _process:
            mode: is_present
            regexp: "(?P<value>no shutdown)"
            from: "{{ bookmarks.interface[interface_key] }}"

Leaf - map
----------

Works exactly like search but we do a lookup of the value on a map.


Arguments:

* **regexp** (mandatory) - Same as ``search``
* **default** (optional) - Same as ``search``
* **map** (optional) - Map where to do the lookup function.

Example.

  Check type of interface by extracting the name and doing a lookup::

    _process:
        mode: map
        regexp: "(?P<value>(\\w|-)*)\\d+"
        from: "{{ interface_key }}"
        map:
            Ethernet: ethernetCsmacd
            Management: ethernetCsmacd
            Loopback: softwareLoopback
            Port-Channel: ieee8023adLag
            Vlan: l3ipvlan

