Translators
^^^^^^^^^^^

Translators are responsible for transforming a model into native configuration.

Special fields
==============

When translating an object, some fields might depend on the translator you are using but some will
available regardless. Some may be even be mandatory.

mode
----

* **mandatory**: yes
* **description**: which parsing/translation action to use for this particular field
* **example**: Translate description attribute of an interface to native configuration::

    description:
        _process:
            - mode: element
              value: "    description {{ model }}\n"
              negate: "    default description"

when
----

* **mandatory**: no
* **description**: the evaluation of this field will determine if the action is executed or
  skipped. This action is probably not very useful when parsing but it's available if you need it.
* **example**: configure ``switchport`` on IOS devices only if the interface is not a loopback
  or a management interface::

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
                      when: "{{ model and interface_key[0:4] not in ['mana', 'loop'] }}"

in
--

* **mandatory**: no
* **description**: where to add the configuration. Sometimes the configuration might have to be
  installed on a different object from the one you are parsing. For example, when configuring a
  tagged subinterface on junos you will have to add also a ``vlan-tagging`` option on the parent
  interface. On ``IOS/EOS``, when configuring interfaces, you have to also add the configuration in
  the root of the configuration and not as a child of the parent interface::

    vlan:
        _process: unnecessary
        config:
            _process: unnecessary
            vlan_id:
                _process:
                    - mode: element
                      element: "vlan-tagging"
                      in: "interface.{{ interface_key }}" # <--- add element to parent interface
                      when: "{{ model > 0 }}"
                      value: null
                    - mode: element
                      element: "vlan-id"
                      when: "{{ model > 0 }}"

    (...)
    subinterface:
        _process:
            mode: container
            key_value: "interface {{ interface_key}}.{{ subinterface_key }}\n"
            negate: "no interface {{ interface_key}}.{{ subinterface_key }}\n"
            in: "interfaces"                            # <--- add element to root of configuration

.. note:: This field follows the same logic as the :ref:`yang_special_field_bookmarks` special field.

Special variables
=================

keys
----

See :ref:`yang_special_field_keys`.

model
-----

This is the current model/attribute being translated. You have the entire object at your disposal,
not only it's value so you can do things like::

    vlan_id:
        _process:
            - mode: element
              value: "    encapsulation dot1q vlan {{ model }}\n"

Or::

    config:
        _process: unnecessary
        ip:
            _process: unnecessary
        prefix_length:
            _process:
                - mode: element
                  value: "    ip address {{ model._parent.ip }}/{{ model }} {{ 'secondary' if model._parent.secondary else '' }}\n"
                  negate: "    default ip address {{ model._parent.ip }}/{{ model }}\n"
