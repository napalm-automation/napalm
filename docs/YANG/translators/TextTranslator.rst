TextTranslator
==============

TextTranslator is responsible of translating a model into text configuration.

Metadata
--------

* **root** - Set to true if this is the root of the model.

List - container
----------------

Create/Removes each element of the list.

Arguments:

 * **key_value** (mandatory): How to create the element.
 * **negate** (mandatory): How to eliminate/default the element.
 * **replace** (optional): Whether the element has to be defaulted or not during the replace operation.
 * **end** (optional): Closing command to signal end of element

Example 1:

  Create/Default interfaces::

    interfaces:
        _process: unnecessary
        interface:
            _process:
                mode: container
                key_value: "interface {{ interface_key }}\n"
                negate: "{{ 'no' if interface_key[0:4] in ['Port', 'Loop'] else 'default' }} interface {{ interface_key }}\n"
                end: "    exit\n"

Example 2:

  Configure IP addresses. As the parent interface is defaulted already, don't do it again::

    address:
        _process:
            mode: container
            key_value: "    ip address {{ model.config.ip }} {{ model.config.prefix_length|cidr_to_netmask }}{{ ' secondary' if model.config.secondary else '' }}\n"
            negate: "    default ip address {{ model.config.ip }} {{ model.config.prefix_length|cidr_to_netmask }}{{ ' secondary' if model.config.secondary else '' }}\n"
            replace: false

Leaf - element
--------------

Configures an attribute.

Arguments:

 * **value** (mandatory): How to configure the attribute
 * **negate** (mandatory): How to default the attribute

Example 1:

  Configure description::

    description:
        _process:
            - mode: element
              value: "    description {{ model }}\n"
              negate: "    default description"

Example 2:

  Configure an IP address borrowing values from other fields::

    address:
        _process: unnecessary
        config:
            _process: unnecessary
            ip:
                _process: unnecessary
            prefix_length:
                _process:
                    - mode: element
                      value: "    ip address {{ model._parent.ip }}/{{ model }} {{ 'secondary' if model._parent.secondary else '' }}\n"
                      negate: "    default ip address {{ model._parent.ip }}/{{ model }} {{ 'secondary' if model._parent.secondary else '' }}\n"
