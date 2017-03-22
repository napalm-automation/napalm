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

Example:

  Create/Default interfaces::

    interfaces:
        _translation: unnecessary
        interface:
            _translation:
                mode: container
                key_value: "interface {{ interface_key }}\n"
                negate: "{{ 'no' if interface_key[0:4] in ['Port', 'Loop'] else 'default' }} interface {{ interface_key }}\n"

Leaf - element
--------------

Configures an attribute.

Arguments:

 * **value** (mandatory): How to configure the attribute
 * **negate** (mandatory): How to default the attribute

Example 1:

  Configure description::

    description:
        _translation:
            - mode: element
              value: "    description {{ model }}\n"
              negate: "    default description"

Example 2:

  Configure an IP address borrowing values from other fields::

    address:
        _translation: unnecessary
        config:
            _translation: unnecessary
            ip:
                _translation: unnecessary
            prefix_length:
                _translation:
                    - mode: element
                      value: "    ip address {{ model._parent.ip }}/{{ model }} {{ 'secondary' if model._parent.secondary else '' }}\n"
                      negate: "    default ip address {{ model._parent.ip }}/{{ model }} {{ 'secondary' if model._parent.secondary else '' }}\n"
