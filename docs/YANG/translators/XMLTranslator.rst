XMLTranslator
=============

XMLTranslator is responsible of translating a model into XML configuration.

Metadata
--------

* **xml_root** - Set this value on the root of the model to instantiate the XML object.

For example::

    ---
    metadata:
        processor: XMLTranslator
        xml_root: configuration

This will instantiate the XML object ``<configuration/>``.

Container - container
---------------------

Creates a container.

Arguments:

 * **container** (mandatory) - Which container to create
 * **replace** (optional) - Whether this element has to be replaced in case of merge/replace or
   it's not necessary (remember XML is hierarchical which means you can unset things directly in
   the root).

Example:

  Create the ``interfaces`` container::

    _process:
        mode: container
        container: interfaces
        replace: true

List - container
----------------

For each element of the list, create a container.

Arguments:


 * **container** (mandatory) - Which container to create
 * **key_element** (mandatory) - Lists require a key element, this is the name of the element.
 * **key_value** (mandatory) - Key element value.


Example:

  Create interfaces::

    interface:
        _process:
            mode: container
            container: interface
            key_element: name
            key_value: "{{ interface_key }}"

  This will result elements such as::

    <interface>
      <name>ge-0/0/0</name>
    </interface>
    <interface>
      <name>lo0</name>
    </interface>

Leaf - element
--------------

Adds an element to a container.

Arguments:

 * **element** (mandatory): Element name.
 * **value** (optional): Override value. Default is value of the object.

Example 1:

  Configure description::

    description:
        _process:
            - mode: element
              element: description

Example 2:

  Enable or disable an interface::

    enabled:
        _process:
            - mode: element
              element: "disable"
              when: "{{ not model }}"
              value: null

  We override the value and set it to ``null`` because to disable we just have to create the
  element, we don't have to set any value.

Example 3:

  Configure an IP address borrowing values from other fields::

    config:
        _process: unnecessary
        ip:
            _process: unnecessary
        prefix_length:
            _process:
                - mode: element
                  element: name
                  value: "{{ model._parent.ip }}/{{ model }}"
                  when: "{{ model }}"

