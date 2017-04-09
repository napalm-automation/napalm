XMLParser
=========

This extractor will read an XML an extract data from it.

To illustrate the examples below we will use the following configuration::

    <configuration>
        <interfaces>
            <interface>
                <name>ge-0/0/0</name>
                <description>adasdasd</description>
            </interface>
            <interface>
                <name>lo0</name>
                <disable/>
            </interface>
        </interfaces>
    </configuration>

List - xpath
------------

Advances in the XML document up to the point where the relevant list of elements is found.

Arguments:

* **xpath** (mandatory): elements to traverse
* **key** (mandatory): which element is the key of the list

Example:

  Starting from the root, the following action will move us to ``interface`` so we can
  parse each interface individually::

    interface:
        _process:
            mode: xpath
            xpath: "interfaces/interface"
            key: name
            from: "{{ bookmarks.interfaces }}"

  This means after this action we will have a list of interface blocks like this::


    - <interface>
        <name>ge-0/0/0</name>
        <description>adasdasd</description>
      </interface>
    - <interface>
        <name>lo0</name>
        <disable/>
      </interface>

  And we will be able to keep processing them individually.

Leaf - xpath
------------

Extracts a value from an element.

Arguments:

* **xpath** (mandatory): element to extract
* **regexp** (optional): Apply regexp to the value of the element. Must capture ``value`` group.
  See "leaf - map" example for more details.
* **default** (optional): Set this value if no element is found.
* **attribute** (optional): Instead of the ``text`` of the element extracted, extract this attribute of the element.

Example:

  For each interface, read the element ``description`` and map it into the object::

    description:
        _process:
            mode: xpath
            xpath: description
            from: "{{ bookmarks['parent'] }}"

Leaf - value
------------

Apply a user-defined value to the object.

Arguments:

* **value** (mandatory): What value to apply

Example:

  In the following example we can assign a value we already have to the ``interface.name`` attribute::

    name:
        _process:
            mode: value
            value: "{{ interface_key }}"

Leaf - map
----------

Extract value and do a lookup to choose value.

Arguments:

* **xpath** (mandatory): Same as ``xpath`` action.
* **regexp** (optional): Same as ``xpath`` action.
* **map** (mandatory): Dictionary where we will do the lookup action.

Example:

  We can read an element, extract some information and then apply the lookup function, for example, we can
  read the interface name, extract some of the first few characters and figure out the type of interface
  like this::

    type:
        _process:
            mode: map
            xpath: name
            regexp: "(?P<value>[a-z]+).*"
            from: "{{ bookmarks['parent'] }}"
            map:
                ge: ethernetCsmacd
                lo: softwareLoopback
                ae: ieee8023adLag

  The regular expression will give `ge` and `lo` which we can map into `ethernetCsmacd` and
  `ieee8023adLag` respectively.

Leaf - is_absent
----------------

Works exactly like ``xpath`` but if the evaluation is ``None``, it will return ``True``.

Example:

  We could check if an interface is enabled with this::

    enabled:
        _process:
            mode: is_absent
            xpath: "disable"
            from: "{{ bookmarks['parent'] }}"

  As `disable` is missing in the interface `ge-0/0/0` we know it's enabled while `lo0` will be not
  as it was present.

Leaf - is_present
-----------------

Works exactly like ``xpath`` but if the evaluation is ``None``, it will return ``False``.

