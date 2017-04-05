YANG Basics
-----------

It's not really necessary to understand how YANG works to write a profile but you need some basic
understanding.

Basic Types
___________

* **container** - A container is just a placeholder, sort of like a map or dictionary. A container
  doesn't store any information per se, instead, it contains attributes of any type. For example,
  the following ``config`` object would be a valid container with three attributes of various types::

    container config:
        leaf description: string
        leaf mtu: uint16
        leaf enabled: boolean

* **leaf** - A leaf is an attribute that stores information. Leafs are of a type and values have to
  be valid for the given type. For example::

    leaf descrpition: string # Any string is valid
    leaf mtu: uint16         # -1 is not valid but 1500 is
    leaf enabled: boolean    # true, false, 1, 0, True, False are valid

.. note::
    There can be further restrictions, for example the leaf ``prefix-length`` is of type ``uint8`` but
    it's further restricted with the option ``range 0..32``

* **YANG lists** - A YANG list represents a container in the tree that will represent individual
  members of a list. For example::

    container interfaces:
        list interface:
            container config:
                leaf description: string
                leaf mtu: uint16
                leaf enabled: boolean

As we start adding elements to the interface list, each individual interface will have it's own
attributes. For example::

    interfaces:
        interface["eth1"]:
            config:
                description: "An interface"
                mtu: 1500
                enabled: true
        interface["eth2"]:
            config:
                description: "Another interface"
                mtu: 9000
                enabled: false
