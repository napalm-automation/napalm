Writing Profiles
================

As it's been already mentioned, a profile is a bunch of YAML files that describe how to map native
configuration and how to translate an object into native configuration. In order to read native
configuration we will use **parsers**, to translate a YANG model into native configuration we will
use **translators**.

Both parsers and translators follow three basic rules:

#. One directory per module.
#. One file per model.
#. Exact same representation of the model inside the file:

For example::

    $ tree napalm_yang/mappings/eos/parsers/config
    napalm_yang/mappings/eos/parsers/config
    ├── napalm-if-ip
    │   └── secondary.yaml
    ├── openconfig-if-ip
    │   └── ipv4.yaml
    ├── openconfig-interfaces
    │   └── interfaces.yaml
    └── openconfig-vlan
        ├── routed-vlan.yaml
        └── vlan.yaml

    4 directories, 5 files
    $ cat napalm_yang/mappings/eos/parsers/config/openconfig-vlan/vlan.yaml
    ---
    metadata:
        (trimmed for brevity)

    vlan:
        (trimmed for brevity)
        config:
            (trimmed for brevity)
            vlan_id:
                (trimmed for brevity)

If we check the content of the file ``vlan.yaml`` we can clearly see two parts:

* **metadata** - This part specifies what parser or translator we want to use as there are several
  depending on the type of data we are parsing from or translating to and some options that the
  parser/translator might need. For example::

    metadata:
        processor: XMLParser
        execute:
            - method: _rpc
              args:
                  get: "<get-configuration/>"

In this case we are using the ``XMLParser`` parser and in order to get the data we need from the
device we have to call the method ``_rpc`` with the ``args`` parameters. This is, by the way, an
RPC call for a junos device.

* **vlan** - This is the part that follows the model specification. In this case is ``vlan`` but in
  others it might be ``interfaces``, ``addressess`` or something else, this will be model dependent
  but it's basically whatever it's not ``metadata``. This part will follow the model specification
  and add rules on each attribute to tell the parser/translator what needs to be done. For
  example::

    vlan:
        _process: unnecessary
        config:
            _process: unnecessary
            vlan_id:
                _process:
                    mode: xpath
                    xpath: "vlan-id"
                    from: "{{ parse_bookmarks['parent'] }}"

As we are dealing with a parser we have to specify the ``_process`` attribute at each step (translators
require the attribute ``_process``). There are two special types of actions; ``unnecessary`` and
``not_implemented``. Both do exactly the same, skip any action and move onto the next attribute. The
only difference is purely aesthetically and for documentation purposes.

Something else worth noting is that each attribute inside ``_process/_process`` is evaluated as a
``jinja2`` template so you can do variable substitutions, evaluations, etc...
