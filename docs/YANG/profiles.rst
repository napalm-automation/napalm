Profiles
--------

In order to correctly map YANG objects to native configuration and vice versa, ``napalm-yang`` uses the concept of **profiles**. Profiles, identify the type of device you are dealing with, which can vary depending on the OS, version and/or platform you are using.

If you are using a napalm driver and have access to your device, you will have access to the ``profile`` property which you can pass to any function that requires to know the profile. If you are not using a napalm driver or don't have access to the device, a profile is just a list of strings so you can just specify it directly. For example::

    # Without access to the device
    model.parse_config(profile=["junos"], config=my_configuration)
    
    # With access
    with driver(hostname, username, password) as d:
        model.parse_config(device=d)
    
    # With access but overriding profile
    with driver(hostname, username, password) as d:
        model.parse_config(device=d, profile=["junos13", "junos"])

.. note:: As you noticed a device may have multiple profiles. When that happens, each model that is
  parsed will loop through the profiles from left to right and use the first profile that
  implements that model (note that a YANG model is often comprised of multiple modules). This
  is useful as there might be small variances between different systems
  but not enough to justify reimplementing everything.

You can find the profiles `here <https://github.com/napalm-automation/napalm-yang/tree/develop/napalm_yang/mappings>`_ but what is exactly is a profile? A profile is a bunch of YAML files that follows the structure of a YANG model and describes two things:

#. How to parse native configuration/state and map it into a model.
#. How to translate a model and map it into native configuration.

For example, for a given interface, the snippet below specifies how to map configuration into the ``openconfig_interface`` model on EOS::

            enabled:
                _process:
                    mode: is_present
                    regexp: "(?P<value>no shutdown)"
                    from: "{{ parse_bookmarks.interface[interface_key] }}"
            description:
                _process:
                    mode: search
                    regexp: "description (?P<value>.*)"
                    from: "{{ parse_bookmarks.interface[interface_key] }}"
            mtu:
                _process:
                    mode: search
                    regexp: "mtu (?P<value>[0-9]+)"
                    from: "{{ parse_bookmarks.interface[interface_key] }}"

And the following snippet how to map the same attributes from the ``openconfig_interface`` to native configuration::

            enabled:
                _process:
                    - mode: element
                      value: "    shutdown\n"
                      when: "{{ not model }}"
            description:
                _process:
                    - mode: element
                      value: "    description {{ model }}\n"
                      negate: "    default description"
            mtu:
                _process:
                    - mode: element
                      value: "    mtu {{ model }}\n"
                      negate: "    default mtu\n"

.. note::
    Profiles can also deal with structured data like XML or JSON.

As you can see it's not extremely difficult to understand what they are doing, in the next section we will learn how to write our own profiles.
