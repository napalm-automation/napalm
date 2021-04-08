IOS-XR (NETCONF)
----------------


Minimum IOS-XR OS Version
~~~~~~~~~~~~~~~~~~~~~~~~~
Only devices running IOS-XR 7.0 or later are supported by NAPALM.


Device management using CLI Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
All configuration methods (``load_merge_candidate``, ``load_replace_candidate``, ``get_config``, ``compare_config``) support configuration encoded in XML and CLI (unstructured) format. This can be specified by using the ``config_encoding`` optional_args argument and setting it to either ``cli`` or ``xml`` (``cli`` is the default value).


Retrieving device environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In IOS-XR 64-bit devices that support an administration mode, the proper operation of ``get_environment`` requires that the ``iosxr_netconf`` driver session is authenticated against a username defined in that administration mode.
