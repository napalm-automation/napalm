IOS-XR (NETCONF)
----------------


Device management using CLI Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
All configuration methods (``load_merge_candidate``, ``load_replace_candidate``, ``get_config``, ``compare_config``) support configuration encoded in XML and CLI (unstructured) format. Only devices running IOS-XR 7.0 or later are supported by NAPALM.


Retrieving device environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In IOS-XR 64-bit devices that support an administration mode, the proper operation of ``get_environment`` requires that the ``iosxr_netconf`` driver session is authenticated against a username defined in that administration mode.
