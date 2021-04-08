IOS-XR (NETCONF)
----------------


Device management using CLI Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
All configuration methods (``load_merge_candidate``, ``load_replace_candidate``, ``get_config``, ``compare_config``) support configuration encoded in XML and CLI (unstructured) format.
Only devices running IOS-XR 6.7.1 or later support configuration encoded in CLI (unstructured) format using this driver.


Retrieving device environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In IOS-XR 64-bit devices that support an administration mode, the proper operation of ``get_environment`` requires that the ``iosxr_netconf`` driver session is
authenticated against a username defined in that administration mode.


Retrieving routes to a destination
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In releases 6.5.1 and earlier, IOS-XR devices did not perform a longest prefix match when querying the RIB operational data model (CSCvn64450/CSCvj23009).
For those releases, ``get_route_to`` returns an empty dictionary when an exact prefix match is not found.
