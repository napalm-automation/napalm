Extend Driver
=============

Occassionally you may have a need that does not fit within one of Napalm's methods, nor will support ever be
expected. As an example, if you wanted to build a parser to filter your unique banner and return structured data
from it, you could extend the driver. The positive side effect is that tools such as Salt, Ansible, and Netbox implicitly
have access to these methods.

The get_driver method, is simply looking for a `custom_napalm.<os>` driver first, and then fail to the normal napalm driver.

.. code-block:: python

    try:
        module = importlib.import_module("custom_" + module_install_name)
    except ImportError:
        module = importlib.import_module(module_install_name)

Extending a Driver
------------------

By simply adding custom_napalm folder with an `__init__.py` and an `<os>.py` (e.g. `ios.py`) with class built to inherit
the os class, you can expose all of the napalm methods, and your custom ones. This may sound like a lot, but this is 
here is a simple example of how to inherit the OS driver and all the requirements.

.. code-block:: python

    from napalm.ios.ios import IOSDriver
    class CustomIOSDriver(IOSDriver):
        """Custom NAPALM Cisco IOS Handler."""
        def get_my_custom_method(self):
            pass

Sample python path custom_napalm directory.::

    custom_napalm/
    ├── __init__.py
    └── ios.py


Creating a Custom Method
------------------------

Bulding on the previous example, we can create a a simple parse to return what our custom enviornment is looking for.

.. code-block:: python

    def get_my_banner(self):
        command = 'show banner motd'
        output = self._send_command(command)

        return_vars = {}
        for line in output.splitlines():
            split_line = line.split()
            if "Site:" == split_line[0]:
                return_vars["site"] = split_line[1]
            elif "Device:" == split_line[0]:
                return_vars["device"] = split_line[1]
            elif "Floor:" == split_line[0]:
                return_vars["floor"] = split_line[1]
            elif "Room:" == split_line[0]:
                return_vars["room"] = split_line[1]
        return return_vars

Which can build.

.. code-block:: python

    >>> import napalm
    >>> ios_device='10.1.100.49'
    >>> ios_user='ntc'
    >>> ios_password='ntc123'
    >>> driver = napalm.get_network_driver('ios')
    >>> device = driver(ios_device, ios_user, ios_password)
    >>> device.open()
    >>> device.get_my_banner()
    {'device': u'NYC-SW01', 'room': u'1004', 'site': u'NYC', 'floor': u'10'}

Custom Driver Notes
-------------------

Please note that since there is no base class `get_my_banner` method, if you attempt to access
this method from an os that is not supporting, then it will fail ungracefully. To alleviate
that, you can raise `NotImplementedError` methods in other os's. It is up to the user to
be able to support their own environment.

.. code-block:: python

    def get_my_banner(self):
        raise NotImplementedError

This feature is meant to allow for maximum amount of flexibility, but it is up to the user to ensure they do
not run into namespace issues, and follow best practices.
