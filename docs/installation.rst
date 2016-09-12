Installation
============


Full installation
-----------------

If you want to fully install NAPALM you can do it by executing:

```
pip install napalm
```

That will install all the drivers currently available.


Partial Installation
--------------------

If you want to install just a subset of the available modules you can just pick them as follows:

```
pip install napalm-eos napalm-junos
```

That will install only the `eos` and the `junos` drivers. If you want to remove or add a module later on you can just use `pip` to do it:

```
pip uninstall napalm-junos
pip install napalm-ios
```

Check the ['Supported Network Operating Systems'](http://napalm.readthedocs.io/en/latest/support/index.html) section for more information about supported modules.


Upgrading
=========

We plan to upgrade napalm as fast as possible. Adding new methods and bugfixes. To upgrade napalm it's a simple as repeating the steps you performed while installing but adding the `-U` flag. For example:

```
pip install napalm -U
```

or:

```
pip install napalm-eos napalm-junos -U
```

Dependencies
------------

Dependencies are supposed to be solved by `pip` and in most cases it works out of the box. However, on some systems some dependencies have to be installed using system tools. For example, the ``cryptography`` package that ``napalm-ios`` uses.

* `napalm_ios`

To to ensure all dependencies are met for these drivers, use the following commands:

**Debian/Ubuntu**:

```
sudo apt-get install build-essential libssl-dev libffi-dev python-dev
```

**Fedora and RHEL-derivatives**:

```
sudo yum install gcc libffi-devel python-devel openssl-devel
```

