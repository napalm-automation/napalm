Quickstart
==========

This tutorial gets you up-and-running quickly with NAPALM in a local virtual environment so you can see it in action.

.. note::  This tutorial does not cover fully automated configuration management (e.g., using NAPALM in conjunction with Ansible, Chef, Salt, etc.).  We hope that tutorials for these tools will be contributed soon so that you can evaluate the options for your particular environment.

Requirements
------------

You'll need a few tools:

* Python
* `pip <https://pip.pypa.io/en/stable/installing/>`_: The PyPA recommended tool for installing Python packages
* `VirtualBox <https://www.virtualbox.org/>`_: a software virtualization tool
* `Vagrant <https://www.vagrantup.com/downloads.html>`_: a command line utility for managing the lifecycle of virtual machines

As the focus of this tutorial is NAPALM, we don't even scratch the surface of these tools.  If you're not familiar with them, please do some research [#f1]_ as they will be an important part of your development/ops toolkit.

Installation
------------

Install NAPALM with pip::

    pip install napalm

Arista vEOS
-----------

We'll use Arista, which can be downloaded for free from the Arista site.

Create an account at https://www.arista.com/en/user-registration, and go to https://www.arista.com/en/support/software-download.

Download the latest "vEOS-lab-<version>-virtualbox.box" listed in the vEOS folder at the bottom of the page.

Add it to your vagrant box list, changing the `<version>`::

    $ vagrant box add --name vEOS-lab-<version>-virtualbox ~/Downloads/vEOS-lab-<version>-virtualbox.box
    $ vagrant box list
    vEOS-lab-quickstart (virtualbox, 0)

Notes:

* we're setting the ``--name`` parameter here so that the tutorial's Vagrantfile will work out-of-the-box.  You may wish to also ``vagrant box add`` this file with the correct version
* ``vagrant box add`` copies downloaded file to a designated directory (e.g., for Mac OS X and Linux: ``~/.vagrant.d/boxes``, Windows: ``C:/Users/USERNAME/.vagrant.d/boxes``).

Starting Vagrant
----------------

The Vagrantfile (in this directory) creates a base box and a vEOS box when you call "vagrant up"::

    $ cd docs/tutorials
    $ vagrant up
    ... [omitted] ...

    $ vagrant status
    Current machine states:
    base                      running (virtualbox)
    eos                       running (virtualbox)

You may see some errors when the eos box is getting created [#f2]_.


Using the NAPALM command-line client
------------------------------------

You can now try the example commands at http://napalm.readthedocs.org/en/latest/cli.html.  Cd to the ``test/unit/eos`` directory which contains the .conf files::

    $ cd PROJECT_ROOT/test/unit/eos

    # dry run.
    # (When prompted, the password is "vagrant")
    $ cl_napalm_configure \
      --user vagrant \
      --vendor eos \
      --strategy replace \
      --optional_args 'port=12443' \
      --dry-run \
      new_good.conf localhost


Try the other examples and commands given at http://napalm.readthedocs.org/en/latest/cli.html.

Shutting down
-------------

    $ cd PROJECT_ROOT/docs/tutorials
    $ vagrant destroy -f
    $ deactivate           # exit the virtualenv environment

Next Steps
----------

There are many possible steps you could take next:

* create Vagrant boxes for other devices
* explore using configuration management tools (Ansible, Chef, Salt, etc.)

Thanks for trying NAPALM!  Please contribute to this documentation and help grow the NAPALM community!


.. [#f1] Vagrant's `getting started guide <https://www.vagrantup.com/docs/getting-started/>`_ is worth reading and working through.

.. [#f2] Currently, ``vagrant up`` with the eos box prints some warnings: "No guest additions were detected on the base box for this VM! Guest additions are required for forwarded ports, shared folders, host only networking, and more. If SSH fails on this machine, please install the guest additions and repackage the box to continue. This is not an error message; everything may continue to work properly, in which case you may ignore this message."  This is not a reassuring message, but everything still seems to work correctly.

