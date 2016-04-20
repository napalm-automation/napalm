Setting up the lab
==================

We'll set up a lab using VirtualBox and Vagrant, with a virtual Arista device.

Working directory
-----------------

Create a directory for your files anywhere on your machine.

Arista vEOS
-----------

The Arista EOS image can be downloaded for free from the Arista site.

Create an account at https://www.arista.com/en/user-registration, and go to https://www.arista.com/en/support/software-download.

Download the latest "vEOS-lab-<version>-virtualbox.box" listed in the vEOS folder at the bottom of the page.

Add it to your vagrant box list, changing the `<version>`::

    $ vagrant box add --name vEOS-lab-<version>-virtualbox ~/Downloads/vEOS-lab-<version>-virtualbox.box
    $ vagrant box list
    vEOS-lab-quickstart (virtualbox, 0)

You can delete the downloaded .box file once you have added it, as ``vagrant box add`` copies downloaded file to a designated directory (e.g., for Mac OS X and Linux: ``~/.vagrant.d/boxes``, Windows: ``C:/Users/USERNAME/.vagrant.d/boxes``).

Starting Vagrant
----------------

Create a file named ``Vagrantfile`` (no file extension) in your working directory with the following content:

.. literalinclude:: Vagrantfile
   :language: ruby

The above content is also available on `GitHub <https://raw.githubusercontent.com/napalm-automation/napalm/master/docs/tutorials/Vagrantfile>`_.

This Vagrantfile creates a base box and a vEOS box when you call "vagrant up"::

    $ vagrant up
    ... [output omitted] ...

    $ vagrant status
    Current machine states:
    base                      running (virtualbox)
    eos                       running (virtualbox)

You may see some errors when the eos box is getting created [#f1]_.


Shutting down
-------------

When you're done with this tutorial, you can shut down Vagrant as follows::

    $ vagrant destroy -f


.. [#f1] Currently, ``vagrant up`` with the eos box prints some warnings: "No guest additions were detected on the base box for this VM! Guest additions are required for forwarded ports, shared folders, host only networking, and more. If SSH fails on this machine, please install the guest additions and repackage the box to continue. This is not an error message; everything may continue to work properly, in which case you may ignore this message."  This is not a reassuring message, but everything still seems to work correctly.

