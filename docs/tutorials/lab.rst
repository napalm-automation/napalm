Setting up the lab
==================

We'll set up a lab using VirtualBox and Vagrant, with a virtual Arista device, and get some sample files for the following steps.

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

Create a file named ``Vagrantfile`` (no file extension) in your working directory with the following content (replace VEOS_BOX by your downloaded EOS version):

.. literalinclude:: Vagrantfile
   :language: ruby

The above content is also available `on GitHub <https://raw.githubusercontent.com/napalm-automation/napalm/master/docs/tutorials/Vagrantfile>`_.

This Vagrantfile creates a base box and a vEOS box when you call ``vagrant up``::

    $ vagrant up --provider virtualbox
    ... [output omitted] ...

    $ vagrant status
    Current machine states:
    base                      running (virtualbox)
    eos                       running (virtualbox)

You may see some errors when the eos box is getting created [#f1]_.

Troubleshooting
^^^^^^^^^^^^^^^

* After running ``vagrant up``, ensure that you can ssh to the box with ``vagrant ssh eos``.
* If you receive the warning "eos: Warning: Remote connection disconnect.  Retrying...", see `this StackOverflow post <http://stackoverflow.com/questions/22575261/vagrant-stuck-connection-timeout-retrying>`_.

Sample files
------------

There are some sample Arista vEOS configuration files on `GitHub <https://github.com/napalm-automation/napalm/blob/master/docs/tutorials/sample_configs>`_.  You can download them to your machine by copying them from GitHub, or using the commands below::

    $ for f in new_good.conf merge_good.conf merge_typo.conf; do
    $   wget https://raw.githubusercontent.com/napalm-automation/napalm/master/docs/tutorials/sample_configs/$f
    $ done

(Note: please open a GitHub issue if these URLs are invalid.)


.. [#f1] Currently, ``vagrant up`` with the eos box prints some warnings: "No guest additions were detected on the base box for this VM! Guest additions are required for forwarded ports, shared folders, host only networking, and more. If SSH fails on this machine, please install the guest additions and repackage the box to continue. This is not an error message; everything may continue to work properly, in which case you may ignore this message."  This is not a reassuring message, but everything still seems to work correctly.

