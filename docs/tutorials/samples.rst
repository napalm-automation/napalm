Programming samples
===================

NAPALM tries to provide a common interface and mechanisms to push configuration and retrieve state data from network devices. This method is very useful in combination with tools like `Ansible <http://www.ansible.com>`_, which in turn allows you to manage a set of devices independent of their network OS.

.. note::  These samples assume you have set up your virtual lab (see :doc:`./lab`), and that the 'eos' box is accessible via point 12443 on your machine.  You should also have the sample configuration files saved locally.

Now that you have installed NAPALM (see :doc:`./installation`) and set up your virtual lab, you can try running some sample scripts to demonstrate NAPALM in action.  You can run each of the scripts below by either pulling the files from the GitHub repository, or you can copy the content to a local script (e.g., ``sample_napalm_script.py``) and run it.

For people new to Python:

* the script name should not conflict with any existing module or package.  For example, don't call the script ``napalm.py``.
* run a Python script with ``$ python your_script_name.py``.

Load/Replace configuration
--------------------------

Create a file called ``load_replace.py`` in a folder with the following content:

.. literalinclude:: sample_scripts/load_replace.py
   :language: python

Run the script, passing the path to the ``new_good.conf`` file as an argument::

    python load_replace.py ../sample_configs/new_good.conf
