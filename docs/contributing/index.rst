Contributing
============

Contributing is very easy and you can do it many ways; documentation, bugfixes, new features, etc. Any sort of contribution is useful.

How to Contribute
-----------------

In order to speed up things we recommend you to follow the following rules when doing certain types of contributions. If something is not clear don't worry, just ask or send your contribution back and we will help you.

New Feature
-----------

New features are going to mostly be either a new method that is not yet defined or implementing a method already defined for a particular driver.

Proposing a new method
______________________

The best way to propose a new method is as follows to send a PR with the proposed method. That will probably spark some debate around the format. The PR will not only have to include the proposed method but some testing.

In addition, before merging we will want an implementation for any driver of your choice.

For example:
  - `get_config proposal <https://github.com/napalm-automation/napalm/pull/69/files>`_ - That particular example had an issue that some had raised as a reference but that's not mandatory. You can create an issue first but that's optional.
  - `get_config implementation for EOS <https://github.com/napalm-automation/napalm-eos/pull/38/files>`_ - Before the PR was merged an implementation was provided as a proof of concept. This is mandatory. This PRs doesn't have to arrive at the same time as the previous one but it will be required. Note that the rules for "`Implementing an already defined method`_" apply to this PR.

Implementing an already defined method
______________________________________

Adding an already defined method to a driver has three very simple steps:

1. Implement the code.
2. Add necessary mocked data.
3. Enable the test and ensure it passes (this step is no longer needed so ignore the ``.travis.yaml`` change on the example below).

Again `get_config implementation for EOS <https://github.com/napalm-automation/napalm-eos/pull/38/files>`_ is a good example.


Bugfixes
--------

If you found a bug and know how to fix just contribute the bugfix. It might be interesting to provide a test to make sure we don't introduce the bug back in the future but this step is optional.

Documentation
-------------

Just do it! :)

Proposing a new driver
----------------------

This is a more complex process but completely doable. You can find more information `here <https://github.com/napalm-automation/napalm-skeleton>`_.

Please check :ref:`contributing-drivers` to understand the process.

.. toctree::
   :maxdepth: 1

   core
   drivers
