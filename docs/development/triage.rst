.. _triaging:

Triaging Issues and Pull Requests
=================================

.. note::

    This document serves mainly as a reference for the NAPALM maintainers,
    but the users are equally welcome to read this document and understand our
    process, and eventually suggest improvements.

We triage Issues and Pull Requests (PR) using GitHub features only:

- :ref:`triage-labels`
- :ref:`triage-milestone`
- :ref:`triage-projects`

.. _triage-labels:

Labels
++++++

.. _triage-driver-labels:

Driver labels
-------------

Each platform supported by NAPALM has associated a label, e.g., ``junos``, ``eos``,
``ios``, ``iosxr``, ``vyos``, etc. It is mandatory that the maintainer to apply
one or more of these labels.

.. _triage-api-change-label:

``api change``
--------------

If the Issue would imply a change in the API, or the PR introduces changes in
the API. By API change we refer to changes in the getters output structure,
methods signature, or any core changes that must be uniformly introduced across
all the drivers.

.. _triage-awesome-label:

``awesome``
-----------

When someone adds or proposes something really awesome.

.. _triage-base-label:

``base``
--------

When base components are affected, e.g., `get_network_driver`, the validate
functionality, or the testing framework.

.. _triage-blocked-label:

``blocked``
-----------

Added in case we block the PR temporarly, or an Issue is currently blocked by
other internal or external factors (PRs pending to be merged, other bugs to be
solved a priori, etc.)

.. _triage-bug-label:

``bug``
-------

Whenever the behaviour reported in the Issue is different than it should, or the
PR kills a bug.

.. _triage-cannot-reproduce:

``cannot reproduce``
--------------------

This refers to Issues only, and it is added when the maintainer(s) cannot
reproduce the behaviour reported.

.. _triage-core-label:

``core``
--------

When any core components (drivers) are affected.

.. _triage-deprecation-label:

``deprecation``
---------------

Added only to PRs, when a API deprecation is introduced.

.. _triage-documentation-label:

``documentation``
-----------------

Can be added to both Issues and PRs, anything related to the documentation.

.. _triage-duplicate-label:

``duplicate``
-------------

Applicable to Issues only, to be added before closing a duplicate.

.. _triage-feature-label:

``feature``
-----------

When a new feature is introduced, or the user requests a new feature.

.. _triage-good-first-issue:

``good first issue``
--------------------

While we want to encourage the community to contribute more and more frequent,
many engineers are still afraid of complex tasks. This label marks simple fixes
that new contributors can address. It is recommended that this label to be
accompanied by an explanation and a pointer for the new contributors. 

.. _triage-help-wanted:

``help wanted``
---------------

This marks an Issue were we ask the community for help, or we need more details
on a particular topic (e.g., outputs from different platforms, explanation, etc.)
from any volunteer from the community.

Once we have all the details required, the maintainer has to remove this label
even though it does not start working on it immediately.

.. _triage-high-severity-label:

``high severity``
-----------------

Whenever a :ref:`triage-bug-label` affects severely one or more features, making
it basically unusable.

.. _triage-info-needed-label:

``info needed``
---------------

We add this label when we need more details and further explanation from the user
that reports an Issue. Once we received everything needed, we can remove that
label.

.. _triage-investigation-label:

``investigation``
-----------------

We need to investigate the problem further.

.. _triage-new-driver:

``new driver``
--------------

When we discuss the possibility to add a new core driver.

.. _triage-new-method:

``new method``
--------------

When we discuss the possibility or implement a new method to one or more drivers.
The method does not necessarily need to be a completely new one to NAPALM.

.. _triage-vendor-bug-label:

``vendor bug``
--------------

When the bug is casued by a vendor stupidity.

.. _triage-milestone:

Milestone
+++++++++

The milestones are used to group the Issues and the Pull Requests from a
different angle:

.. _triage-version-milestone:

Version
-------

The Issue will be solved, or the PR will be included in this release.

.. _triage-approved-milestone:

``APPROVED``
------------

It means that we accept the Issue or the PR, but we don't have a schedule yet
for when the Issue will be solved, or the PR will be included in a release.

.. _triage-blocked-milestone:

``BLOCKED``
-----------

This groups the Issues or the PRs we could not accept for the reasons marked
using the labels.

.. _triage-discussion-milestone:

``DISCUSSION``
--------------

The Issue or the PR needs further discussion.


.. _triage-projects:

Projects
++++++++

Any major change that may consist on several Pull Requests should be groupped
into a GitHub Project.

