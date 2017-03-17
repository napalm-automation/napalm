[![PyPI](https://img.shields.io/pypi/v/napalm.svg)](https://pypi.python.org/pypi/napalm)
[![PyPI](https://img.shields.io/pypi/dm/napalm.svg)](https://pypi.python.org/pypi/napalm)
[![Build Status](https://travis-ci.org/napalm-automation/napalm.svg?branch=master)](https://travis-ci.org/napalm-automation/napalm)


NAPALM
======
NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support) is a Python library that implements a set of functions to interact with different router vendor devices using a unified API.

![NAPALM logo](static/logo.png?raw=true "NAPALM logo")

NAPALM supports several methods to connect to the devices, to manipulate configurations or to retrieve data.

Supported Network Operating Systems
-----------------------------------

Please check the following [link](https://napalm.readthedocs.io/en/latest/support/index.html) to see which devices are supported. Make sure you understand the [caveats](https://napalm.readthedocs.io/en/latest/support/index.html#caveats).

Documentation
=============

Before using the library, please read the documentation at: [Read the Docs](https://napalm.readthedocs.io)

You can also watch a [live demo](https://youtu.be/93q-dHC0u0I) of NAPALM to see what it is and what it can do for you.

Install
=======

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

Check the ['Supported Network Operating Systems'](#supported-network-operating-systems) section for more information about supported modules.

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

We will be posting news on our slack channel and on Twitter (more details soon).

Automation Frameworks
======================

Due to its flexibility, NAPALM can be integrated in widely used automation frameworks.

Ansible
-------

Please check [napalm-ansible](https://github.com/napalm-automation/napalm-ansible) for existing Ansible modules leveraging the NAPALM API. Make sure you read the documentation and you understand how it works before trying to use it.

SaltStack
---------

Beginning with release code named `Carbon` (2016.11), [NAPALM is fully integrated](https://mirceaulinic.net/2016-11-30-salt-carbon-released/) in SaltStack - no additional modules required. For setup recommendations, please see [napalm-salt](https://github.com/napalm-automation/napalm-salt). For documentation and usage examples, you can check the modules documentation, starting from the [release notes](https://docs.saltstack.com/en/develop/topics/releases/2016.11.0.html#network-automation-napalm) and [this blog post](https://mirceaulinic.net/2016-11-17-network-orchestration-with-salt-and-napalm/).


Contact
=======

Mailing List
------------

If you have any questions, join the users' mailing list at [napalm-automation@googlegroups.com](mailto:napalm-automation@googlegroups.com) and if you are developer and want to contribute to NAPALM feel free to join to the developers' mailing list at [napalm-dev@googlegroups.com](mailto:napalm-dev@googlegroups.com)

Slack
-----

Slack is probably the easiest way to get help with NAPALM. You can find us in the channel `napalm` on the [network.toCode()](https://networktocode.herokuapp.com/) team.

FAQ
---

If you have any issues using NAPALM or encounter any errors, before submitting any questions (directly by email or on Slack), please go through the following checklist:

- Make sure you have the latest release installed. We release very often, so upgrading to the latest version might help in many cases.
- Double or triple check if you indeed are able to access the device using the credentials provided.
- Does your device meet the minimum [requirements](http://napalm.readthedocs.io/en/latest/support/index.html#general-support-matrix)?
- Some operating systems have some specific [constraints](http://napalm.readthedocs.io/en/latest/support/index.html#caveats). (e.g. have you enabled the XML agent on IOS-XR, or the NXAPI feature on NXOS?)
- Are you able to connect to the device using NAPALM? Check using the CLI test tool:

```bash
$ cl_napalm_test --vendor VENDOR --user USERNAME --password PASSWORD --optional_args OPTIONAL_ARGS HOSTNAME
```

Where vendor, username, password and hostname are mandatory. [Optional arguments](http://napalm.readthedocs.io/en/latest/support/index.html#optional-arguments) are specified as comma separated values.

Example:

```bash
$ cl_napalm_test --vendor junos --user napalm --password dbejmujz --optional_args 'port=12202, config_lock=False' edge01.bjm01
```

In case you have any errors, please review the steps above - this looks like a problem with your environment setup.

In order to get help faster, when submitting a bug/error make sure to include all the details requested.

News
====

Blog Posts
----------

* [NAPALM, Ansible, and Cisco IOS](https://pynet.twb-tech.com/blog/automation/napalm-ios.html) by Kirk Byers
* [Adding Cisco IOS support to NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support)](https://projectme10.wordpress.com/2015/12/07/adding-cisco-ios-support-to-napalm-network-automation-and-programmability-abstraction-layer-with-multivendor-support/) by Gabriele Gerbino
* [Network orchestration with Salt and NAPALM](https://mirceaulinic.net/2016-11-17-network-orchestration-with-salt-and-napalm/) by Mircea Ulinic

Presentations
-------------

* [NANOG 64 Presentation & Demo](https://youtu.be/93q-dHC0u0I) by David Barroso and Elisa Jasinska
* [Netnod Autumn Meeting 2015 Presentation](https://www.netnod.se/sites/default/files/NAPALM-david_barroso-Netnodautumnmeeting2015.pdf) by David Barroso
* [Automating IXP Device Configurations with Ansible at the Euro-IX Forum](https://www.euro-ix.net/m/uploads/2015/10/26/euroix-berlin-v2.pdf) by Elisa Jasinska
* [Network Automation with Salt and NAPALM at NANOG 68](https://www.nanog.org/sites/default/files/NANOG68%20Network%20Automation%20with%20Salt%20and%20NAPALM%20Mircea%20Ulinic%20Cloudflare%20(1).pdf); [video](https://www.youtube.com/watch?v=gV2918bH5_c); [recorded demo](https://www.youtube.com/watch?v=AqBk5fM7qZ0) by Mircea Ulinic

Podcasts
--------

* [NAPALM: Integrating Ansible with Network Devices on Software Gone Wild](http://blog.ipspace.net/2015/06/napalm-integrating-ansible-with-network.html) with David Barroso and Elisa Jasinska

Authors
=======
 * David Barroso ([dbarrosop@dravetech.com](mailto:dbarroso@dravetech.com))
 * Elisa Jasinska ([elisa@bigwaveit.org](mailto:elisa@bigwaveit.org))
 * Many others, check the [contributors](https://github.com/napalm-automation/napalm/graphs/contributors) page for details.


Thanks
======

This project was founded by David Barroso as part of [Spotify][spotify] and Elisa Jasinska as part of [BigWave IT][bigwave]. Originally it was hosted by the [Spotify][spotify] organization but due to the many contributions received by third parties we agreed creating a dedicated organization for NAPALM and give a big thanks to [Spotify][spotify] for the support.

[spotify]: http://www.spotify.com
[bigwave]: http://bigwaveit.org/
