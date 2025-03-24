[![PyPI](https://img.shields.io/pypi/v/napalm.svg)](https://pypi.python.org/pypi/napalm)
[![PyPI versions](https://img.shields.io/pypi/pyversions/napalm.svg)](https://pypi.python.org/pypi/napalm)
[![Actions Build](https://github.com/napalm-automation/napalm/actions/workflows/commit.yaml/badge.svg?branch=develop)](https://github.com/napalm-automation/napalm/actions/workflows/commit.yaml)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)


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

```
pip install napalm
```

*Note*: Beginning with release 5.1.0 and later, NAPALM offers support for
Python 3.9+ only.

*Note*: Beginning with release 5.0.0 and later, NAPALM offers support for
Python 3.8+ only.

*Note*: Beginning with release 4.0.0 and later, NAPALM offers support for
Python 3.7+ only.


Upgrading
=========

We plan to upgrade napalm as fast as possible. Adding new methods and bugfixes. To upgrade napalm it's a simple as repeating the steps you performed while installing but adding the `-U` flag. For example:

```
pip install napalm -U
```

We will be posting news on our slack channel and on Twitter.


Automation Frameworks
======================

Due to its flexibility, NAPALM can be integrated in widely used automation frameworks.


Ansible
-------

Please check [napalm-ansible](https://github.com/napalm-automation/napalm-ansible) for existing Ansible modules leveraging the NAPALM API. Make sure you read the documentation and you understand how it works before trying to use it.


SaltStack
---------

Beginning with release code named `Carbon` (2016.11), [NAPALM is fully integrated](https://mirceaulinic.net/2016-11-30-salt-carbon-released/) in SaltStack - no additional modules required. For setup recommendations, please see [napalm-salt](https://github.com/napalm-automation/napalm-salt). For documentation and usage examples, you can check the modules documentation, starting from the [release notes](https://docs.saltstack.com/en/develop/topics/releases/2016.11.0.html#network-automation-napalm) and [this blog post](https://mirceaulinic.net/2016-11-17-network-orchestration-with-salt-and-napalm/).

StackStorm
----------

NAPALM is usable from StackStorm using the [NAPALM integration pack](https://github.com/StackStorm-Exchange/stackstorm-napalm). See that repository for instructions on installing and configuring the pack to work with StackStorm. General StackStorm documentation can be found at [https://docs.stackstorm.com/](https://docs.stackstorm.com/), and StackStorm can be easily spun up for testing using [Vagrant](https://github.com/StackStorm/st2vagrant) or [Docker](https://github.com/StackStorm/st2-docker).


Contact
=======

Slack
-----

Slack is probably the easiest way to get help with NAPALM. You can find us in the channel `napalm` on the [network.toCode()](https://networktocode.herokuapp.com/) team.

FAQ
---

If you have any issues using NAPALM or encounter any errors, before submitting any questions (directly by email or on Slack), please go through the following checklist:

- Make sure you have the latest release installed. We release very often, so upgrading to the latest version might help in many cases.
- Double check you are able to access the device using the credentials provided.
- Does your device meet the minimum [requirements](http://napalm.readthedocs.io/en/latest/support/index.html#general-support-matrix)?
- Some operating systems have some specific [constraints](http://napalm.readthedocs.io/en/latest/support/index.html#caveats). (e.g. have you enabled the XML agent on IOS-XR, or the NXAPI feature on NXOS?)
- Are you able to connect to the device using NAPALM? Check using napalm CLI to get_facts:

```bash
$ napalm --vendor VENDOR --user USERNAME --password PASSWORD --optional_args OPTIONAL_ARGS HOSTNAME call get_facts
```

Where vendor, username, password and hostname are mandatory. [Optional arguments](http://napalm.readthedocs.io/en/latest/support/index.html#optional-arguments) are specified as comma separated values.

Example:

```bash
$ napalm --vendor junos --user napalm --password dbejmujz --optional_args 'port=12202, config_lock=False' edge01.bjm01 call get_facts
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
* [Network Configuration Consistency with StackStorm and NAPALM](https://stackstorm.com/2017/04/11/ensuring-network-configuration-consistency-stackstorm-napalm/) by Matt Oswalt

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
 * David Barroso ([dbarrosop@dravetech.com](mailto:dbarrosop@dravetech.com))
 * Mircea Ulinic ([ping@mirceaulinic.net](mailto:ping@mirceaulinic.net))
 * Kirk Byers ([ktbyers@twb-tech.com](mailto:ktbyers@twb-tech.com))
 * Elisa Jasinska ([elisa@bigwaveit.org](mailto:elisa@bigwaveit.org))
 * Many others, check the [contributors](https://github.com/napalm-automation/napalm/graphs/contributors) page for details.


Thanks
======

This project is maintained by David Barroso, Mircea Ulinic, and Kirk Byers and a set of other contributors.

Originally it was hosted by the [Spotify][spotify] organization but due to the many contributions received by third parties we agreed creating a dedicated organization for NAPALM and give a big thanks to [Spotify][spotify] for the support.

[spotify]: http://www.spotify.com
[bigwave]: http://bigwaveit.org/
