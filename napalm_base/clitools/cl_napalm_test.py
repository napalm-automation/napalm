# -*- coding: utf-8 -*-
'''
NAPALM CLI Tools: test connectivity
===================================

Module to test connectivity with the network device through NAPALM.
'''

from __future__ import absolute_import

# stdlib
import sys
import getpass
import argparse

import logging
logger = logging.getLogger(__file__)

# local modules
from cl_napalm_configure import build_help
from cl_napalm_configure import open_connection
from cl_napalm_configure import configure_logging


def main():

    args = build_help(connect_test=True)
    configure_logging(args.debug)

    device = open_connection(args.vendor,
                             args.hostname,
                             args.user,
                             args.password,
                             args.optional_args)

    print('Successfully connected to the device.')

    device.close()

    sys.exit(0)


if __name__ == '__main__':
    main()
