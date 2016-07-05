# -*- coding: utf-8 -*-
'''
NAPALM CLI Tools: test connectivity
===================================

Module to test connectivity with the network device through NAPALM.
'''

from __future__ import absolute_import

# stdlib
import sys

import logging
logger = logging.getLogger(__file__)

# import helpers
from helpers import build_help
from helpers import open_connection
from helpers import configure_logging


def main():

    args = build_help(connect_test=True)
    configure_logging(logger, args.debug)

    device = open_connection(logger,
                             args.vendor,
                             args.hostname,
                             args.user,
                             args.password,
                             args.optional_args)

    print('Successfully connected to the device.')

    logger.debug('Closing session...')

    device.close()

    logger.debug('Connection closed!')

    sys.exit(0)


if __name__ == '__main__':
    main()
