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
from napalm_base import get_network_driver
from napalm_base.clitools.helpers import build_help
from napalm_base.clitools.helpers import configure_logging
from napalm_base.clitools.helpers import parse_optional_args


def main():

    args = build_help(connect_test=True)
    configure_logging(logger, args.debug)

    logger.debug('Getting driver for OS "{driver}"'.format(driver=args.vendor))
    driver = get_network_driver(args.vendor)

    optional_args = parse_optional_args(args.optional_args)
    logger.debug('Connecting to device "{device}" with user "{user}" and optional_args={optional_args}'.format(
                    device=args.hostname, user=args.user, optional_args=optional_args))

    with driver(args.hostname,
                args.user,
                args.password,
                optional_args=optional_args) as device:
        print('Successfully connected to the device.')

    sys.exit(0)


if __name__ == '__main__':
    main()
