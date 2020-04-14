# -*- coding: utf-8 -*-
"""
NAPALM CLI Tools: test connectivity
===================================

Module to test connectivity with the network device through NAPALM.
"""
# import helpers
from napalm.base import get_network_driver
from napalm.base.clitools.helpers import build_help
from napalm.base.clitools.helpers import configure_logging
from napalm.base.clitools.helpers import parse_optional_args
from napalm.base.clitools.helpers import warning

# stdlib
import sys
import logging

logger = logging.getLogger("cl_napalm_test.py")


def main():
    warning()
    args = build_help(connect_test=True)
    configure_logging(logger, args.debug)

    logger.debug('Getting driver for OS "{driver}"'.format(driver=args.vendor))
    driver = get_network_driver(args.vendor)

    optional_args = parse_optional_args(args.optional_args)
    logger.debug(
        'Connecting to device "{}" with user "{}" and optional_args={}'.format(
            args.hostname, args.user, optional_args
        )
    )

    with driver(
        args.hostname, args.user, args.password, optional_args=optional_args
    ) as device:
        logger.debug("Successfully connected to the device: {}".format(device.hostname))
        print("Successfully connected to the device")
    sys.exit(0)


if __name__ == "__main__":
    main()
