from __future__ import print_function

import argparse
import sys
import getpass

from napalm import get_network_driver

import logging
logger = logging.getLogger('cl-napalm-config.py')


def build_help():
    parser = argparse.ArgumentParser(
        description='Command line tool to handle configuration on devices using NAPALM.'
                    'The script will print the diff on the screen',
        epilog='Automate all the things!!!'
    )
    parser.add_argument(
        dest='config_file',
        action='store',
        help='File containing the configuration you want to deploy.'
    )
    parser.add_argument(
        dest='hostname',
        action='store',
        help='Host where you want to deploy the configuration.'
    )
    parser.add_argument(
        '--user', '-u',
        dest='user',
        action='store',
        default=getpass.getuser(),
        help='User for authenticating to the host. Default: user running the script.'
    )
    parser.add_argument(
        '--password', '-p',
        dest='password',
        action='store',
        help='Password for authenticating to the host.'
             'If you do not provide a password in the CLI you will be prompted.',
    )
    parser.add_argument(
        '--vendor', '-v',
        dest='vendor',
        action='store',
        required=True,
        help='Host Operating System.'
    )
    parser.add_argument(
        '--strategy', '-s',
        dest='strategy',
        action='store',
        choices=['replace', 'merge'],
        default='replace',
        help='Strategy to use to deploy configuration. Default: replace.'
    )
    parser.add_argument(
        '--optional_args', '-o',
        dest='optional_args',
        action='store',
        help='String with comma separated key=value pairs that will be passed via optional_args to the driver.',
    )
    parser.add_argument(
        '--dry-run', '-d',
        dest='dry_run',
        action='store_true',
        default=None,
        help='Only returns diff, it does not deploy the configuration.',
    )
    parser.add_argument(
        '--debug',
        dest='debug',
        action='store_true',
        help='Enables debug mode; more verbosity.'
    )
    args = parser.parse_args()

    if args.password is None:
        password = getpass.getpass('Enter password: ')
        setattr(args, 'password', password)

    return args


def configure_logging(debug):
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    ch = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)


class CustomException(Exception):
    pass


def run(vendor, hostname, user, password, strategy, optional_args, config_file, dry_run):
    logger.debug('Getting driver for OS "{driver}"'.format(driver=vendor))
    driver = get_network_driver(vendor)

    if optional_args is not None:
        optional_args = {x.split('=')[0]: x.split('=')[1] for x in optional_args.replace(' ', '').split(',')}

    logger.debug('Connecting to device "{device}" with user "{user}" and optional_args={optional_args}'.format(
                    device=hostname, user=user, optional_args=optional_args))
    with driver(hostname, user, password, optional_args=optional_args) as device:
        logger.debug('Strategy for loading configuration is "{strategy}"'.format(strategy=strategy))
        if strategy == 'replace':
            strategy_method = device.load_replace_candidate
        elif strategy == 'merge':
            strategy_method = device.load_merge_candidate

        logger.debug('Loading configuration file "{config}"'.format(config=config_file))
        strategy_method(filename=config_file)

        logger.debug('Comparing configuration')
        diff = device.compare_config()

        if dry_run:
            logger.debug('Dry-run. Discarding configuration.')
        else:
            logger.debug('Committing configuration')
            device.commit_config()
        logger.debug('Closing session')

        return diff


def main():
    args = build_help()
    configure_logging(args.debug)

    print(run(args.vendor, args.hostname, args.user, args.password, args.strategy,
              args.optional_args, args.config_file, args.dry_run))
    sys.exit(0)


if __name__ == '__main__':
    main()
