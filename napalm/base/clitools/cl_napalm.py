# import helpers
from napalm.base import get_network_driver
from napalm.base.clitools import helpers

# stdlib
import json
import logging
import argparse
import getpass
import pkgutil
from importlib.metadata import version
from functools import wraps


def debugging(name):
    def real_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            censor_parameters = ["password"]
            censored_kwargs = {
                k: v if k not in censor_parameters else "*******"
                for k, v in kwargs.items()
            }
            logger.debug(
                "{} - Calling with args: {}, {}".format(name, args, censored_kwargs)
            )
            try:
                r = func(*args, **kwargs)
                logger.debug("{} - Successful".format(name))
                return r
            except NotImplementedError:
                if name not in [
                    "pre_connection_tests",
                    "connection_tests",
                    "post_connection_tests",
                ]:
                    logger.debug("{} - Not implemented".format(name))
            except Exception as e:
                logger.error("{} - Failed: {}".format(name, e))
                print("\n================= Traceback =================\n")
                raise

        return wrapper

    return real_decorator


logger = logging.getLogger("napalm")


def build_help():
    parser = argparse.ArgumentParser(
        description="Command line tool to handle configuration on devices using NAPALM."
        "The script will print the diff on the screen",
        epilog="Automate all the things!!!",
    )
    parser.add_argument(
        dest="hostname",
        action="store",
        help="Host where you want to deploy the configuration.",
    )
    parser.add_argument(
        "--user",
        "-u",
        dest="user",
        action="store",
        default=getpass.getuser(),
        help="User for authenticating to the host. Default: user running the script.",
    )
    parser.add_argument(
        "--password",
        "-p",
        dest="password",
        action="store",
        help="Password for authenticating to the host."
        "If you do not provide a password in the CLI you will be prompted.",
    )
    parser.add_argument(
        "--vendor",
        "-v",
        dest="vendor",
        action="store",
        required=True,
        help="Host Operating System.",
    )
    parser.add_argument(
        "--optional_args",
        "-o",
        dest="optional_args",
        action="store",
        help="String with comma separated key=value pairs passed via optional_args to the driver.",
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        help="Enables debug mode; more verbosity.",
    )
    subparser = parser.add_subparsers(title="actions")

    config = subparser.add_parser("configure", help="Perform a configuration operation")
    config.set_defaults(which="config")
    config.add_argument(
        dest="config_file",
        action="store",
        help="File containing the configuration you want to deploy.",
    )
    config.add_argument(
        "--strategy",
        "-s",
        dest="strategy",
        action="store",
        choices=["replace", "merge"],
        default="replace",
        help="Strategy to use to deploy configuration. Default: replace.",
    )
    config.add_argument(
        "--dry-run",
        "-d",
        dest="dry_run",
        action="store_true",
        default=None,
        help="Only returns diff, it does not deploy the configuration.",
    )

    call = subparser.add_parser("call", help="Call a napalm method")
    call.set_defaults(which="call")
    call.add_argument(dest="method", action="store", help="Run this method")
    call.add_argument(
        "--method-kwargs",
        "-k",
        dest="method_kwargs",
        action="store",
        help='kwargs to pass to the method. For example: "destination=1.1.1.1,protocol=bgp"',
    )

    validate = subparser.add_parser("validate", help="Validate configuration/state")
    validate.set_defaults(which="validate")
    validate.add_argument(
        dest="validation_file",
        action="store",
        help="Validation file containing resources derised states",
    )
    args = parser.parse_args()

    if not hasattr(args, "which"):
        args.which = None

    if args.password is None:
        password = getpass.getpass("Enter password: ")
        setattr(args, "password", password)

    return args


def check_installed_packages():
    logger.debug("Gathering napalm packages")
    napalm_packages = sorted(
        [
            "{}=={}".format(i.name, version(i.name))
            for i in list(pkgutil.iter_modules())
            if i.name.startswith("napalm")
        ]
    )
    for n in napalm_packages:
        logger.debug(n)


@debugging("get_network_driver")
def call_get_network_driver(vendor):
    return get_network_driver(vendor)


@debugging("__init__")
def call_instantiating_object(driver, *args, **kwargs):
    return driver(*args, **kwargs)


@debugging("pre_connection_tests")
def call_pre_connection(driver):
    driver.pre_connection_tests()


@debugging("connection_tests")
def call_connection(device):
    device.connection_tests()


@debugging("post_connection_tests")
def call_post_connection(device):
    device.post_connection_tests()


@debugging("get_facts")
def call_facts(device):
    facts = device.get_facts()
    logger.debug("Gathered facts:\n{}".format(json.dumps(facts, indent=4)))
    print(json.dumps(facts, indent=4))


@debugging("close")
def call_close(device):
    return device.close()


@debugging("open")
def call_open_device(device):
    return device.open()


@debugging("load_replace_candidate")
def call_load_replace_candidate(device, *args, **kwargs):
    return device.load_replace_candidate(*args, **kwargs)


@debugging("load_merge_candidate")
def call_load_merge_candidate(device, *args, **kwargs):
    return device.load_merge_candidate(*args, **kwargs)


@debugging("compare_config")
def call_compare_config(device, *args, **kwargs):
    diff = device.compare_config(*args, **kwargs)
    logger.debug("Gathered diff:")
    print(diff)
    return diff


@debugging("commit_config")
def call_commit_config(device, *args, **kwargs):
    return device.commit_config(*args, **kwargs)


def configuration_change(device, config_file, strategy, dry_run):
    if strategy == "replace":
        strategy_method = call_load_replace_candidate
    elif strategy == "merge":
        strategy_method = call_load_merge_candidate

    strategy_method(device, filename=config_file)

    diff = call_compare_config(device)

    if not dry_run:
        call_commit_config(device)
    return diff


@debugging("method")
def call_getter(device, method, **kwargs):
    logger.debug("{} - Attempting to resolve method".format(method))
    func = getattr(device, method)
    logger.debug(
        "{} - Attempting to call method with kwargs: {}".format(method, kwargs)
    )
    r = func(**kwargs)
    logger.debug("{} - Response".format(method))
    print(json.dumps(r, indent=4))


@debugging("compliance_report")
def call_compliance_report(device, validation_file):
    result = device.compliance_report(validation_file)
    print(json.dumps(result, indent=4))
    return result


def run_tests(args):
    driver = call_get_network_driver(args.vendor)
    optional_args = helpers.parse_optional_args(args.optional_args)

    device = call_instantiating_object(
        driver,
        args.hostname,
        args.user,
        password=args.password,
        timeout=60,
        optional_args=optional_args,
    )

    if args.debug:
        call_pre_connection(device)

    call_open_device(device)

    if args.debug:
        call_connection(device)
        call_facts(device)

    if args.which == "call":
        method_kwargs = helpers.parse_optional_args(args.method_kwargs)
        call_getter(device, args.method, **method_kwargs)
    elif args.which == "config":
        configuration_change(device, args.config_file, args.strategy, args.dry_run)
    elif args.which == "validate":
        call_compliance_report(device, args.validation_file)

    call_close(device)

    if args.debug:
        call_post_connection(device)


def main():
    args = build_help()
    helpers.configure_logging(logger, debug=args.debug)
    logger.debug("Starting napalm's debugging tool")
    check_installed_packages()
    run_tests(args)


if __name__ == "__main__":
    main()
