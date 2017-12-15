from napalm import get_network_driver

import pprint

import logging
import sys

logger = logging.getLogger("napalm-base")


def config_logging(level=logging.DEBUG, stream=sys.stdout):
    logger.setLevel(level)
    ch = logging.StreamHandler(stream)
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)


config_logging()


##########################################################################
# By default the recorder is set in mode "pass" which doesn't do a thing
##########################################################################
eos_configuration = {
    'hostname': '127.0.0.1',
    'username': 'vagrant',
    'password': 'vagrant',
    'optional_args': {'port': 12443}
}

#  eos = get_network_driver("eos")
#  d = eos(**eos_configuration)

#  d.open()
#  pprint.pprint(d.get_facts())
#  pprint.pprint(d.get_interfaces())


##########################################################################
# In recording mode it will capture all the interactions between the drivers
# and the underlying library and store them into a file.
##########################################################################

eos_configuration = {
    'hostname': '127.0.0.1',
    'username': 'vagrant',
    'password': 'vagrant',
    'optional_args': {'port': 12443,
                      'recorder_mode': "record",
                      'recorder_path': "./test_recorder"}
}

eos = get_network_driver("eos")
d = eos(**eos_configuration)

d.open()
pprint.pprint(d.get_facts())
pprint.pprint(d.get_interfaces())
pprint.pprint(d.cli(["show version"]))

try:
    pprint.pprint(d.cli(["wrong command"]))
except Exception as e:
    print("Recording exception")
    print(e)


##########################################################################
# In replaying mode it will capture all the interactions between the drivers
# and the underlying library and instead of caling it it will return
# the results of a previous run
##########################################################################

eos_configuration = {
    'hostname': '127.0.0.1',
    'username': 'fake',
    'password': 'wrong',
    'optional_args': {'port': 123,
                      'recorder_mode': "replay",
                      'recorder_path': "./test_recorder"}
}

eos = get_network_driver("eos")
d = eos(**eos_configuration)

d.open()
pprint.pprint(d.get_facts())
pprint.pprint(d.get_interfaces())
pprint.pprint(d.cli(["show version"]))
pprint.pprint(d.cli(["wrong command"]))
