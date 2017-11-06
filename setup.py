"""setup.py file."""
import uuid
import os

from distutils.core import Command
from setuptools import setup, find_packages
from setuptools.command import install


from pip.req import parse_requirements

import pip
import sys

__author__ = 'David Barroso <dbarrosop@dravetech.com>'

# Read SUPPORTED_DRIVERS from file (without importing)
_locals = {}
filename = os.path.join('napalm', '_SUPPORTED_DRIVERS.py')
with open(filename) as supported:
    exec(supported.read(), None, _locals)
    SUPPORTED_DRIVERS = _locals['SUPPORTED_DRIVERS']


def process_requirements(dep):
    print("PROCESSING DEPENDENCIES FOR {}".format(dep))
    u = uuid.uuid1()
    iter_reqs = parse_requirements("requirements/{}".format(dep), session=u)
    [pip.main(['install', (str(ir.req))]) for ir in iter_reqs]


def custom_command_driver(driver):
    class CustomCommand(Command):
        """A custom command to run Pylint on all Python source files."""
        user_options = []

        def initialize_options(self):
            pass

        def finalize_options(self):
            pass

        def run(self):
            """Run command."""
            process_requirements(driver)

    return CustomCommand


class CustomInstall(install.install):
    """A custom command to run Pylint on all Python source files."""

    def run(self):
        """Run command."""
        if any([d in sys.argv for d in SUPPORTED_DRIVERS]):
            process_requirements('base')
        else:
            process_requirements('all')
        install.install.run(self)


custom_commands = {d: custom_command_driver(d) for d in SUPPORTED_DRIVERS}
custom_commands['install'] = CustomInstall

setup(
    cmdclass=custom_commands,
    name="napalm",
    version='2.0.0',
    packages=find_packages(exclude=("test*", )),
    test_suite='test_base',
    author="David Barroso, Kirk Byers, Mircea Ulinic",
    author_email="dbarrosop@dravetech.com, ping@mirceaulinic.net, ktbyers@twb-tech.com",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation/napalm",
    include_package_data=True,
    install_requires=[],
    entry_points={
        'console_scripts': [
            'cl_napalm_configure=napalm.base.clitools.cl_napalm_configure:main',
            'cl_napalm_test=napalm.base.clitools.cl_napalm_test:main',
            'cl_napalm_validate=napalm.base.clitools.cl_napalm_validate:main',
            'napalm=napalm.base.clitools.cl_napalm:main',
        ],
    }
)
