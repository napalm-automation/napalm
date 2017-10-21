"""setup.py file."""
import uuid

from setuptools import setup, find_packages
from pip.req import parse_requirements
from itertools import chain

import sys

__author__ = 'David Barroso <dbarrosop@dravetech.com>'


def extract_drivers(opt):
    return set([r.replace("--drivers=", "").strip() for r in opt.split(",")])


def process_requirements():
    develop = False
    if 'egg_info' in sys.argv:
        return []
    elif 'develop' in sys.argv:
        develop = True

    requirements = set()
    for r in sys.argv:
        if r.startswith("--drivers"):
            requirements |= extract_drivers(r)

    # let's remove the options
    sys.argv = [o for o in sys.argv if not o.startswith("--drivers")]

    requirements = requirements or set(['all'])
    requirements.add('base')

    u = uuid.uuid1()

    iter_reqs = chain(*[parse_requirements("requirements/{}".format(r), session=u)
                        for r in requirements])

    if develop:
        import pip
        [pip.main(['install', (str(ir.req))]) for ir in iter_reqs]

    return [str(ir.req) for ir in iter_reqs]


reqs = process_requirements()


setup(
    name="napalm",
    version='2.0.0a1',
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
    install_requires=reqs,
    entry_points={
        'console_scripts': [
            'cl_napalm_configure=napalm.base.clitools.cl_napalm_configure:main',
            'cl_napalm_test=napalm.base.clitools.cl_napalm_test:main',
            'cl_napalm_validate=napalm.base.clitools.cl_napalm_validate:main',
            'napalm=napalm.base.clitools.cl_napalm:main',
        ],
    }
)
