"""setup.py file."""

import uuid

from setuptools import setup, find_packages
from pip.req import parse_requirements

__author__ = 'David Barroso <dbarrosop@dravetech.com>'

install_reqs = parse_requirements('requirements.txt', session=uuid.uuid1())
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name="napalm-iosxr",
    version="0.4.3",
    packages=find_packages(),
    author="David Barroso, Mircea Ulinic",
    author_email="dbarrosop@dravetech.com, mircea@cloudflare.com",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation/napalm-iosxr",
    include_package_data=True,
    install_requires=reqs,
)
