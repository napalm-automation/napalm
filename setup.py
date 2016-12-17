"""setup.py file."""

import uuid

from setuptools import setup, find_packages
from pip.req import parse_requirements

__author__ = 'Shota Muto <dos9954@gmail.com>'

install_reqs = parse_requirements('requirements.txt', session=uuid.uuid1())
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name="napalm-vyos",
    version="0.1.1",
    packages=find_packages(),
    author="Shota Muto",
    author_email="dos9954@gmail.com",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        'Topic :: Utilities',
         'Programming Language :: Python',
         'Programming Language :: Python :: 2',
         'Programming Language :: Python :: 2.7',
         'Operating System :: POSIX :: Linux',
         'Operating System :: MacOS',
    ],
    include_package_data=True,
    install_requires=reqs,
)
