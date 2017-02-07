"""setup.py file."""

import uuid

from setuptools import setup, find_packages
from pip.req import parse_requirements

__author__ = 'Matt Ryan <inetuid@gmail.com>'

install_reqs = parse_requirements('requirements.txt', session=uuid.uuid1())
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name="napalm-ros",
    version="0.2.1",
    packages=find_packages(),
    author="Matt Ryan",
    author_email="inetuid@gmail.com",
    description="Network Automation and Programmability Abstraction Layer driver for Mikrotik ROS",
    classifiers=[
        'Topic :: Utilities',
         'Programming Language :: Python',
         'Programming Language :: Python :: 2',
         'Programming Language :: Python :: 2.7',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation/napalm-ros",
    include_package_data=True,
    install_requires=reqs,
)
