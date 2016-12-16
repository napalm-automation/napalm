"""setup.py file."""
import uuid

from setuptools import setup, find_packages
from pip.req import parse_requirements

__author__ = 'Kirk Byers <ktbyers@twb-tech.com>'

install_reqs = parse_requirements('requirements.txt', session=uuid.uuid1())
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name="napalm-ios",
    version="0.5.1",
    packages=find_packages(),
    author="Kirk Byers",
    author_email="ktbyers@twb-tech.com",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation/napalm-ios",
    include_package_data=True,
    install_requires=reqs,
)
