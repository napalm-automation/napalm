import uuid

__author__ = 'David Barroso <dbarroso@spotify.net>'
from setuptools import setup, find_packages
from pip.req import parse_requirements


install_reqs = parse_requirements('requirements.txt', session=uuid.uuid1())
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name="napalm",
    version="0.20",
    packages=find_packages(),
    author="David Barroso",
    author_email="dbarroso@spotify.net",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/spotify/napalm",
    include_package_data=True,
    install_requires = reqs,
    entry_points='''
    '''
)
