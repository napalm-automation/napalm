"""setup.py file."""
from setuptools import setup, find_packages

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]


__author__ = "David Barroso <dbarrosop@dravetech.com>"

setup(
    name="napalm",
    version="2.3.3",
    packages=find_packages(exclude=("test*",)),
    test_suite="test_base",
    author="David Barroso, Kirk Byers, Mircea Ulinic",
    author_email="dbarrosop@dravetech.com, ping@mirceaulinic.net, ktbyers@twb-tech.com",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        "Topic :: Utilities",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    url="https://github.com/napalm-automation/napalm",
    include_package_data=True,
    install_requires=reqs,
    entry_points={
        "console_scripts": [
            "cl_napalm_configure=napalm.base.clitools.cl_napalm_configure:main",
            "cl_napalm_test=napalm.base.clitools.cl_napalm_test:main",
            "cl_napalm_validate=napalm.base.clitools.cl_napalm_validate:main",
            "napalm=napalm.base.clitools.cl_napalm:main",
        ]
    },
)
