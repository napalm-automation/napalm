"""Useful helpers for basic stuff like parsing module version."""

import os
import re


def find_version(*file_paths):
    """
    This pattern was modeled on a method from the Python Packaging User Guide:
        https://packaging.python.org/en/latest/single_source_version.html

    We read instead of importing so we don't get import errors if our code
    imports from dependencies listed in install_requires.
    """
    base_module_file = os.path.join(*file_paths)
    with open(base_module_file) as f:
        base_module_data = f.read()
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              base_module_data, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")
