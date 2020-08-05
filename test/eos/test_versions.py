"""Tests for versions utils"""
from napalm.eos.utils.versions import EOSVersion


def test_version_create():
    """
    Test we can create version object
    """
    versions = ["4.21.7.1M", "4.20.24F-2GB", "blablabla"]

    for v in versions:
        assert v == EOSVersion(v).version


def test_version_comparisons():
    """
    Test version comparison
    """
    old_version = "4.21.7.1M"
    new_verion = "4.23.0F"

    assert EOSVersion(old_version) < EOSVersion(new_verion)
    assert EOSVersion(new_verion) > EOSVersion(old_version)
    assert EOSVersion(old_version) <= EOSVersion(new_verion)
    assert EOSVersion(new_verion) >= EOSVersion(old_version)
    assert not EOSVersion(old_version) < EOSVersion(old_version)
    assert EOSVersion(old_version) == EOSVersion(old_version)
    assert EOSVersion(old_version) <= EOSVersion(old_version)
