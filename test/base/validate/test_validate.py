"""Tests for the validate operation."""
from __future__ import unicode_literals

from napalm.base.base import NetworkDriver
from napalm.base import constants as C
import json

import os
import yaml


BASEPATH = os.path.dirname(__file__)


def construct_yaml_str(self, node):
    # Override the default string handling function
    # to always return unicode objects
    return self.construct_scalar(node)


def _read_yaml(filename):
    yaml.Loader.add_constructor("tag:yaml.org,2002:str", construct_yaml_str)
    yaml.SafeLoader.add_constructor("tag:yaml.org,2002:str", construct_yaml_str)
    with open(filename, "r") as f:
        return yaml.safe_load(f.read())


class TestValidate:
    """Wraps tests."""

    def test_simple_fail(self):
        """A simple test."""
        mocked_data = os.path.join(BASEPATH, "mocked_data", "simple_fail")
        expected_report = _read_yaml(os.path.join(mocked_data, "report.yml"))

        device = FakeDriver(mocked_data)
        actual_report = device.compliance_report(
            os.path.join(mocked_data, "validate.yml")
        )

        assert expected_report == actual_report, yaml.safe_dump(actual_report)

    def test_non_strict_pass(self):
        """A simple test."""
        mocked_data = os.path.join(BASEPATH, "mocked_data", "non_strict_pass")
        expected_report = _read_yaml(os.path.join(mocked_data, "report.yml"))

        device = FakeDriver(mocked_data)
        actual_report = device.compliance_report(
            os.path.join(mocked_data, "validate.yml")
        )

        assert expected_report == actual_report, yaml.safe_dump(actual_report)

    def test_non_strict_pass_from_source(self):
        """A simple test."""
        mocked_data = os.path.join(BASEPATH, "mocked_data", "non_strict_pass")
        expected_report = _read_yaml(os.path.join(mocked_data, "report.yml"))

        device = FakeDriver(mocked_data)
        source = _read_yaml(os.path.join(mocked_data, "validate.yml"))
        actual_report = device.compliance_report(validation_source=source)

        assert expected_report == actual_report, yaml.safe_dump(actual_report)

    def test_non_strict_fail(self):
        """A simple test."""
        mocked_data = os.path.join(BASEPATH, "mocked_data", "non_strict_fail")
        expected_report = _read_yaml(os.path.join(mocked_data, "report.yml"))

        device = FakeDriver(mocked_data)
        actual_report = device.compliance_report(
            os.path.join(mocked_data, "validate.yml")
        )

        assert expected_report == actual_report, yaml.safe_dump(actual_report)

    def test_non_strict_fail_from_source(self):
        """A simple test."""
        mocked_data = os.path.join(BASEPATH, "mocked_data", "non_strict_fail")
        expected_report = _read_yaml(os.path.join(mocked_data, "report.yml"))

        device = FakeDriver(mocked_data)
        source = _read_yaml(os.path.join(mocked_data, "validate.yml"))
        actual_report = device.compliance_report(validation_source=source)

        assert expected_report == actual_report, yaml.safe_dump(actual_report)

    def test_strict_fail(self):
        """A simple test."""
        mocked_data = os.path.join(BASEPATH, "mocked_data", "strict_fail")
        expected_report = _read_yaml(os.path.join(mocked_data, "report.yml"))

        device = FakeDriver(mocked_data)
        actual_report = device.compliance_report(
            os.path.join(mocked_data, "validate.yml")
        )

        assert expected_report == actual_report, yaml.safe_dump(actual_report)

    def test_strict_fail_from_source(self):
        """A simple test."""
        mocked_data = os.path.join(BASEPATH, "mocked_data", "strict_fail")
        expected_report = _read_yaml(os.path.join(mocked_data, "report.yml"))

        device = FakeDriver(mocked_data)
        source = _read_yaml(os.path.join(mocked_data, "validate.yml"))
        actual_report = device.compliance_report(validation_source=source)

        assert expected_report == actual_report, yaml.safe_dump(actual_report)

    def test_strict_pass(self):
        """A simple test."""
        mocked_data = os.path.join(BASEPATH, "mocked_data", "strict_pass")
        expected_report = _read_yaml(os.path.join(mocked_data, "report.yml"))

        device = FakeDriver(mocked_data)
        actual_report = device.compliance_report(
            os.path.join(mocked_data, "validate.yml")
        )

        assert expected_report == actual_report, yaml.safe_dump(actual_report)

    def test_strict_pass_from_source(self):
        """A simple test."""
        mocked_data = os.path.join(BASEPATH, "mocked_data", "strict_pass")
        expected_report = _read_yaml(os.path.join(mocked_data, "report.yml"))

        device = FakeDriver(mocked_data)
        source = _read_yaml(os.path.join(mocked_data, "validate.yml"))
        actual_report = device.compliance_report(validation_source=source)

        assert expected_report == actual_report, yaml.safe_dump(actual_report)

    def test_strict_pass_skip(self):
        """A simple test."""
        mocked_data = os.path.join(BASEPATH, "mocked_data", "strict_pass_skip")
        expected_report = _read_yaml(os.path.join(mocked_data, "report.yml"))

        device = FakeDriver(mocked_data)
        actual_report = device.compliance_report(
            os.path.join(mocked_data, "validate.yml")
        )

        assert expected_report == actual_report, yaml.safe_dump(actual_report)

    def test_strict_pass_skip_from_source(self):
        """A simple test."""
        mocked_data = os.path.join(BASEPATH, "mocked_data", "strict_pass_skip")
        expected_report = _read_yaml(os.path.join(mocked_data, "report.yml"))

        device = FakeDriver(mocked_data)
        source = _read_yaml(os.path.join(mocked_data, "validate.yml"))
        actual_report = device.compliance_report(validation_source=source)

        assert expected_report == actual_report, yaml.safe_dump(actual_report)

    def test_immutable_validation_source(self):
        """Test validation_source is not modified."""
        mocked_data = os.path.join(BASEPATH, "mocked_data", "strict_pass_skip")

        device = FakeDriver(mocked_data)
        source = _read_yaml(os.path.join(mocked_data, "validate.yml"))
        witness = _read_yaml(os.path.join(mocked_data, "validate.yml"))
        device.compliance_report(validation_source=source)

        assert source == witness, yaml.safe_dump(source)


class FakeDriver(NetworkDriver):
    """This is a fake NetworkDriver."""

    def __init__(self, path):
        self.path = path

    def __getattribute__(self, name):
        def load_json(filename):
            def func(**kwargs):
                with open(filename, "r") as f:
                    return json.loads(f.read())

            return func

        if name.startswith("get_") or name in C.ACTION_TYPE_METHODS:
            filename = os.path.join(self.path, "{}.json".format(name))
            return load_json(filename)
        elif name == "method_not_implemented":
            raise NotImplementedError
        else:
            return object.__getattribute__(self, name)
