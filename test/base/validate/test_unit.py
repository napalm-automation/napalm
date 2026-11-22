"""Tests for the validate methods."""

import pytest
import copy

from napalm.base import validate
from napalm.base.exceptions import ValidationException

_compare_getter = [
    (
        {"list": [r"\d{2}", 1, 2]},
        [1, 2, 33],
        {"complies": True, "extra": [], "missing": [], "present": [r"\d{2}", 1, 2]},
    ),
    (
        {"list": [1, 2, 3]},
        [1, 2, 3, 4, 5],
        {"complies": True, "extra": [], "missing": [], "present": [1, 2, 3]},
    ),
    (
        {"list": [2, 1, 3]},
        [3, 2, 1],
        {"complies": True, "extra": [], "missing": [], "present": [2, 1, 3]},
    ),
    (
        {"list": [1, 2, {"list": [1, 2]}]},
        [1, 2, [1, 2]],
        #  {u'complies': True, u'extra': [], u'missing': [], u'present': [1, 2, [1, 2]]}
        {
            "complies": True,
            "extra": [],
            "missing": [],
            "present": [1, 2, {"list": [1, 2]}],
        },
    ),
    (
        {"list": [r"\d{2}", 4, 3]},
        [1, 2, 3],
        {"complies": False, "extra": [], "missing": [r"\d{2}", 4], "present": [3]},
    ),
    (
        {"list": [{"list": [1, 2]}, 3]},
        [1, 2, 3],
        {
            "complies": False,
            "extra": [],
            "missing": [{"list": [1, 2]}],
            "present": [3],
        },
    ),
    (
        {"_mode": "strict", "list": [1, 2, 3]},
        [1, 2, 3],
        {"complies": True, "extra": [], "missing": [], "present": [1, 2, 3]},
    ),
    (
        {"_mode": "strict", "list": [1, 2, 3]},
        [1, 2, 3, 4, 5],
        {"complies": False, "extra": [4, 5], "missing": [], "present": [1, 2, 3]},
    ),
    (
        {"_mode": "strict", "list": [2, 1, 3]},
        [3, 2, 1],
        {"complies": True, "extra": [], "missing": [], "present": [2, 1, 3]},
    ),
    (
        {"_mode": "strict", "list": [1, 2, {"_mode": "strict", "list": [1, 2]}]},
        [1, 2, [1, 2]],
        #  {u'complies': True, u'extra': [], u'missing': [], u'present': [1, 2, [1, 2]]}
        {
            "complies": True,
            "extra": [],
            "missing": [],
            "present": [1, 2, {"list": [1, 2]}],
        },
    ),
    (
        {"_mode": "strict", "list": [4, 3]},
        [1, 2, 3],
        {"complies": False, "extra": [1, 2], "missing": [4], "present": [3]},
    ),
    (
        {"_mode": "strict", "list": [{"_mode": "strict", "list": [1, 2]}, 3]},
        [1, 2, 3],
        {
            "complies": False,
            "extra": [1, 2],
            "missing": [{"list": [1, 2]}],
            "present": [3],
        },
    ),
    (
        {"a": 1, "b": 2, "c": 3},
        {"a": 1, "b": 2, "c": 3},
        {
            "complies": True,
            "extra": [],
            "missing": [],
            "present": {
                "a": {"complies": True, "nested": False},
                "b": {"complies": True, "nested": False},
                "c": {"complies": True, "nested": False},
            },
        },
    ),
    (
        {"a": 1, "b": 2, "c": 3},
        {"a": 2, "b": 2, "c": 3},
        {
            "complies": False,
            "extra": [],
            "missing": [],
            "present": {
                "a": {
                    "actual_value": 2,
                    "expected_value": 1,
                    "complies": False,
                    "nested": False,
                },
                "b": {"complies": True, "nested": False},
                "c": {"complies": True, "nested": False},
            },
        },
    ),
    (
        {"a": 1, "b": 2, "c": 3},
        {"b": 1, "c": 3},
        {
            "complies": False,
            "extra": [],
            "missing": ["a"],
            "present": {
                "b": {
                    "actual_value": 1,
                    "expected_value": 2,
                    "complies": False,
                    "nested": False,
                },
                "c": {"complies": True, "nested": False},
            },
        },
    ),
    (
        {"a": 1, "b": 2, "c": {"A": 1, "B": 2}},
        {"a": 1, "b": 2, "c": {"A": 1, "B": 2}},
        {
            "complies": True,
            "extra": [],
            "missing": [],
            "present": {
                "a": {"complies": True, "nested": False},
                "b": {"complies": True, "nested": False},
                "c": {"complies": True, "nested": True},
            },
        },
    ),
    (
        {"a": 1, "b": 2, "c": {"A": 1, "B": 2}},
        {"a": 1, "b": 2, "d": {"A": 1, "B": 2}},
        {
            "complies": False,
            "extra": [],
            "missing": ["c"],
            "present": {
                "a": {"complies": True, "nested": False},
                "b": {"complies": True, "nested": False},
            },
        },
    ),
    (
        {"a": 1, "b": 2, "c": {"A": 3, "B": 2}},
        {"a": 1, "b": 2, "c": {"A": 1, "B": 2}},
        {
            "complies": False,
            "extra": [],
            "missing": [],
            "present": {
                "a": {"complies": True, "nested": False},
                "b": {"complies": True, "nested": False},
                "c": {
                    "complies": False,
                    "diff": {
                        "complies": False,
                        "extra": [],
                        "missing": [],
                        "present": {
                            "A": {
                                "actual_value": 1,
                                "expected_value": 3,
                                "complies": False,
                                "nested": False,
                            },
                            "B": {"complies": True, "nested": False},
                        },
                    },
                    "nested": True,
                },
            },
        },
    ),
    (
        {"a": 1, "b": 2, "c": {"A": 3, "B": 2}},
        {"a": 1, "b": 2, "c": {"A": 1}},
        {
            "complies": False,
            "extra": [],
            "missing": [],
            "present": {
                "a": {"complies": True, "nested": False},
                "b": {"complies": True, "nested": False},
                "c": {
                    "complies": False,
                    "diff": {
                        "complies": False,
                        "extra": [],
                        "missing": ["B"],
                        "present": {
                            "A": {
                                "actual_value": 1,
                                "expected_value": 3,
                                "complies": False,
                                "nested": False,
                            }
                        },
                    },
                    "nested": True,
                },
            },
        },
    ),
    (
        {"_mode": "strict", "a": 1, "b": 2, "c": 3},
        {"a": 1, "b": 2, "c": 3},
        {
            "complies": True,
            "extra": [],
            "missing": [],
            "present": {
                "a": {"complies": True, "nested": False},
                "b": {"complies": True, "nested": False},
                "c": {"complies": True, "nested": False},
            },
        },
    ),
    (
        {"_mode": "strict", "a": 1, "b": 2, "c": 3},
        {"a": 2, "b": 2, "c": 3},
        {
            "complies": False,
            "extra": [],
            "missing": [],
            "present": {
                "a": {
                    "actual_value": 2,
                    "expected_value": 1,
                    "complies": False,
                    "nested": False,
                },
                "b": {"complies": True, "nested": False},
                "c": {"complies": True, "nested": False},
            },
        },
    ),
    (
        {"_mode": "strict", "a": 1, "b": 2, "c": 3},
        {"b": 1, "c": 3},
        {
            "complies": False,
            "extra": [],
            "missing": ["a"],
            "present": {
                "b": {
                    "actual_value": 1,
                    "expected_value": 2,
                    "complies": False,
                    "nested": False,
                },
                "c": {"complies": True, "nested": False},
            },
        },
    ),
    (
        {"_mode": "strict", "a": 1, "b": 2, "c": {"_mode": "strict", "A": 1, "B": 2}},
        {"a": 1, "b": 2, "c": {"A": 1, "B": 2}},
        {
            "complies": True,
            "extra": [],
            "missing": [],
            "present": {
                "a": {"complies": True, "nested": False},
                "b": {"complies": True, "nested": False},
                "c": {"complies": True, "nested": True},
            },
        },
    ),
    (
        {"_mode": "strict", "a": 1, "b": 2, "c": {"_mode": "strict", "A": 1, "B": 2}},
        {"a": 1, "b": 2, "d": {"A": 1, "B": 2}},
        {
            "complies": False,
            "extra": ["d"],
            "missing": ["c"],
            "present": {
                "a": {"complies": True, "nested": False},
                "b": {"complies": True, "nested": False},
            },
        },
    ),
    (
        {"_mode": "strict", "a": 1, "b": 2, "c": {"_mode": "strict", "A": 3, "B": 2}},
        {"a": 1, "b": 2, "c": {"A": 1, "B": 2}},
        {
            "complies": False,
            "extra": [],
            "missing": [],
            "present": {
                "a": {"complies": True, "nested": False},
                "b": {"complies": True, "nested": False},
                "c": {
                    "complies": False,
                    "diff": {
                        "complies": False,
                        "extra": [],
                        "missing": [],
                        "present": {
                            "A": {
                                "actual_value": 1,
                                "expected_value": 3,
                                "complies": False,
                                "nested": False,
                            },
                            "B": {"complies": True, "nested": False},
                        },
                    },
                    "nested": True,
                },
            },
        },
    ),
    (
        {"_mode": "strict", "a": 1, "b": 2, "c": {"_mode": "strict", "A": 3, "B": 2}},
        {"a": 1, "b": 2, "c": {"A": 1, "C": 4}},
        {
            "complies": False,
            "extra": [],
            "missing": [],
            "present": {
                "a": {"complies": True, "nested": False},
                "b": {"complies": True, "nested": False},
                "c": {
                    "complies": False,
                    "diff": {
                        "complies": False,
                        "extra": ["C"],
                        "missing": ["B"],
                        "present": {
                            "A": {
                                "actual_value": 1,
                                "expected_value": 3,
                                "complies": False,
                                "nested": False,
                            }
                        },
                    },
                    "nested": True,
                },
            },
        },
    ),
    (
        {"_mode": "strict", "a": 1, "b": 2, "c": {"_mode": "strict", "A": 3, "B": 2}},
        {"a": 1, "b": 2, "c": {"A": 1, "C": 4}},
        {
            "complies": False,
            "extra": [],
            "missing": [],
            "present": {
                "a": {"complies": True, "nested": False},
                "b": {"complies": True, "nested": False},
                "c": {
                    "complies": False,
                    "diff": {
                        "complies": False,
                        "extra": ["C"],
                        "missing": ["B"],
                        "present": {
                            "A": {
                                "actual_value": 1,
                                "expected_value": 3,
                                "complies": False,
                                "nested": False,
                            }
                        },
                    },
                    "nested": True,
                },
            },
        },
    ),
]


class TestValidate:
    """Wraps tests."""

    @pytest.mark.parametrize("src, dst, result", _compare_getter)
    def test__compare_getter_list(self, src, dst, result):
        """Test for _compare_getter_list."""
        assert validate.compare(copy.deepcopy(src), copy.deepcopy(dst)) == copy.deepcopy(result)

    def test_numeric_comparison(self):
        assert validate._compare_numeric("<2", 1)
        assert not validate._compare_numeric("<2", 3)
        assert validate._compare_numeric("<=2", 2)
        assert validate._compare_numeric("<3", "2")
        assert validate._compare_numeric("!=3", "2")
        assert validate._compare_tolerance("10%20", 18)
        assert validate._compare_tolerance("10%20", 22)
        with pytest.raises(ValueError):
            assert validate._compare_numeric("a2a", 2)
        with pytest.raises(ValueError):
            assert validate._compare_numeric("<1a1", 2)
        with pytest.raises(ValueError):
            assert validate._compare_numeric("a<1", 2)
        with pytest.raises(ValueError):
            assert validate._compare_numeric("<1", "asdasd2")
        with pytest.raises(ValueError):
            assert validate._compare_numeric("<1", "2asdasd")


class TestMatchMode:
    """Tests for the nonstrict/strict and partial/exact modes."""

    def test_mode_parsing(self):
        assert validate._mode("") == {"strict": False, "exact": False}
        assert validate._mode("nonstrict partial") == {"strict": False, "exact": False}
        assert validate._mode("strict") == {"strict": True, "exact": False}
        assert validate._mode("exact") == {"strict": False, "exact": True}
        assert validate._mode("strict exact") == {"strict": True, "exact": True}

    @pytest.mark.parametrize(
        "mode", ["fullmatch", "strict strict2", "strict nonstrict", "partial exact"]
    )
    def test_mode_errors(self, mode):
        with pytest.raises(ValidationException):
            validate._mode(mode)

    def test_list_partial_is_default(self):
        """Without a mode, a list pattern still matches part of an element."""
        result = validate.compare({"list": ["Vlan5"]}, ["Vlan5554"])
        assert result["complies"] is True

    def test_list_exact(self):
        """The case from issue 2029: Vlan5 must not match Vlan5554."""
        result = validate.compare({"_mode": "exact", "list": ["Vlan5"]}, ["Vlan5554"])
        assert result == {"complies": False, "present": [], "missing": ["Vlan5"], "extra": []}
        result = validate.compare({"_mode": "exact", "list": ["Vlan5"]}, ["Vlan5554", "Vlan5"])
        assert result["complies"] is True

    def test_list_exact_keeps_regex(self):
        result = validate.compare({"_mode": "exact", "list": [r"Vlan\d+"]}, ["Vlan5554"])
        assert result["complies"] is True

    def test_dict_value_exact(self):
        src = {"_mode": "exact", "os_version": r"15\.9"}
        assert (
            validate.compare(copy.deepcopy(src), {"os_version": "15.9(3)M3"})["complies"] is False
        )
        assert validate.compare(copy.deepcopy(src), {"os_version": "15.9"})["complies"] is True
        src = {"os_version": r"15\.9"}
        assert validate.compare(copy.deepcopy(src), {"os_version": "15.9(3)M3"})["complies"] is True

    def test_exact_and_strict_together(self):
        src = {"_mode": "strict exact", "list": ["Vlan5"]}
        assert validate.compare(copy.deepcopy(src), ["Vlan5"])["complies"] is True
        result = validate.compare(copy.deepcopy(src), ["Vlan5", "Vlan6"])
        assert result["complies"] is False
        assert result["extra"] == ["Vlan6"]

    def test_exact_applies_to_current_level_only(self):
        """Like strict, exact is set per level and is not inherited by nested dicts."""
        src = {"_mode": "exact", "outer": "abc", "inner": {"value": "abc"}}
        dst = {"outer": "abc", "inner": {"value": "abcdef"}}
        result = validate.compare(copy.deepcopy(src), dst)
        assert result["complies"] is True
        src["inner"]["_mode"] = "exact"
        result = validate.compare(copy.deepcopy(src), dst)
        assert result["complies"] is False

    def test_numeric_operators_unchanged_in_exact(self):
        src = {"_mode": "exact", "cpu": "<15.0", "mem": "10.0<->20.0", "x": "10%20"}
        assert validate.compare(src, {"cpu": 5, "mem": 15, "x": 19})["complies"] is True
