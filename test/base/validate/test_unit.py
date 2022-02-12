"""Tests for the validate methods."""
import pytest
import copy

from napalm.base import validate

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
        assert validate.compare(
            copy.deepcopy(src), copy.deepcopy(dst)
        ) == copy.deepcopy(result)

    def test_numeric_comparison(self):
        assert validate._compare_numeric("<2", 1)
        assert not validate._compare_numeric("<2", 3)
        assert validate._compare_numeric("<=2", 2)
        assert validate._compare_numeric("<3", "2")
        assert validate._compare_numeric("!=3", "2")
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
