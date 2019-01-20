"""Simplify Python3 compatibility. Modeled after six behavior for small set of things"""
from __future__ import print_function
from __future__ import unicode_literals

import sys
import inspect

PY2 = sys.version_info.major == 2
PY3 = sys.version_info.major == 3


def argspec(*args, **kwargs):
    if PY2:
        # (args, varargs, keywords, defaults)
        return inspect.getargspec(*args, **kwargs)
    elif PY3:
        # (args, varargs, varkw, defaults, kwonlyargs, kwonlydefaults, annotations)
        return inspect.getfullargspec(*args, **kwargs)


if PY3:
    string_types = (str,)
    text_type = str
elif PY2:
    string_types = (basestring,)  # noqa
    text_type = unicode  # noqa
else:
    raise ValueError("Invalid version of Python dectected")
