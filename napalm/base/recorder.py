from functools import wraps

from collections import defaultdict

from datetime import datetime

from napalm.base.utils import py23_compat

import pip
import logging
import os

from napalm.base.vendor.camel import Camel, CamelRegistry

logger = logging.getLogger("napalm-base")

camel_registry = CamelRegistry()
camel = Camel([camel_registry])


try:
    from pyeapi.eapilib import CommandError as pyeapiCommandError

    @camel_registry.dumper(pyeapiCommandError, 'pyeapiCommandError', version=1)
    def _dump_pyeapiCommandError(e):
        return {
            "code": e.error_code,
            "message": e.error_text,
            "kwargs": {
                "command_error": e.command_error,
                "commands": e.commands,
                "output": e.output,
            },
        }

    @camel_registry.loader('pyeapiCommandError', version=1)
    def _load_pyeapiCommandError(data, version):
        return pyeapiCommandError(data["code"], data["message"], **data["kwargs"])
except Exception:
    # If we can't import pyeapi there is no point on adding serializer/deserializer
    pass


# This is written as a decorator so it can be used independently
def recorder(cls):
    def real_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if cls.mode == "pass":
                return func(*args, **kwargs)

            cls.current_count = cls.calls[func.__name__]
            cls.calls[func.__name__] += 1

            if cls.mode == "record":
                return record(cls, cls.record_exceptions, func, *args, **kwargs)
            elif cls.mode == "replay":
                return replay(cls, func, *args, **kwargs)

        return wrapper
    return real_decorator


def record(cls, exception_valid, func, *args, **kwargs):
    logger.debug("Recording {}".format(func.__name__))

    data = {
        "call": {
            "func": func.__name__,
            "args": args,
            "kwargs": kwargs,
        }
    }
    try:
        r = func(*args, **kwargs)
        raised_exception = False
    except Exception as e:
        if not exception_valid:
            raise e
        raised_exception = True
        r = e

    data["result"] = r

    filename = "{}.{}.yaml".format(func.__name__, cls.current_count)
    with open(os.path.join(cls.path, filename), 'w') as f:
        f.write(camel.dump(data))

    if raised_exception:
        raise r
    else:
        return r


def replay(cls, func, *args, **kwargs):
    logger.debug("Replaying {}".format(func.__name__))
    filename = "{}.{}.yaml".format(func.__name__, cls.current_count)
    with open(os.path.join(cls.path, filename), 'r') as f:
        data = camel.load(py23_compat.text_type(f.read()))

    if isinstance(data["result"], Exception):
        raise data["result"]
    return data["result"]


class Recorder(object):

    def __init__(self, cls, recorder_options, *args, **kwargs):
        self.cls = cls

        self.mode = recorder_options.get("mode", "pass")
        self.path = recorder_options.get("path", "")
        self.record_exceptions = recorder_options.get("record_exceptions", True)

        self.device = cls(*args, **kwargs)
        self.calls = defaultdict(lambda: 1)

        if self.mode == "record":
            self.stamp_metadata()

    def stamp_metadata(self):
        dt = datetime.now()

        installed_packages = pip.get_installed_distributions()
        napalm_packages = sorted(["{}=={}".format(i.key, i.version)
                                  for i in installed_packages if i.key.startswith("napalm")])

        with open("{}/metadata.yaml".format(self.path), "w") as f:
            f.write(camel.dump({"date": dt, "napalm_version": napalm_packages}))

    def __getattr__(self, attr):
        return recorder(self)(self.device.__getattribute__(attr))
