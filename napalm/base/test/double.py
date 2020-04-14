"""Base class for Test doubles."""
import json
import re
import os
import sys


class BaseTestDouble(object):
    """Base class for test doubles."""

    def __init__(self, *args, **kwargs):
        """Initiate object."""
        self.current_test = ""
        self.current_test_case = ""

    def find_file(self, filename):
        """Find the necessary file for the given test case."""
        # Find base_dir of submodule
        module_dir = os.path.dirname(sys.modules[self.__module__].__file__)

        full_path = os.path.join(
            module_dir,
            "mocked_data",
            self.current_test,
            self.current_test_case,
            filename,
        )

        if os.path.exists(full_path):
            return full_path
        else:
            raise IOError("Couldn't find file with mocked data: {}".format(full_path))

    @staticmethod
    def sanitize_text(text):
        """Remove some weird characters from text, useful for building filenames from commands."""
        regexp = "[^a-zA-Z0-9]"
        return re.sub(regexp, "_", text)[0:150]

    @staticmethod
    def read_json_file(filename):
        """Parse a json file and return its content."""
        with open(filename) as data_file:
            return json.load(data_file)

    @staticmethod
    def read_txt_file(filename):
        """Return the content of a file."""
        with open(filename) as data_file:
            return data_file.read()

    @property
    def expected_result(self):
        """Return the expected result for the current test case."""
        filename = self.find_file("expected_result.json")

        with open(filename, mode="r") as f:
            try:
                return json.loads(f.read())
            except ValueError:
                raise ValueError(
                    "No JSON object could be decoded on filename: {}".format(filename)
                )


def _string_key_to_int(param):
    """For a given dictionary, convert all strings that represent a number into an int."""
    new_dict = {}

    if isinstance(param, list):
        return [_string_key_to_int(element) for element in param]
    elif isinstance(param, dict):
        for key, value in param.items():
            try:
                new_dict[int(key)] = _string_key_to_int(value)
            except ValueError:
                new_dict[key] = _string_key_to_int(value)
        return new_dict
    else:
        return param
