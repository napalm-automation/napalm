"""Some functions to work with EOS version numbers"""
import re


class EOSVersion:
    """
    Class to represent EOS version
    """

    def __init__(self, version):
        """
        Create object
        :param version: str: version string
        """
        self.version = version
        self.numbers = []
        self.type = ""

        self._parse(version)

    def _parse(self, version):
        """
        Parse version string
        :param version: str: version
        :return: None
        """
        m = re.match(r"^(?P<numbers>\d[\d.]+\d)", version)

        if m:
            self.numbers = m.group("numbers").split(".")

    def __lt__(self, other):
        if not len(self.numbers):
            return True

        for x, y in zip(self.numbers, other.numbers):
            if x < y:
                return True
            elif x > y:
                return False

        return False

    def __gt__(self, other):
        if not len(self.numbers):
            return False

        for x, y in zip(self.numbers, other.numbers):
            if x > y:
                return True
            elif x < y:
                return False

        return False

    def __eq__(self, other):
        if len(self.numbers) != len(other.numbers):
            return False

        for x, y in zip(self.numbers, other.numbers):
            if x != y:
                return False

        return True

    def __le__(self, other):
        return self < other or self == other

    def __ge__(self, other):
        return self > other or self == other
