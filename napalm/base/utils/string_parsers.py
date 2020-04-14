""" Common methods to normalize a string """
import re


def convert(text):
    """Convert text to integer, if it is a digit."""
    if text.isdigit():
        return int(text)
    return text


def alphanum_key(key):
    """ split on end numbers."""
    return [convert(c) for c in re.split("([0-9]+)", key)]


def sorted_nicely(sort_me):
    """ Sort the given iterable in the way that humans expect."""
    return sorted(sort_me, key=alphanum_key)


def colon_separated_string_to_dict(string, separator=":"):
    """
    Converts a string in the format:

        Name: Et3
        Switchport: Enabled
        Administrative Mode: trunk
        Operational Mode: trunk
        MAC Address Learning: enabled
        Access Mode VLAN: 3 (VLAN0003)
        Trunking Native Mode VLAN: 1 (default)
        Administrative Native VLAN tagging: disabled
        Administrative private VLAN mapping: ALL
        Trunking VLANs Enabled: 2-3,5-7,20-21,23,100-200
        Trunk Groups:

    into a dictionary

    """
    dictionary = dict()
    for line in string.splitlines():
        line_data = line.split(separator)
        if len(line_data) > 1:
            dictionary[line_data[0].strip()] = "".join(line_data[1:]).strip()
        elif len(line_data) == 1:
            dictionary[line_data[0].strip()] = None
        else:
            raise Exception(
                "Something went wrong parsing the colo separated string {}".format(line)
            )
    return dictionary


def hyphen_range(string):
    """
    Expands a string of numbers separated by commas and hyphens into a list of integers.
    For example:  2-3,5-7,20-21,23,100-200
    """
    list_numbers = list()
    temporary_list = string.split(",")

    for element in temporary_list:
        sub_element = element.split("-")

        if len(sub_element) == 1:
            list_numbers.append(int(sub_element[0]))
        elif len(sub_element) == 2:
            for number in range(int(sub_element[0]), int(sub_element[1]) + 1):
                list_numbers.append(number)
        else:
            raise Exception(
                "Something went wrong expanding the range {}".format(string)
            )

    return list_numbers


def convert_uptime_string_seconds(uptime):
    """Convert uptime strings to seconds. The string can be formatted various ways."""
    regex_list = [
        # n years, n weeks, n days, n hours, n minutes where each of the fields except minutes
        # is optional. Additionally, can be either singular or plural
        (
            r"((?P<years>\d+) year(s)?,\s+)?((?P<weeks>\d+) week(s)?,\s+)?"
            r"((?P<days>\d+) day(s)?,\s+)?((?P<hours>\d+) "
            r"hour(s)?,\s+)?((?P<minutes>\d+) minute(s)?)"
        ),
        # n days, HH:MM:SS where each field is required (except for days)
        (
            r"((?P<days>\d+) day(s)?,\s+)?"
            r"((?P<hours>\d+)):((?P<minutes>\d+)):((?P<seconds>\d+))"
        ),
        # 7w6d5h4m3s where each field is optional
        (
            r"((?P<weeks>\d+)w)?((?P<days>\d+)d)?((?P<hours>\d+)h)?"
            r"((?P<minutes>\d+)m)?((?P<seconds>\d+)s)?"
        ),
    ]
    regex_list = [re.compile(x) for x in regex_list]

    uptime_dict = {}
    for regex in regex_list:
        match = regex.search(uptime)
        if match:
            uptime_dict = match.groupdict()
            break

    uptime_seconds = 0
    for unit, value in uptime_dict.items():
        if value is not None:
            if unit == "years":
                uptime_seconds += int(value) * 31536000
            elif unit == "weeks":
                uptime_seconds += int(value) * 604800
            elif unit == "days":
                uptime_seconds += int(value) * 86400
            elif unit == "hours":
                uptime_seconds += int(value) * 3600
            elif unit == "minutes":
                uptime_seconds += int(value) * 60
            elif unit == "seconds":
                uptime_seconds += int(value)
            else:
                raise Exception(
                    'Unrecognized unit "{}" in uptime:{}'.format(unit, uptime)
                )

    if not uptime_dict:
        raise Exception("Unrecognized uptime string:{}".format(uptime))

    return uptime_seconds
