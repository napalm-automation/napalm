"""
Validation methods for the NAPALM base.

See: https://napalm.readthedocs.io/en/latest/validate.html
"""
from __future__ import unicode_literals

import yaml

from napalm_base.exceptions import ValidationException


def _get_validation_file(validation_file):
    try:
        with open(validation_file, 'r') as stream:
            try:
                validation_source = yaml.load(stream)
            except yaml.YAMLError as exc:
                raise ValidationException(exc)
    except IOError:
        raise ValidationException("File {0} not found.".format(validation_file))
    return validation_source


def _mode(mode_string):
    mode = {'strict': False}

    for m in mode_string.split():
        if m not in mode.keys():
            raise ValidationException("mode '{}' not recognized".format(m))
        mode[m] = True
    return mode


def _compare_getter_list(src, dst, mode):
    result = {"complies": True, "present": [], "missing": [], "extra": []}
    for src_element in src:
        found = False
        for index, dst_element in enumerate(dst):
            intermediate_match = _compare_getter(src_element, dst_element)
            if intermediate_match:
                found = True
                result["present"].append(src_element)
                dst.pop(index)
                break
        if not found:
            result["complies"] = False
            result["missing"].append(src_element)

    if mode["strict"] and dst:
        result["extra"] = dst
        result["complies"] = False

    return result


def _compare_getter_dict(src, dst, mode):
    result = {"complies": True, "present": {}, "missing": [], "extra": []}

    for key, src_element in src.items():
        try:
            dst_element = dst.pop(key)
            result["present"][key] = {}
            intermediate_result = _compare_getter(src_element, dst_element)

            if isinstance(intermediate_result, dict):
                nested = True

                complies = intermediate_result["complies"]

                if not complies:
                    result["present"][key]['diff'] = intermediate_result
            else:
                complies = intermediate_result
                nested = False
                if not complies:
                    result["present"][key]["actual_value"] = dst_element

            if not complies:
                result["complies"] = False

            result["present"][key]["complies"] = complies
            result["present"][key]["nested"] = nested
        except KeyError:
            result["missing"].append(key)
            result["complies"] = False

    if mode["strict"] and dst:
        result["extra"] = list(dst.keys())
        result["complies"] = False

    return result


def _compare_getter(src, dst):
    if isinstance(src, str):
        src = u'{}'.format(src)

    if isinstance(src, dict):
        mode = _mode(src.pop('_mode', ''))
        if 'list' in src.keys():
            if not isinstance(dst, list):
                # This can happen with nested lists
                return False

            return _compare_getter_list(src['list'], dst, mode)
        return _compare_getter_dict(src, dst, mode)
    else:
        return src == dst


def compliance_report(cls, validation_file=None):
    report = {}
    validation_source = _get_validation_file(validation_file)

    for getter, expected_results in validation_source.items():
        if getter == "get_config":
            # TBD
            pass
        else:
            actual_results = getattr(cls, getter)()
            report[getter] = _compare_getter(expected_results, actual_results)

    report["complies"] = all([e["complies"] for e in report.values()])
    return report
