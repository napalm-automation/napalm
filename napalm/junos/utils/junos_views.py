"""
Load tables/views
"""
import yaml
import re
from jnpr.junos.factory import FactoryLoader
from os.path import splitext


def _preprocess_yml(path):
    """Dynamically create PY3 version of the file by re-writing 'unicode' to 'str'."""
    with open(path) as f:
        tmp_yaml = f.read()
    return re.sub(r"unicode", "str", tmp_yaml)


def _loadyaml_bypass(yaml_str):
    """Bypass Juniper's loadyaml and directly call FactoryLoader"""
    return FactoryLoader().load(yaml.safe_load(yaml_str))


_YAML_ = splitext(__file__)[0] + ".yml"
py3_yaml = _preprocess_yml(_YAML_)
globals().update(_loadyaml_bypass(py3_yaml))
