"""
Load tables/views
"""
from jnpr.junos.factory import loadyaml
from os.path import splitext
from napalm_base.utils import py23_compat

# Temporary fix until PYEZ provides a better solution
if py23_compat.PY2:
    _YAML_ = splitext(__file__)[0] + '.yml'
else:
    _YAML_ = splitext(__file__)[0] + '_py3.yml'
globals().update(loadyaml(_YAML_))
