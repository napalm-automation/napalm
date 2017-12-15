# encoding: utf8
#  Original code from https://github.com/eevee/camel
#  This project is licensed under the ISC license, reproduced below.

#  Copyright (c) 2012, Lexy "eevee" Munroe <eevee.camel@veekun.com>

#  Permission to use, copy, modify, and/or distribute this software for any
#  purpose with or without fee is hereby granted, provided that the above
#  copyright notice and this permission notice appear in all copies.

#  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
#  REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
#  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
#  INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
#  LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
#  OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#  PERFORMANCE OF THIS SOFTWARE.


from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import base64
import collections
import functools
from io import StringIO
import types

import yaml

try:
    from yaml import CSafeDumper as SafeDumper
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeDumper
    from yaml import SafeLoader


YAML_TAG_PREFIX = 'tag:yaml.org,2002:'

_str = type('')
_bytes = type(b'')
_long = type(18446744073709551617)  # 2**64 + 1


class CamelDumper(SafeDumper):
    """Subclass of yaml's `SafeDumper` that scopes representers to the
    instance, rather than to the particular class, because damn.
    """
    def __init__(self, *args, **kwargs):
        # TODO this isn't quite good enough; pyyaml still escapes anything
        # outside the BMP
        kwargs.setdefault('allow_unicode', True)
        super(CamelDumper, self).__init__(*args, **kwargs)
        self.yaml_representers = SafeDumper.yaml_representers.copy()
        self.yaml_multi_representers = SafeDumper.yaml_multi_representers.copy()

        # Always dump bytes as binary, even on Python 2
        self.add_representer(bytes, CamelDumper.represent_binary)

    def represent_binary(self, data):
        # This is copy-pasted, because it only exists in pyyaml in python 3 (?!)
        if hasattr(base64, 'encodebytes'):
            data = base64.encodebytes(data).decode('ascii')
        else:
            data = base64.encodestring(data).decode('ascii')
        return self.represent_scalar(
            YAML_TAG_PREFIX + 'binary', data, style='|')

    def add_representer(self, data_type, representer):
        self.yaml_representers[data_type] = representer

    def add_multi_representer(self, data_type, representer):
        self.yaml_multi_representers[data_type] = representer


class CamelLoader(SafeLoader):
    """Subclass of yaml's `SafeLoader` that scopes constructors to the
    instance, rather than to the particular class, because damn.
    """
    def __init__(self, *args, **kwargs):
        super(CamelLoader, self).__init__(*args, **kwargs)
        self.yaml_constructors = SafeLoader.yaml_constructors.copy()
        self.yaml_multi_constructors = SafeLoader.yaml_multi_constructors.copy()
        self.yaml_implicit_resolvers = SafeLoader.yaml_implicit_resolvers.copy()

    def add_constructor(self, data_type, constructor):
        self.yaml_constructors[data_type] = constructor

    def add_multi_constructor(self, data_type, constructor):
        self.yaml_multi_constructors[data_type] = constructor

    def add_implicit_resolver(self, tag, regexp, first):
        if first is None:
            first = [None]
        for ch in first:
            self.yaml_implicit_resolvers.setdefault(ch, []).append((tag, regexp))

    def add_path_resolver(self, *args, **kwargs):
        # This API is non-trivial and claims to be experimental and unstable
        raise NotImplementedError


class Camel(object):
    """Class responsible for doing the actual dumping to and loading from YAML.
    """
    def __init__(self, registries=()):
        self.registries = collections.OrderedDict()
        self.version_locks = {}  # class => version

        self.add_registry(STANDARD_TYPES)
        for registry in registries:
            self.add_registry(registry)

    def add_registry(self, registry, tag_prefix=None, tag_shorthand=None):
        self.registries[registry] = (
            tag_prefix or registry.tag_prefix,
            tag_shorthand or registry.tag_shorthand,
        )

    def lock_version(self, cls, version):
        self.version_locks[cls] = version

    def make_dumper(self, stream):
        tag_shorthands = {}
        for registry, (prefix, shorthand) in self.registries.items():
            if shorthand is None:
                continue
            if shorthand in tag_shorthands:
                raise ValueError(
                    "Conflicting tag shorthands: {!r} is short for both {!r} and {!r}"
                    .format(shorthand, tag_shorthands[shorthand], prefix))
            tag_shorthands[shorthand] = prefix

        dumper = CamelDumper(stream, default_flow_style=False, tags=tag_shorthands)
        for registry in self.registries:
            registry.inject_dumpers(dumper, version_locks=self.version_locks)
        return dumper

    def dump(self, data):
        stream = StringIO()
        dumper = self.make_dumper(stream)
        dumper.open()
        dumper.represent(data)
        dumper.close()
        return stream.getvalue()

    def make_loader(self, stream):
        loader = CamelLoader(stream)
        for registry in self.registries:
            registry.inject_loaders(loader)
        return loader

    def load(self, data):
        stream = StringIO(data)
        loader = self.make_loader(stream)
        obj = loader.get_data()
        if loader.check_node():
            raise RuntimeError("Multiple documents found in stream; use load_all")
        return obj

    def load_first(self, data):
        stream = StringIO(data)
        loader = self.make_loader(stream)
        return loader.get_data()

    def load_all(self, data):
        stream = StringIO(data)
        loader = self.make_loader(stream)
        while loader.check_node():
            yield loader.get_data()


class DuplicateVersion(ValueError):
    pass


class CamelRegistry(object):
    frozen = False

    def __init__(self, tag_prefix='!', tag_shorthand=None):
        self.tag_prefix = tag_prefix
        self.tag_shorthand = tag_shorthand

        # type => {version => function)
        self.dumpers = collections.defaultdict(dict)
        self.multi_dumpers = collections.defaultdict(dict)
        # base tag => {version => function}
        self.loaders = collections.defaultdict(dict)

    def freeze(self):
        self.frozen = True

    # Dumping

    def _check_tag(self, tag):
        # Good a place as any, I suppose
        if self.frozen:
            raise RuntimeError("Can't add to a frozen registry")

        if ';' in tag:
            raise ValueError(
                "Tags may not contain semicolons: {0!r}".format(tag))

    def dumper(self, cls, tag, version, inherit=False):
        self._check_tag(tag)

        if inherit:
            store_in = self.multi_dumpers
        else:
            store_in = self.dumpers

        if version in store_in[cls]:
            raise DuplicateVersion

        tag = self.tag_prefix + tag

        if version is None:
            full_tag = tag
        elif isinstance(version, (int, _long)) and version > 0:
            full_tag = "{0};{1}".format(tag, version)
        else:
            raise TypeError(
                "Expected None or a positive integer version; "
                "got {0!r} instead".format(version))

        def decorator(f):
            store_in[cls][version] = functools.partial(
                self.run_representer, f, full_tag)
            return f

        return decorator

    def run_representer(self, representer, tag, dumper, data):
        canon_value = representer(data)
        # Note that we /do not/ support subclasses of the built-in types here,
        # to avoid complications from returning types that have their own
        # custom representers
        canon_type = type(canon_value)
        # TODO this gives no control over flow_style, style, and implicit.  do
        # we intend to figure it out ourselves?
        if canon_type is dict:
            return dumper.represent_mapping(tag, canon_value, flow_style=False)
        elif canon_type is collections.OrderedDict:
            # pyyaml tries to sort the items of a dict, which defeats the point
            # of returning an OrderedDict.  Luckily, it only does this if the
            # value it gets has an 'items' method; otherwise it skips the
            # sorting and iterates the value directly, assuming it'll get
            # key/value pairs.  So pass in the dict's items iterator.
            return dumper.represent_mapping(tag, canon_value.items(), flow_style=False)
        elif canon_type in (tuple, list):
            return dumper.represent_sequence(tag, canon_value, flow_style=False)
        elif canon_type in (int, _long, float, bool, _str, type(None)):
            return dumper.represent_scalar(tag, canon_value)
        else:
            raise TypeError(
                "Representers must return native YAML types, but the representer "
                "for {!r} returned {!r}, which is of type {!r}"
                .format(data, canon_value, canon_type))

    def inject_dumpers(self, dumper, version_locks=None):
        if not version_locks:
            version_locks = {}

        for add_method, dumpers in [
                (dumper.add_representer, self.dumpers),
                (dumper.add_multi_representer, self.multi_dumpers)]:
            for cls, versions in dumpers.items():
                version = version_locks.get(cls, max)
                if versions and version is max:
                    if None in versions:
                        representer = versions[None]
                    else:
                        representer = versions[max(versions)]
                elif version in versions:
                    representer = versions[version]
                else:
                    raise KeyError(
                        "Don't know how to dump version {0!r} of type {1!r}"
                        .format(version, cls))
                add_method(cls, representer)

    # Loading
    # TODO implement "upgrader", which upgrades from one version to another

    def loader(self, tag, version):
        self._check_tag(tag)

        if version in self.loaders[tag]:
            raise DuplicateVersion

        tag = self.tag_prefix + tag

        def decorator(f):
            self.loaders[tag][version] = functools.partial(
                self.run_constructor, f, version)
            return f

        return decorator

    def run_constructor(self, constructor, version, *yaml_args):
        # Two args for add_constructor, three for add_multi_constructor
        if len(yaml_args) == 3:
            loader, suffix, node = yaml_args
            version = int(suffix)
        else:
            loader, node = yaml_args

        if isinstance(node, yaml.ScalarNode):
            data = loader.construct_scalar(node)
        elif isinstance(node, yaml.SequenceNode):
            data = loader.construct_sequence(node, deep=True)
        elif isinstance(node, yaml.MappingNode):
            data = loader.construct_mapping(node, deep=True)
        else:
            raise TypeError("Not a primitive node: {!r}".format(node))
        return constructor(data, version)

    def inject_loaders(self, loader):
        for tag, versions in self.loaders.items():
            # "all" loader overrides everything
            if all in versions:
                if None in versions:
                    loader.add_constructor(tag, versions[None])
                else:
                    loader.add_constructor(tag, versions[all])
                loader.add_multi_constructor(tag + ";", versions[all])
                continue

            # Otherwise, add each constructor individually
            for version, constructor in versions.items():
                if version is None:
                    loader.add_constructor(tag, constructor)
                elif version is any:
                    loader.add_multi_constructor(tag + ";", versions[any])
                    if None not in versions:
                        loader.add_constructor(tag, versions[any])
                else:
                    full_tag = "{0};{1}".format(tag, version)
                    loader.add_constructor(full_tag, constructor)


# YAML's "language-independent types" — not builtins, but supported with
# standard !! tags.  Most of them are built into pyyaml, but OrderedDict is
# curiously overlooked.  Loaded first by default into every Camel object.
# Ref: http://yaml.org/type/
# TODO pyyaml supports tags like !!python/list; do we care?
STANDARD_TYPES = CamelRegistry(tag_prefix=YAML_TAG_PREFIX)


@STANDARD_TYPES.dumper(frozenset, 'set', version=None)
def _dump_frozenset(data):
    return dict.fromkeys(data)


@STANDARD_TYPES.dumper(collections.OrderedDict, 'omap', version=None)
def _dump_ordered_dict(data):
    pairs = []
    for key, value in data.items():
        pairs.append({key: value})
    return pairs


@STANDARD_TYPES.loader('omap', version=None)
def _load_ordered_dict(data, version):
    return collections.OrderedDict(
        pair for datum in data for (pair,) in [datum.items()]
    )


# Extra Python types that don't have native YAML equivalents, but that PyYAML
# supports with !!python/foo tags.  Dumping them isn't supported by default,
# but loading them is, since there's no good reason for it not to be.
# A couple of these dumpers override builtin type support.  For example, tuples
# are dumped as lists by default, but this registry will dump them as
# !!python/tuple.
PYTHON_TYPES = CamelRegistry(tag_prefix=YAML_TAG_PREFIX)


@PYTHON_TYPES.dumper(tuple, 'python/tuple', version=None)
def _dump_tuple(data):
    return list(data)


@STANDARD_TYPES.loader('python/tuple', version=None)
def _load_tuple(data, version):
    return tuple(data)


@PYTHON_TYPES.dumper(complex, 'python/complex', version=None)
def _dump_complex(data):
    ret = repr(data)
    if str is bytes:
        ret = ret.decode('ascii')
    # Complex numbers become (1+2j), but the parens are superfluous
    if ret[0] == '(' and ret[-1] == ')':
        return ret[1:-1]
    else:
        return ret


@STANDARD_TYPES.loader('python/complex', version=None)
def _load_complex(data, version):
    return complex(data)


@PYTHON_TYPES.dumper(frozenset, 'python/frozenset', version=None)  # noqa
def _dump_frozenset(data):
    try:
        return list(sorted(data))
    except TypeError:
        return list(data)


@STANDARD_TYPES.loader('python/frozenset', version=None)
def _load_frozenset(data, version):
    return frozenset(data)


if hasattr(types, 'SimpleNamespace'):
    @PYTHON_TYPES.dumper(types.SimpleNamespace, 'python/namespace', version=None)
    def _dump_simple_namespace(data):
        return data.__dict__

    @STANDARD_TYPES.loader('python/namespace', version=None)
    def _load_simple_namespace(data, version):
        return types.SimpleNamespace(**data)


STANDARD_TYPES.freeze()
PYTHON_TYPES.freeze()
