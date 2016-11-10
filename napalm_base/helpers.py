"""Helper functions for the NAPALM base."""

# Python3 support
from __future__ import print_function
from __future__ import unicode_literals

# std libs
import os
import sys

# third party libs
import jinja2
import jtextfsm as textfsm
from netaddr import EUI
from netaddr import mac_unix
from netaddr import IPAddress

# local modules
import napalm_base.exceptions
from napalm_base.utils.jinja_filters import CustomJinjaFilters
from napalm_base.utils import py23_compat


# ----------------------------------------------------------------------------------------------------------------------
# helper classes -- will not be exported
# ----------------------------------------------------------------------------------------------------------------------
class _MACFormat(mac_unix):
    pass


_MACFormat.word_fmt = '%.2X'


# ----------------------------------------------------------------------------------------------------------------------
# callable helpers
# ----------------------------------------------------------------------------------------------------------------------
def load_template(cls, template_name, template_source=None, template_path=None,
                  openconfig=False, **template_vars):
    try:
        if isinstance(template_source, py23_compat.string_types):
            template = jinja2.Template(template_source)
        else:
            current_dir = os.path.dirname(os.path.abspath(sys.modules[cls.__module__].__file__))
            if (isinstance(template_path, py23_compat.string_types) and
                    os.path.isdir(template_path) and os.path.isabs(template_path)):
                current_dir = os.path.join(template_path, cls.__module__.split('.')[-1])
                # append driver name at the end of the custom path

            if openconfig:
                template_dir_path = '{current_dir}/oc_templates'.format(current_dir=current_dir)
            else:
                template_dir_path = '{current_dir}/templates'.format(current_dir=current_dir)

            if not os.path.isdir(template_dir_path):
                raise napalm_base.exceptions.DriverTemplateNotImplemented(
                        '''Config template dir does not exist: {path}.
                        Please create it and add driver-specific templates.'''.format(
                            path=template_dir_path
                        )
                    )

            loader = jinja2.FileSystemLoader(template_dir_path)
            environment = jinja2.Environment(loader=loader)

            for filter_name, filter_function in CustomJinjaFilters.filters().items():
                environment.filters[filter_name] = filter_function

            template = environment.get_template('{template_name}.j2'.format(
                template_name=template_name
            ))
        configuration = template.render(**template_vars)
    except jinja2.exceptions.TemplateNotFound:
        raise napalm_base.exceptions.TemplateNotImplemented(
            "Config template {template_name}.j2 is not defined under {path}".format(
                template_name=template_name,
                path=template_dir_path
            )
        )
    except (jinja2.exceptions.UndefinedError, jinja2.exceptions.TemplateSyntaxError) as jinjaerr:
        raise napalm_base.exceptions.TemplateRenderException(
            "Unable to render the Jinja config template {template_name}: {error}".format(
                template_name=template_name,
                error=jinjaerr.message
            )
        )
    return cls.load_merge_candidate(config=configuration)


def textfsm_extractor(cls, template_name, raw_text):
    """
    Applies a TextFSM template over a raw text and return the matching table.

    Main usage of this method will be to extract data form a non-structured output
    from a network device and return the values in a table format.

    :param cls: Instance of the driver class
    :param template_name: Specifies the name of the template to be used
    :param raw_text: Text output as the devices prompts on the CLI
    :return: table-like list of entries
    """
    textfsm_data = list()
    cls.__class__.__name__.replace('Driver', '')
    current_dir = os.path.dirname(os.path.abspath(sys.modules[cls.__module__].__file__))
    template_dir_path = '{current_dir}/utils/textfsm_templates'.format(
        current_dir=current_dir
    )
    template_path = '{template_dir_path}/{template_name}.tpl'.format(
        template_dir_path=template_dir_path,
        template_name=template_name
    )

    try:
        fsm_handler = textfsm.TextFSM(open(template_path))
    except IOError:
        raise napalm_base.exceptions.TemplateNotImplemented(
            "TextFSM template {template_name}.tpl is not defined under {path}".format(
                template_name=template_name,
                path=template_dir_path
            )
        )
    except textfsm.TextFSMTemplateError as tfte:
        raise napalm_base.exceptions.TemplateRenderException(
            "Wrong format of TextFSM template {template_name}: {error}".format(
                template_name=template_name,
                error=py23_compat.text_type(tfte)
            )
        )

    objects = fsm_handler.ParseText(raw_text)

    for obj in objects:
        index = 0
        entry = {}
        for entry_value in obj:
            entry[fsm_handler.header[index].lower()] = entry_value
            index += 1
        textfsm_data.append(entry)

    return textfsm_data


def find_txt(xml_tree, path, default=''):
    """
    Extracts the text value from an XML tree, using XPath.
    In case of error, will return a default value.

    :param xml_tree: the XML Tree object. Assumed is <type 'lxml.etree._Element'>.
    :param path:     XPath to be applied, in order to extract the desired data.
    :param default:  Value to be returned in case of error.
    :return: a str value.
    """
    value = ''
    try:
        xpath_applied = xml_tree.xpath(path)  # will consider the first match only
        if len(xpath_applied) and xpath_applied[0] is not None:
            xpath_result = xpath_applied[0]
            if isinstance(xpath_result, type(xml_tree)):
                value = xpath_result.text.strip()
            else:
                value = xpath_result
    except Exception:  # in case of any exception, returns default
        value = default
    return py23_compat.text_type(value)


def convert(to, who, default=u''):
    """
    Converts data to a specific datatype.
    In case of error, will return a default value.

    :param to:      datatype to be casted to.
    :param who:     value to cast.
    :param default: value to return in case of error.
    :return: a str value.
    """
    if who is None:
        return default
    try:
        return to(who)
    except:
        return default


def mac(raw):
    """
    Converts a raw string to a standardised MAC Address EUI Format.

    :param raw: the raw string containing the value of the MAC Address
    :return: a string with the MAC Address in EUI format

    Example:

    .. code-block:: python

        >>> mac('0123.4567.89ab')
        u'01:23:45:67:89:AB'

    Some vendors like Cisco return MAC addresses like a9:c5:2e:7b:6: which is not entirely valid
    (with respect to EUI48 or EUI64 standards). Therefore we need to stuff with trailing zeros

    Example
    >>> mac('a9:c5:2e:7b:6:')
    u'A9:C5:2E:7B:60:00'

    If Cisco or other obscure vendors use their own standards, will throw an error and we can fix
    later, however, still works with weird formats like:

    >>> mac('123.4567.89ab')
    u'01:23:45:67:89:AB'
    >>> mac('23.4567.89ab')
    u'00:23:45:67:89:AB'
    """
    if raw.endswith(':'):
        flat_raw = raw.replace(':', '')
        raw = '{flat_raw}{zeros_stuffed}'.format(
            flat_raw=flat_raw,
            zeros_stuffed='0'*(12-len(flat_raw))
        )
    return py23_compat.text_type(EUI(raw, dialect=_MACFormat))


def ip(addr):
    """
    Converts a raw string to a valid IP address.

    Motivation: the groups of the IP addreses may contain leading zeros. IPv6 addresses can \
    contain sometimes uppercase characters. E.g.: 2001:0dB8:85a3:0000:0000:8A2e:0370:7334 has \
    the same logical value as 2001:db8:85a3::8a2e:370:7334. However, their values as strings are \
    not the same.

    :param raw: the raw string containing the value of the IP Address
    :return: a string containing the IP Address in a standard format (no leading zeros, \
    zeros-grouping, lowercase)

    Example:

    .. code-block:: python

        >>> ip('2001:0dB8:85a3:0000:0000:8A2e:0370:7334')
        u'2001:db8:85a3::8a2e:370:7334'
    """
    return py23_compat.text_type(IPAddress(addr))
