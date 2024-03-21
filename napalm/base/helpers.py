"""Helper functions for the NAPALM base."""

import ipaddress
import itertools
import logging

# std libs
import os
import re
import sys
from typing import Optional, Dict, Any, List, Union, Tuple, TypeVar, Callable
from collections.abc import Iterable

# third party libs
import jinja2
import textfsm
from lxml import etree
from netaddr import EUI
from netaddr import mac_unix
from netutils.config.parser import IOSConfigParser

# Do not remove the below imports, functions were moved to netutils, but to not
# break backwards compatibility, these should remain
from netutils.interface import abbreviated_interface_name  # noqa
from netutils.interface import canonical_interface_name  # noqa
from netutils.constants import BASE_INTERFACES as base_interfaces  # noqa
from netutils.constants import REVERSE_MAPPING as reverse_mapping  # noqa
from netutils.interface import split_interface as _split_interface

try:
    from ttp import quick_parse as ttp_quick_parse

    TTP_INSTALLED = True
except ImportError:
    TTP_INSTALLED = False

# local modules
import napalm.base.exceptions
from napalm.base import constants
from napalm.base.models import ConfigDict
from napalm.base.utils.jinja_filters import CustomJinjaFilters

T = TypeVar("T")
R = TypeVar("R")

# -------------------------------------------------------------------
# Functional Global
# -------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------
# helper classes -- will not be exported
# -------------------------------------------------------------------
class _MACFormat(mac_unix):
    pass


_MACFormat.word_fmt = "%.2X"


# -------------------------------------------------------------------
# callable helpers
# -------------------------------------------------------------------
def load_template(
    cls: "napalm.base.NetworkDriver",
    template_name: str,
    template_source: Optional[str] = None,
    template_path: Optional[str] = None,
    openconfig: bool = False,
    jinja_filters: Dict = {},
    **template_vars: Any,
) -> None:
    try:
        search_path = []
        if isinstance(template_source, str):
            template = jinja2.Template(template_source)
        else:
            if template_path is not None:
                if (
                    isinstance(template_path, str)
                    and os.path.isdir(template_path)
                    and os.path.isabs(template_path)
                ):
                    # append driver name at the end of the custom path
                    search_path.append(
                        os.path.join(template_path, cls.__module__.split(".")[-1])
                    )
                else:
                    raise IOError(
                        "Template path does not exist: {}".format(template_path)
                    )
            else:
                # Search modules for template paths
                for c in cls.__class__.mro():
                    if c is object:
                        continue
                    module = sys.modules[c.__module__].__file__
                    if module:
                        path = os.path.abspath(module)
                    else:
                        continue
                    if path:
                        path_to_append = os.path.dirname(path)
                    else:
                        continue
                    if path_to_append:
                        search_path.append(path_to_append)

            if openconfig:
                search_path = ["{}/oc_templates".format(s) for s in search_path]
            else:
                search_path = ["{}/templates".format(s) for s in search_path]

            loader = jinja2.FileSystemLoader(search_path)
            environment = jinja2.Environment(loader=loader)

            for filter_name, filter_function in itertools.chain(
                CustomJinjaFilters.filters().items(), jinja_filters.items()
            ):
                environment.filters[filter_name] = filter_function

            template = environment.get_template(
                "{template_name}.j2".format(template_name=template_name)
            )
        configuration = template.render(**template_vars)
    except jinja2.exceptions.TemplateNotFound:
        raise napalm.base.exceptions.TemplateNotImplemented(
            "Config template {template_name}.j2 not found in search path: {sp}".format(
                template_name=template_name, sp=search_path
            )
        )
    except (
        jinja2.exceptions.UndefinedError,
        jinja2.exceptions.TemplateSyntaxError,
    ) as jinjaerr:
        raise napalm.base.exceptions.TemplateRenderException(
            "Unable to render the Jinja config template {template_name}: {error}".format(
                template_name=template_name, error=str(jinjaerr)
            )
        )
    return cls.load_merge_candidate(config=configuration)


def netutils_parse_parents(
    parent: str, child: str, config: Union[str, List[str]]
) -> List[str]:
    """
    Use Netutils to find parent lines that contain a specific child line.

    :param parent: The parent line to search for
    :param child:  The child line required under the given parent
    :param config: The device running/startup config
    """
    # Check if the config is a list, if it is a list, then join it to make a string.
    if isinstance(config, list):
        config = "\n".join(config)
        config = config + "\n"

    # Config tree is the entire configuration in a tree format,
    # followed by getting the individual lines that has the formats:
    # ConfigLine(config_line=' ip address 192.0.2.10 255.255.255.0',
    # parents=('interface GigabitEthernet1',))
    # ConfigLine(config_line='Current configuration : 1624 bytes', parents=())
    config_tree = IOSConfigParser(str(config))
    configuration_lines = config_tree.build_config_relationship()

    # Return config is the list that will be returned
    return_config = []

    # Loop over each of the configuration lines
    for line in configuration_lines:
        # Loop over any line that has a parent line. If there are no parents for a line item then
        # the parents is an empty tuple.
        for parent_line in line.parents:
            if (
                child in line.config_line
                and re.match(parent, parent_line) is not None
                and parent_line not in return_config
            ):
                return_config.append(parent_line)

    return return_config


def netutils_parse_objects(
    cfg_section: str, config: Union[str, List[str]]
) -> List[str]:
    """
    Use Netutils to find and return a section of Cisco IOS config.
    Similar to "show run | section <cfg_section>"

    :param cfg_section: The section of the config to return eg. "router bgp"
    :param config: The running/startup config of the device to parse
    """
    # Check if the config is a list, if it is a list, then join it to make a string.
    if isinstance(config, list):
        config = "\n".join(config)
        config = config + "\n"

    # Config tree is the entire configuration in a tree format,
    # followed by getting the individual lines that has the formats:
    # ConfigLine(config_line=' ip address 192.0.2.10 255.255.255.0',
    # parents=('interface GigabitEthernet1',))
    # ConfigLine(config_line='Current configuration : 1624 bytes', parents=())
    config_tree = IOSConfigParser(str(config))
    lines = config_tree.build_config_relationship()

    # Return config is the list that will be returned
    return_config = []
    for line in lines:
        # The parent configuration is expected on the function that this is replacing,
        # add the parent line to the base of the return_config
        if cfg_section in line.config_line:
            return_config.append(line.config_line)
        # Check if the tuple is greater than 0
        if len(line.parents) > 0:
            # Check the eldest parent, if that is part of the config section, then append
            # the current line being checked to it.
            if cfg_section in line.parents[0]:
                return_config.append(line.config_line)

    return return_config


def regex_find_txt(pattern: str, text: str, default: str = "") -> Any:
    """ ""
    RegEx search for pattern in text. Will try to match the data type of the "default" value
    or return the default value if no match is found.
    This is to parse IOS config like below:
    regex_find_txt(r"remote-as (65000)", "neighbor 10.0.0.1 remote-as 65000", default=0)
    RETURNS: 65001

    :param pattern: RegEx pattern to match on
    :param text: String of text ot search for "pattern" in
    :param default="": Default value and type to return on error
    """
    text = str(text)
    value = re.findall(pattern, text)
    try:
        if not value:
            logger.error("No Regex match found for pattern: %s" % (str(pattern)))
            raise Exception("No Regex match found for pattern: %s" % (str(pattern)))
        if not isinstance(value, type(default)):
            if isinstance(value, list) and len(value) == 1:
                value = value[0]
            value = type(default)(value)  # type: ignore
    except Exception as regexFindTxtErr01:  # in case of any exception, returns default
        logger.error(
            'errorCode="regexFindTxtErr01" in napalm.base.helpers with systemMessage="%s"\
                 message="Error while attempting to find regex pattern, \
                      default to empty string"'
            % (regexFindTxtErr01)
        )
        value = default  # type: ignore
    return value


def textfsm_extractor(
    cls: "napalm.base.NetworkDriver", template_name: str, raw_text: str
) -> List[Dict]:
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
    fsm_handler = None
    for c in cls.__class__.mro():
        if c is object:
            continue
        module = sys.modules[c.__module__].__file__
        if module:
            current_dir = os.path.dirname(os.path.abspath(module))
        else:
            continue
        template_dir_path = "{current_dir}/utils/textfsm_templates".format(
            current_dir=current_dir
        )
        template_path = "{template_dir_path}/{template_name}.tpl".format(
            template_dir_path=template_dir_path, template_name=template_name
        )

        try:
            with open(template_path) as f:
                fsm_handler = textfsm.TextFSM(f)

                for obj in fsm_handler.ParseText(raw_text):
                    entry = {}
                    for index, entry_value in enumerate(obj):
                        entry[fsm_handler.header[index].lower()] = entry_value
                    textfsm_data.append(entry)

                return textfsm_data
        except IOError as textfsmExtractorErr01:  # Template not present in this class
            logger.error(
                'errorCode="textfsmExtractorErr01" in napalm.base.helpers with systemMessage="%s"\
                message="Error while attempting to apply a textfsm template to  \
                format the output returned from the device,\
                continuing loop..."'
                % (textfsmExtractorErr01)
            )
            continue  # Continue up the MRO
        except textfsm.TextFSMTemplateError as tfte:
            logging.error(
                "Wrong format of TextFSM template {template_name}: {error}".format(
                    template_name=template_name, error=str(tfte)
                )
            )
            raise napalm.base.exceptions.TemplateRenderException(
                "Wrong format of TextFSM template {template_name}: {error}".format(
                    template_name=template_name, error=str(tfte)
                )
            )

    raise napalm.base.exceptions.TemplateNotImplemented(
        "TextFSM template {template_name}.tpl is not defined under {path}".format(
            template_name=template_name, path=template_dir_path
        )
    )


def ttp_parse(
    cls: "napalm.base.NetworkDriver",
    template: str,
    raw_text: str,
    structure: str = "flat_list",
) -> Union[None, List, Dict]:
    """
    Applies a TTP template over a raw text and return the parsing results.

    Main usage of this method will be to extract data form a non-structured output
    from a network device and return parsed values.

    :param cls: Instance of the driver class
    :param template: Specifies the name or the content of the template to be used
    :param raw_text: Text output as the devices prompts on the CLI
    :param structure: Results structure to apply to parsing results
    :return: parsing results structure

    ``template`` can be inline TTP template string, reference to TTP Templates
    repository template in a form of ``ttp://path/to/template`` or name of template
    file within ``{NAPALM_install_dir}/utils/ttp_templates/{template}.txt`` folder.
    """
    if not TTP_INSTALLED:
        msg = "\nTTP is not installed. Please PIP install ttp:\n" "pip install ttp\n"
        raise napalm.base.exceptions.ModuleImportError(msg)

    result = None

    for c in cls.__class__.mro():
        if c is object:
            continue
        module = sys.modules[c.__module__].__file__
        if module:
            current_dir = os.path.dirname(os.path.abspath(module))
        else:
            continue
        template_dir_path = "{current_dir}/utils/ttp_templates".format(
            current_dir=current_dir
        )

        # check if inline template given, use it as is
        if "{{" in template and "}}" in template:
            template = template
        # check if template from ttp_templates repo, use it as is
        elif template.startswith("ttp://"):
            template = template
        # default to using template in NAPALM folder
        else:
            template = "{template_dir_path}/{template}.txt".format(
                template_dir_path=template_dir_path, template=template
            )
            if not os.path.exists(template):
                msg = "Template '{template}' not found".format(template=template)
                logging.error(msg)
                raise napalm.base.exceptions.TemplateRenderException(msg)

        # parse data
        try:
            result = ttp_quick_parse(
                data=str(raw_text),
                template=template,
                result_kwargs={"structure": structure},
                parse_kwargs={"one": True},
            )
            break
        except Exception as e:
            msg = "TTP template:\n'{template}'\nError: {error}".format(
                template=template, error=e
            )
            logging.exception(e)
            logging.error(msg)
            raise napalm.base.exceptions.TemplateRenderException(msg)

    return result


def find_txt(
    xml_tree: etree._Element,
    path: str,
    default: str = "",
    namespaces: Optional[Dict] = None,
) -> str:
    """
    Extracts the text value from an XML tree, using XPath.
    In case of error or text element unavailability, will return a default value.

    :param xml_tree:   the XML Tree object. Assumed is <type 'lxml.etree._Element'>.
    :param path:       XPath to be applied, in order to extract the desired data.
    :param default:    Value to be returned in case of error.
    :param namespaces: prefix-namespace mappings to process XPath
    :return: a str value.
    """
    value = ""
    try:
        xpath_applied = xml_tree.xpath(
            path, namespaces=namespaces
        )  # will consider the first match only
        xpath_length = len(xpath_applied)  # get a count of items in XML tree
        if xpath_length and xpath_applied[0] is not None:
            xpath_result = xpath_applied[0]
            if isinstance(xpath_result, type(xml_tree)):
                if xpath_result.text:
                    value = xpath_result.text.strip()
                else:
                    value = default
            else:
                value = xpath_result
        else:
            if xpath_applied == "":
                logger.debug(
                    "Unable to find the specified-text-element/XML path: %s in  \
                        the XML tree provided. Total Items in XML tree: %d "
                    % (path, xpath_length)
                )
    except Exception as findTxtErr01:  # in case of any exception, returns default
        logger.error(findTxtErr01)
        value = default
    return str(value)


def convert(to: Callable[[T], R], who: Optional[T], default: Optional[R] = None) -> R:
    """
    Converts data to a specific datatype.
    In case of error, will return a default value.

    :param to:      datatype to be casted to.
    :param who:     value to cast.
    :param default: default value to return in case of an error with the conversion function.
    :return:        the result of the cast or a default value.
    """
    if default is None:
        # Mypy is currently unable to resolve the Optional[R] correctly, therefore the following
        # assignments to 'default' need a 'type: ignore' statement.
        # Ref: https://github.com/python/mypy/issues/8708
        if to in [str, ip, mac]:
            default = ""  # type: ignore
        elif to in [float, int]:
            default = 0  # type: ignore
        elif to == bool:
            default = False  # type: ignore
        elif to == list:
            default = []  # type: ignore
        else:
            raise ValueError(
                f"Can't convert with callable {to} - no default is defined for this type."
            )

    # This is safe because the None-case if handled above. This needs to be here because Mypy is
    # unable to infer that 'default' is in fact not None based of the chained if-statements above.
    assert default is not None

    if who is None:
        return default
    try:
        return to(who)
    except:  # noqa
        return default


def mac(raw: str) -> str:
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
    if raw.endswith(":"):
        flat_raw = raw.replace(":", "")
        raw = "{flat_raw}{zeros_stuffed}".format(
            flat_raw=flat_raw, zeros_stuffed="0" * (12 - len(flat_raw))
        )
    return str(EUI(raw, dialect=_MACFormat))


def ip(addr: str, version: Optional[int] = None) -> str:
    """
    Converts a raw string to a valid IP address. Optional version argument will detect that \
    object matches specified version.

    Motivation: the groups of the IP addreses may contain leading zeros. IPv6 addresses can \
    contain sometimes uppercase characters. E.g.: 2001:0dB8:85a3:0000:0000:8A2e:0370:7334 has \
    the same logical value as 2001:db8:85a3::8a2e:370:7334. However, their values as strings are \
    not the same.

    :param raw: the raw string containing the value of the IP Address
    :param version: insist on a specific IP address version.
    :type version: int, optional.
    :return: a string containing the IP Address in a standard format (no leading zeros, \
    zeros-grouping, lowercase)

    Example:

    .. code-block:: python

        >>> ip('2001:0dB8:85a3:0000:0000:8A2e:0370:7334')
        u'2001:db8:85a3::8a2e:370:7334'
    """
    scope = ""
    if "%" in addr:
        addr, scope = addr.split("%", 1)
    addr_obj = ipaddress.ip_address(addr)
    if version and addr_obj.version != version:
        raise ValueError("{} is not an ipv{} address".format(addr, version))
    if addr_obj.version == 6 and addr_obj.ipv4_mapped is not None:
        return_addr = "%s:%s" % ("::ffff", addr_obj.ipv4_mapped)
    else:
        return_addr = str(addr_obj)
    if scope:
        return_addr = "%s%%%s" % (return_addr, scope)
    return return_addr


def as_number(as_number_val: str) -> int:
    """Convert AS Number to standardized asplain notation as an integer."""
    as_number_str = str(as_number_val)
    if "." in as_number_str:
        big, little = as_number_str.split(".")
        return (int(big) << 16) + int(little)
    else:
        return int(as_number_str)


def split_interface(intf_name: str) -> Tuple[str, str]:
    """Split an interface name based on first digit, slash, or space match."""
    return _split_interface(interface=intf_name)


def transform_lldp_capab(capabilities: Union[str, Any]) -> List[str]:
    if capabilities and isinstance(capabilities, str):
        capabilities = capabilities.strip().lower().split(",")
        return sorted(
            [constants.LLDP_CAPAB_TRANFORM_TABLE[c.strip()] for c in capabilities]
        )
    else:
        return []


def generate_regex_or(filters: Iterable) -> str:
    """
    Build a regular expression logical-or from a list/tuple of regex patterns.

    This allows a single regular expression operation to be used in contexts when a loop
    and multiple patterns would otherwise be necessary.

    For example, (pattern1|pattern2|pattern3)

    Return the pattern.
    """
    if isinstance(filters, str) or not isinstance(filters, Iterable):
        raise ValueError("filters argument must be an iterable, but can't be a string.")

    return_pattern = r"("
    for pattern in filters:
        return_pattern += rf"{pattern}|"
    return_pattern += r")"
    return return_pattern


def sanitize_config(config: str, filters: Dict) -> str:
    """
    Given a dictionary of filters, remove sensitive data from the provided config.
    """
    for filter_, replace in filters.items():
        config = re.sub(filter_, replace, config, flags=re.M)
    return config


def sanitize_configs(configs: ConfigDict, filters: Dict) -> ConfigDict:
    """
    Apply sanitize_config on the dictionary of configs typically returned by
    the get_config method.
    """
    for cfg_name, config in configs.items():
        assert isinstance(config, str)
        if config.strip():
            configs[cfg_name] = sanitize_config(config, filters)  # type: ignore
    return configs
