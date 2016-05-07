"""Helper functions for the NAPALM base."""

# std libs
import os
import sys

# third party libs
import jinja2
import textfsm

# local modules
import napalm_base.exceptions


def load_template(cls, template_name, template_source=None, template_path=None, **template_vars):

    try:
        if isinstance(template_source, basestring):
            template = jinja2.Template(template_source)
        else:
            current_dir = os.path.dirname(os.path.abspath(sys.modules[cls.__module__].__file__))
            if isinstance(template_path, basestring) and os.path.isdir(template_path) and os.path.isabs(template_path):
                current_dir = os.path.join(template_path, cls.__module__.split('.')[-1])
                # append driver name at the end of the custom path
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

    driver_name = cls.__class__.__name__.replace('Driver', '')
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
    except textfsm.textfsm.TextFSMTemplateError as tfte:
        raise napalm_base.exceptions.TemplateRenderException(
            "Wrong format of TextFSM template {template_name}: {error}".format(
                template_name=template_name,
                error=tfte.message
            )
        )

    objects = fsm_handler.ParseText(raw_text)

    for obj in objects:
        index = 0
        entry = {}
        for entry_value in obj:
            entry[fsm_handler.header[index].lower()] = str(entry_value)
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
                value = str(xpath_result)
    except Exception:  # in case of any exception, returns default
        value = default

    return value


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
