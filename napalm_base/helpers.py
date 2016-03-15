"""Helper functions for the NAPALM base."""

# std libs
import os
import sys

# third party libs
import jinja2
import textfsm

# local modules
import napalm_base.exceptions


def load_template(cls, template_name, **template_vars):
    """
    Will load a templated configuration on the device.

    :param cls: instance of the driver class
    :param template_name: identifies the template name
    :param template_vars: dictionary with the

    :raise DriverTemplateNotImplemented if no template defined for the device type
    :raise TemplateNotImplemented if the template specified in template_name is not defined
    :raise TemplateRenderException if the user passed wrong arguments to the template
    """
    try:
        current_dir = os.path.dirname(os.path.abspath(sys.modules[cls.__module__].__file__))
        template_dir_path = '{current_dir}/templates'.format(current_dir=current_dir)

        if not os.path.isdir(template_dir_path):
            raise napalm_base.exceptions.DriverTemplateNotImplemented("There's no config template defined.")

        loader = jinja2.FileSystemLoader(template_dir_path)
        environment = jinja2.Environment(loader=loader)
        template = environment.get_template('{template_name}.j2'.format(
            template_name=template_name
        ))
        configuration = template.render(**template_vars)
    except jinja2.exceptions.TemplateNotFound:
        raise napalm_base.exceptions.TemplateNotImplemented(
            "Template {template_name}.j2 not defined under {path}".format(
                template_name=template_name,
                path=template_dir_path
            )
        )
    except jinja2.exceptions.UndefinedError as ue:
        raise napalm_base.exceptions.TemplateRenderException(
            "Unable to render the template: {}".format(ue.message)
        )
    cls.load_merge_candidate(config=configuration)


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
    template_path = '{current_dir}/utils/textfsm_templates/{template_name}.tpl'.format(
        current_dir=current_dir,
        driver_name=driver_name.lower(),
        template_name=template_name
    )

    try:
        fsm_handler = textfsm.TextFSM(open(template_path))
    except IOError:
        raise napalm_base.exceptions.TemplateNotImplemented(
            "TextFSM template {template_name} not defined!".format(
                template_name=template_name
            )
        )
    except textfsm.textfsm.TextFSMTemplateError:
        raise napalm_base.exceptions.TemplateRenderException(
            "Wrong format of template {template_name}".format(
                template_name=template_name
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
