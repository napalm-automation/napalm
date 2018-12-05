import re
from lxml import etree


def xml_pipe_normalization(xml_output):
    """Convert string output from '| xml' to lxml etree."""
    # NX-OS appends ]]>]]> to some of the '| xml' output (remove this)
    pipe_xml_trailer  = r"]]>]]>"
    xml_output = re.sub(pipe_xml_trailer, "", xml_output)
    xml_output = xml_output.strip()

    # etree fromstring() requires byte string
    xml_output = xml_output.encode()
    return etree.fromstring(xml_output)


def xml_parse_show_version(xml_output, namespaces=None):
    """Unified XML Parser for 'show version' output from NX-API or '| xml'."""

    if namespaces is None:
        namespaces = {}

    model = xml_output.find(".//chassis_id", namespaces=namespaces)
    hostname = xml_output.find(".//host_name", namespaces=namespaces)
    serial_number = xml_output.find(".//proc_board_id", namespaces=namespaces)
    os_version = xml_output.find(".//sys_ver_str", namespaces=namespaces)

    facts = {
        "model": model,
        "hostname": hostname,
        "serial_number", serial_number,
        "os_version": os_version,
    }

    for k, v in facts.items():
        if v is None:
           raise ValueError("XML Parsing Error")
        else:
            facts[k] = v.text

    from pprint import pprint
    pprint(facts)

    # uptime_days = xml_output.find("./body/kern_uptm_days").text
    # uptime_hours = xml_output.find("./body/kern_uptm_hrs").text
    # uptime_mins = xml_output.find("./body/kern_uptm_mins").text
    # uptime_secs = xml_output.find("./body/kern_uptm_secs").text
