import re
from lxml import etree


def uptime_calc(days=0, hours=0, mins=0, secs=0):
    uptime = 0
    uptime += days * 24 * 60 * 60
    uptime += hours * 60 * 60
    uptime += mins * 60
    uptime += secs
    return uptime


def xml_pipe_normalization(xml_output):
    """Convert string output from '| xml' to lxml etree."""
    # NX-OS appends ]]>]]> to some of the '| xml' output (remove this)
    pipe_xml_trailer = r"]]>]]>"
    xml_output = re.sub(pipe_xml_trailer, "", xml_output)
    xml_output = xml_output.strip()

    # etree fromstring() requires byte string
    xml_output = xml_output.encode()
    return etree.fromstring(xml_output)


def xml_show_hostname(xml_output, namespaces=None):
    """Unified XML Parser for 'hostname' output from NX-API or '| xml'."""
    if namespaces is None:
        namespaces = {}
    hostname = xml_output.find(".//{*}hostname", namespaces=namespaces)
    return hostname.text if hostname is not None else ""


def xml_show_interface(xml_output, namespaces=None):
    """Unified XML Parser for 'show interface brief' output from NX-API or '| xml'."""
    if namespaces is None:
        namespaces = {}

    intf_list = xml_output.findall(".//{*}ROW_interface/{*}interface", namespaces=namespaces)
    if intf_list is not None:
        return [intf.text for intf in intf_list]
    else:
        return []


def xml_show_version(xml_output, namespaces=None):
    """Unified XML Parser for 'show version' output from NX-API or '| xml'."""
    if namespaces is None:
        namespaces = {}

    model = xml_output.find(".//{*}chassis_id", namespaces=namespaces)
    hostname = xml_output.find(".//{*}host_name", namespaces=namespaces)
    serial_number = xml_output.find(".//{*}proc_board_id", namespaces=namespaces)
    os_version = xml_output.find(".//{*}sys_ver_str", namespaces=namespaces)
    uptime_days = xml_output.find(".//{*}kern_uptm_days", namespaces=namespaces)
    uptime_hours = xml_output.find(".//{*}kern_uptm_hrs", namespaces=namespaces)
    uptime_mins = xml_output.find(".//{*}kern_uptm_mins", namespaces=namespaces)
    uptime_secs = xml_output.find(".//{*}kern_uptm_secs", namespaces=namespaces)

    facts = {
        "model": model,
        "hostname": hostname,
        "serial_number": serial_number,
        "os_version": os_version,
        "uptime_days": uptime_days,
        "uptime_hours": uptime_hours,
        "uptime_mins": uptime_mins,
        "uptime_secs": uptime_secs,
    }

    for k, v in facts.items():
        if v is None:
            raise ValueError("XML Parsing Error")
        else:
            if "uptime" in k:
                facts[k] = int(v.text)
            else:
                facts[k] = v.text

    days = facts.pop("uptime_days")
    hours = facts.pop("uptime_hours")
    mins = facts.pop("uptime_mins")
    secs = facts.pop("uptime_secs")
    uptime = uptime_calc(days=days, hours=hours, mins=mins, secs=secs)
    facts["uptime"] = uptime
    return facts
