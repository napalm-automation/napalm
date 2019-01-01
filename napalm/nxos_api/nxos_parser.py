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

    intf_list = xml_output.findall(
        ".//{*}ROW_interface/{*}interface", namespaces=namespaces
    )
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


def xml_show_lldp_neighbors(xml_output, namespaces=None):
    """Unified XML Parser for 'show lldp neighbors' output from NX-API or '| xml'."""
    if namespaces is None:
        namespaces = {}

    remote_systems = xml_output.findall(".//{*}chassis_id", namespaces=namespaces)
    remote_systems = [x.text for x in remote_systems]
    local_ports = xml_output.findall(".//{*}l_port_id", namespaces=namespaces)
    local_ports = [x.text for x in local_ports]
    remote_ports = xml_output.findall(".//{*}port_id", namespaces=namespaces)
    remote_ports = [x.text for x in remote_ports]

    if len(local_ports) != len(remote_ports) != len(remote_systems):
        raise ValueError("XML parsing failure in show lldp neighbors")

    lldp_dict = {}
    for local_intf, remote_host, remote_port in zip(
        local_ports, remote_systems, remote_ports
    ):
        lldp_dict.setdefault(local_intf, [])
        lldp_dict[local_intf].append({"hostname": remote_host, "port": remote_port})

    return lldp_dict


def xml_show_lldp_neighbors_detail(xml_output, namespaces=None):
    """Unified XML Parser for 'show lldp neighbors detail' output from NX-API or '| xml'."""
    if namespaces is None:
        namespaces = {}

    import ipdb

    ipdb.set_trace()

    print(etree.tostring(xml_output).decode())

    def xml_text_attribute(xml_output, element_pattern, namespaces):
        """Findall search for XML element_pattern; return text."""
        fields = xml_output.findall(element_pattern, namespaces=namespaces)
        return [x.text for x in fields]

    remote_descr = xml_text_attribute(xml_output, ".//{*}sys_desc", namespaces)
    remote_port_name = xml_text_attribute(xml_output, ".//{*}port_id", namespaces)
    remote_port_descr = xml_text_attribute(xml_output, ".//{*}port_desc", namespaces)
    chassis_id = xml_text_attribute(xml_output, ".//{*}chassis_id", namespaces)
    capabilities = xml_text_attribute(xml_output, ".//{*}capability", namespaces)
    remote_name = xml_text_attribute(xml_output, ".//{*}sys_name", namespaces)
    local_ports = xml_text_attribute(xml_output, ".//{*}l_port_id", namespaces)

    local_port_count = len(local_ports)
    for test_list in (
        remote_descr,
        remote_port_name,
        remote_port_descr,
        chassis_id,
        capabilities,
        remote_name,
    ):
        if len(test_list) != len(local_ports):
            raise ValueError("XML parsing failure in show lldp neighbors detail")

    lldp_dict = {}
    for lldp_entry in zip(
        local_ports,
        remote_descr,
        remote_port_name,
        remote_port_descr,
        chassis_id,
        capabilities,
        remote_name,
    ):
        entry_local_intf, entry_remote_descr, entry_remote_port, entry_remote_port_descr, entry_chassis_id, entry_capabilities, entry_remote_name = (
            lldp_entry
        )
        lldp_dict.setdefault(local_intf, [])
        print(lldp_entry)
        # FIX
        # 1. Capabilities is a bitwise field
        # 2. Not sure if capabilities is enabled capabibilities and available capabilities or something else
        # 3. Default for parent interface
        # 4. Need to integrate with new LLDP solution
        lldp_dict[local_intf].append(
            {
                "remote_port_description": entry_remote_port_descr,
                "remote_port": entry_remote_port,
                "remote_system_description": entry_remote_descr,
                "remote_chassis_id": entry_chassis_id,
                "remote_system_enable_capab": entry_capabilities,
                "parent_interface": "",
                "remote_system_capab": entry_capabilities,
                "remote_system_name": entry_remote_name,
            }
        )
    return lldp_dict
