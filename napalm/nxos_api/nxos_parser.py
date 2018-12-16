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
    pipe_xml_trailer  = r"]]>]]>"
    xml_output = re.sub(pipe_xml_trailer, "", xml_output)
    xml_output = xml_output.strip()

    # etree fromstring() requires byte string
    xml_output = xml_output.encode()
    return etree.fromstring(xml_output)


def xml_show_version(xml_output, namespaces=None):
    """Unified XML Parser for 'show version' output from NX-API or '| xml'."""
    if namespaces is None:
        namespaces = {}

    model = xml_output.find(".//chassis_id", namespaces=namespaces)
    hostname = xml_output.find(".//host_name", namespaces=namespaces)
    serial_number = xml_output.find(".//proc_board_id", namespaces=namespaces)
    os_version = xml_output.find(".//sys_ver_str", namespaces=namespaces)
    uptime_days = xml_output.find(".//kern_uptm_days", namespaces=namespaces)
    uptime_hours = xml_output.find(".//kern_uptm_hrs", namespaces=namespaces)
    uptime_mins = xml_output.find(".//kern_uptm_mins", namespaces=namespaces)
    uptime_secs = xml_output.find(".//kern_uptm_secs", namespaces=namespaces)

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
            if 'uptime' in k:
                facts[k] = int(v.text)
            else:
                facts[k] = v.text

    days = facts.pop("uptime_days")
    hours = facts.pop("uptime_hours")
    mins = facts.pop("uptime_mins")
    secs = facts.pop("uptime_secs")
    uptime = uptime_calc(days=days, hours=hours, mins=mins, secs=secs)
    facts["uptime"] = uptime
    from pprint import pprint
    pprint(facts)
    return facts


if __name__ == "__main__":

    xml_out_from_cli = """<?xml version="1.0" encoding="ISO-8859-1"?>
    <nf:rpc-reply xmlns:nf="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns="http://www.cisco.com/nxos:1.0:sysmgrcli">
     <nf:data>
      <show>
       <version>
        <__XML__OPT_Cmd_sysmgr_show_version___readonly__>
         <__readonly__>
          <header_str>Cisco Nexus Operating System (NX-OS) Software
    TAC support: http://www.cisco.com/tac
    Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
    Copyright (c) 2002-2016, Cisco Systems, Inc. All rights reserved.
    The copyrights to certain works contained herein are owned by
    other third parties and are used and distributed under license.
    Some parts of this software are covered under the GNU Public
    License. A copy of the license is available at
    http://www.gnu.org/licenses/gpl.html.
    
    NX-OSv is a demo version of the Nexus Operating System
    </header_str>
          <loader_ver_str>N/A</loader_ver_str>
          <kickstart_ver_str>7.3(1)D1(1) [build 7.3(1)D1(0.10)]</kickstart_ver_str>
          <sys_ver_str>7.3(1)D1(1) [build 7.3(1)D1(0.10)]</sys_ver_str>
          <kick_file_name>bootflash:///titanium-d1-kickstart.7.3.1.D1.0.10.bin</kick_file_name>
          <kick_cmpl_time> 1/11/2016 16:00:00</kick_cmpl_time>
          <kick_tmstmp>02/22/2016 23:39:33</kick_tmstmp>
          <isan_file_name>bootflash:///titanium-d1.7.3.1.D1.0.10.bin</isan_file_name>
          <isan_cmpl_time> 1/11/2016 16:00:00</isan_cmpl_time>
          <isan_tmstmp>02/23/2016 01:43:36</isan_tmstmp>
          <chassis_id>NX-OSv Chassis</chassis_id>
          <module_id>NX-OSv Supervisor Module</module_id>
          <cpu_name>Intel(R) Xeon(R) CPU E5-2670</cpu_name>
          <memory>4002196</memory>
          <mem_type>kB</mem_type>
          <proc_board_id>TM6012EC74B</proc_board_id>
          <host_name>nxos1</host_name>
          <bootflash_size>1582402</bootflash_size>
          <kern_uptm_days>101</kern_uptm_days>
          <kern_uptm_hrs>18</kern_uptm_hrs>
          <kern_uptm_mins>50</kern_uptm_mins>
          <kern_uptm_secs>44</kern_uptm_secs>
          <manufacturer>Cisco Systems, Inc.</manufacturer>
         </__readonly__>
        </__XML__OPT_Cmd_sysmgr_show_version___readonly__>
       </version>
      </show>
     </nf:data>
    </nf:rpc-reply>
    ]]>]]>
    """

    import ipdb
    ipdb.set_trace()
    namespace_map = {
        None: 'http://www.cisco.com/nxos:1.0:sysmgrcli',
        'nf': 'urn:ietf:params:xml:ns:netconf:base:1.0'
    }

    xml_output = xml_pipe_normalization(xml_out_from_cli)
    output = xml_parse_show_version(xml_output, namespaces=namespace_map)
 
    xml_out_from_api = """
    <?xml version="1.0"?>
    <ins_api>
      <type>cli_show</type>
      <version>1.2</version>
      <sid>eoc</sid>
      <outputs>
        <output>
          <body>
          <header_str>Cisco Nexus Operating System (NX-OS) Software
    TAC support: http://www.cisco.com/tac
    Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html
    Copyright (c) 2002-2016, Cisco Systems, Inc. All rights reserved.
    The copyrights to certain works contained herein are owned by
    other third parties and are used and distributed under license.
    Some parts of this software are covered under the GNU Public
    License. A copy of the license is available at
    http://www.gnu.org/licenses/gpl.html.
    
    NX-OSv is a demo version of the Nexus Operating System
    </header_str>
          <loader_ver_str>N/A</loader_ver_str>
          <kickstart_ver_str>7.3(1)D1(1) [build 7.3(1)D1(0.10)]</kickstart_ver_str>
          <sys_ver_str>7.3(1)D1(1) [build 7.3(1)D1(0.10)]</sys_ver_str>
          <kick_file_name>bootflash:///titanium-d1-kickstart.7.3.1.D1.0.10.bin</kick_file_name>
          <kick_cmpl_time> 1/11/2016 16:00:00</kick_cmpl_time>
          <kick_tmstmp>02/22/2016 23:39:33</kick_tmstmp>
          <isan_file_name>bootflash:///titanium-d1.7.3.1.D1.0.10.bin</isan_file_name>
          <isan_cmpl_time> 1/11/2016 16:00:00</isan_cmpl_time>
          <isan_tmstmp>02/23/2016 01:43:36</isan_tmstmp>
          <chassis_id>NX-OSv Chassis</chassis_id>
          <module_id>NX-OSv Supervisor Module</module_id>
          <cpu_name>Intel(R) Xeon(R) CPU E5-2670</cpu_name>
          <memory>4002196</memory>
          <mem_type>kB</mem_type>
          <proc_board_id>TM6012EC74B</proc_board_id>
          <host_name>nxos1</host_name>
          <bootflash_size>1582402</bootflash_size>
          <kern_uptm_days>101</kern_uptm_days>
          <kern_uptm_hrs>18</kern_uptm_hrs>
          <kern_uptm_mins>51</kern_uptm_mins>
          <kern_uptm_secs>56</kern_uptm_secs>
          <manufacturer>Cisco Systems, Inc.</manufacturer>
         </body>
          <input>show version</input>
          <msg>Success</msg>
          <code>200</code>
        </output>
      </outputs>
    </ins_api>
    """
    
