import json
from lxml import etree


def test_build_payload(mock_pynxos_device):
    """
    Payload format should be as follows:
    [
        {
            'id': 1,
            'jsonrpc': '2.0',
            'method': 'cli',
            'params': {'cmd': 'show hostname', 'version': 1.0}
        }
    ]
    """
    mock_device = mock_pynxos_device
    payload = mock_device.api._build_payload(["show hostname"], method="cli")
    payload = json.loads(payload)
    assert isinstance(payload, list)
    payload_dict = payload[0]
    assert payload_dict["id"] == 1
    assert payload_dict["jsonrpc"] == "2.0"
    assert payload_dict["method"] == "cli"
    assert payload_dict["params"]["cmd"] == "show hostname"
    assert payload_dict["params"]["version"] == 1.0


def test_build_payload_list(mock_pynxos_device):
    """Payload with list of commands (jsonrpc)"""
    mock_device = mock_pynxos_device
    payload = mock_device.api._build_payload(
        ["show hostname", "show version"], method="cli"
    )
    payload = json.loads(payload)
    assert len(payload) == 2
    payload_dict = payload[0]
    assert payload_dict["id"] == 1
    assert payload_dict["jsonrpc"] == "2.0"
    assert payload_dict["method"] == "cli"
    assert payload_dict["params"]["cmd"] == "show hostname"
    assert payload_dict["params"]["version"] == 1.0
    payload_dict = payload[1]
    assert payload_dict["id"] == 2
    assert payload_dict["jsonrpc"] == "2.0"
    assert payload_dict["method"] == "cli"
    assert payload_dict["params"]["cmd"] == "show version"
    assert payload_dict["params"]["version"] == 1.0


def test_build_payload_xml(mock_pynxos_device_xml):
    """
    Payload format should be as follows:
    <?xml version="1.0"?>
    <ins_api>
      <version>1.2</version>
      <type>cli_show</type>
      <chunk>0</chunk>
      <sid>sid</sid>
      <input>show hostname</input>
      <output_format>xml</output_format>
    </ins_api>
    """
    mock_device = mock_pynxos_device_xml
    payload = mock_device.api._build_payload(["show hostname"], method="cli_show")
    xml_root = etree.fromstring(payload)
    assert xml_root.tag == "ins_api"
    version = xml_root.find("./version")
    api_method = xml_root.find("./type")
    sid = xml_root.find("./sid")
    api_cmd = xml_root.find("./input")
    output_format = xml_root.find("./output_format")
    assert version.tag == "version"
    assert version.text == "1.0"
    assert api_method.tag == "type"
    assert api_method.text == "cli_show"
    assert sid.tag == "sid"
    assert sid.text == "sid"
    assert api_cmd.tag == "input"
    assert api_cmd.text == "show hostname"
    assert output_format.tag == "output_format"
    assert output_format.text == "xml"


def test_build_payload_xml_list(mock_pynxos_device_xml):
    """Build payload with list of commands (XML)."""
    mock_device = mock_pynxos_device_xml
    payload = mock_device.api._build_payload(
        ["show hostname", "show version"], method="cli_show"
    )
    xml_root = etree.fromstring(payload)
    assert xml_root.tag == "ins_api"
    version = xml_root.find("./version")
    api_method = xml_root.find("./type")
    sid = xml_root.find("./sid")  # noqa
    api_cmd = xml_root.find("./input")
    output_format = xml_root.find("./output_format")
    assert api_cmd.text == "show hostname ;show version"
    assert version.tag == "version"
    assert version.text == "1.0"
    assert api_method.text == "cli_show"
    assert output_format.text == "xml"


def test_build_payload_xml_config(mock_pynxos_device_xml):
    """Build payload with list of commands (XML)."""
    mock_device = mock_pynxos_device_xml
    payload = mock_device.api._build_payload(
        ["logging history size 200"], method="cli_conf"
    )
    xml_root = etree.fromstring(payload)
    api_method = xml_root.find("./type")
    api_cmd = xml_root.find("./input")
    assert xml_root.tag == "ins_api"
    assert api_cmd.text == "logging history size 200"
    assert api_method.text == "cli_conf"
