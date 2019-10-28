import pytest
from napalm.nxapi_plumbing import NXAPICommandError


def test_pynxos_attributes_xml(mock_pynxos_device_xml):
    pynxos_device = mock_pynxos_device_xml
    assert pynxos_device.host == "nxos1.fake.com"
    assert pynxos_device.username == "admin"
    assert pynxos_device.password == "foo"
    assert pynxos_device.port == 8443
    assert pynxos_device.transport == "https"
    assert pynxos_device.api_format == "xml"
    assert pynxos_device.verify is False


def test_show_hostname_xml(mock_pynxos_device_xml):
    result = mock_pynxos_device_xml.show("show hostname")
    xml_obj = result
    response = xml_obj.find("./body/hostname")
    input_obj = xml_obj.find("./input")
    msg_obj = xml_obj.find("./msg")
    code_obj = xml_obj.find("./code")
    assert input_obj.text == "show hostname"
    assert msg_obj.text == "Success"
    assert code_obj.text == "200"
    assert response.text == "nxos.domain.com"


def test_show_version_raw_xml(mock_pynxos_device_xml):
    xml_obj = mock_pynxos_device_xml.show("show version", raw_text=True)
    assert xml_obj.tag == "output"
    body_obj = xml_obj.find("./body")
    input_obj = xml_obj.find("./input")
    msg_obj = xml_obj.find("./msg")
    code_obj = xml_obj.find("./code")
    assert input_obj.text == "show version"
    assert msg_obj.text == "Success"
    assert code_obj.text == "200"
    assert "Cisco Nexus Operating System" in body_obj.text
    assert "cisco NX-OSv" in body_obj.text
    assert "Kernel uptime" in body_obj.text


def test_show_list_xml(mock_pynxos_device_xml):
    cmds = ["show hostname", "show version"]
    result = mock_pynxos_device_xml.show_list(cmds)
    result_show_hostname = result[0]
    result_show_version = result[1]  # noqa
    xml_obj = result_show_hostname
    response = xml_obj.find("./body/hostname")
    input_obj = xml_obj.find("./input")
    msg_obj = xml_obj.find("./msg")
    code_obj = xml_obj.find("./code")
    assert input_obj.text == "show hostname"
    assert msg_obj.text == "Success"
    assert code_obj.text == "200"
    assert response.text == "nxos.domain.com"


def test_show_invalid_xml(mock_pynxos_device_xml):
    """Execute an invalid command."""
    with pytest.raises(NXAPICommandError) as e:
        mock_pynxos_device_xml.show("bogus command")
    assert 'The command "bogus command" gave the error' in str(e.value)
    assert "Syntax error while parsing" in str(e.value)
