def test_config_jsonrpc(mock_pynxos_device):
    result = mock_pynxos_device.config("logging history size 200")
    assert result is None


def test_config_list_jsonrpc(mock_pynxos_device):
    cfg_cmds = [
        "logging history size 200",
        "logging history size 300",
        "logging history size 400",
    ]
    result = mock_pynxos_device.config_list(cfg_cmds)
    for i, response_dict in enumerate(result):
        assert cfg_cmds[i] == response_dict["command"]
        assert response_dict["result"] is None


def test_config_xml(mock_pynxos_device_xml):
    xml_obj = mock_pynxos_device_xml.config("logging history size 200")
    status_code = xml_obj.find("./code")
    msg = xml_obj.find("./msg")
    assert status_code.text == "200"
    assert msg.text == "Success"


def test_config_xml_list(mock_pynxos_device_xml):
    cfg_cmds = [
        "logging history size 200",
        "logging history size 300",
        "logging history size 400",
    ]
    xml_obj = mock_pynxos_device_xml.config_list(cfg_cmds)
    assert len(xml_obj) == 3
    for element in xml_obj:
        status_code = element.find("./code")
        msg = element.find("./msg")
        assert status_code.text == "200"
        assert msg.text == "Success"
