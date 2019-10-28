import pytest
from napalm.nxapi_plumbing import NXAPICommandError


def test_pynxos_attributes(mock_pynxos_device):
    pynxos_device = mock_pynxos_device
    assert pynxos_device.host == "nxos1.fake.com"
    assert pynxos_device.username == "admin"
    assert pynxos_device.password == "foo"
    assert pynxos_device.port == 8443
    assert pynxos_device.transport == "https"
    assert pynxos_device.api_format == "jsonrpc"
    assert pynxos_device.verify is False


def test_show_hostname_jsonrpc(mock_pynxos_device):
    result = mock_pynxos_device.show("show hostname")
    assert result["hostname"] == "nxos.domain.com"


def test_show_hostname_raw_jsonrpc(mock_pynxos_device):
    result = mock_pynxos_device.show("show hostname", raw_text=True)
    assert result.strip() == "nxos.domain.com"


def test_show_version_jsonrpc(mock_pynxos_device):
    result = mock_pynxos_device.show("show version")
    assert result["chassis_id"] == "NX-OSv Chassis"
    assert result["memory"] == 4002196
    assert result["proc_board_id"] == "TM6012EC74B"
    assert result["sys_ver_str"] == "7.3(1)D1(1) [build 7.3(1)D1(0.10)]"


def test_show_list_jsonrpc(mock_pynxos_device):
    cmds = ["show hostname", "show version"]
    result = mock_pynxos_device.show_list(cmds)
    result_hostname = result[0]
    result_version = result[1]
    result_hostname["command"] == "show hostname"
    result_version["command"] == "show version"

    # Get the inner result response
    result_hostname = result[0]["result"]
    result_version = result[1]["result"]
    assert result_hostname["hostname"] == "nxos.domain.com"
    assert result_version["chassis_id"] == "NX-OSv Chassis"
    assert result_version["memory"] == 4002196
    assert result_version["proc_board_id"] == "TM6012EC74B"
    assert result_version["sys_ver_str"] == "7.3(1)D1(1) [build 7.3(1)D1(0.10)]"


def test_show_invalid_jsonrpc(mock_pynxos_device):
    """Execute an invalid command."""
    with pytest.raises(NXAPICommandError) as e:
        mock_pynxos_device.show("bogus command")
    assert 'The command "bogus command" gave the error "% Invalid command' in str(
        e.value
    )
