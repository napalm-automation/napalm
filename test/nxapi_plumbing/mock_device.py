from requests.auth import HTTPBasicAuth
import json
from lxml import etree

from napalm.nxapi_plumbing import Device
from napalm.nxapi_plumbing import RPCClient, XMLClient


class FakeResponse(object):
    def __init__(self):
        self.text = ""


def mock_post(
    url, timeout, data, headers, auth, verify, api_type="jsonrpc", raw_text=False
):
    """Look up the response based on the URL and payload."""

    # Construct the path to search for the mocked data
    # e.g. ./mocked_data/jsonrpc_show_hostname/response.json
    base_dir = "test/nxapi_plumbing/mocked_data"
    if api_type == "jsonrpc":
        data = json.loads(data)
        if len(data) == 1:
            api_cmd = data[0]["params"]["cmd"]
            if isinstance(api_cmd, list):
                api_cmd = "__".join(api_cmd)
        else:
            cmd_list = [cmd_dict["params"]["cmd"] for cmd_dict in data]
            api_cmd = "__".join(cmd_list)
        file_ext = "json"
    elif api_type == "xml":
        xml_root = etree.fromstring(data)
        input_obj = xml_root.find("./input")
        api_cmd = input_obj.text
        file_ext = "xml"
    api_cmd = api_cmd.replace(" ", "_")
    api_cmd = api_cmd.replace(";", "_")

    if raw_text:
        file_path = "{base_dir}/{api_type}_{api_cmd}_raw/response.{file_ext}".format(
            base_dir=base_dir, api_type=api_type, api_cmd=api_cmd, file_ext=file_ext
        )
    else:
        file_path = "{base_dir}/{api_type}_{api_cmd}/response.{file_ext}".format(
            base_dir=base_dir, api_type=api_type, api_cmd=api_cmd, file_ext=file_ext
        )

    with open(file_path) as f:
        return f.read()


class MockDevice(Device):
    def __init__(
        self,
        host,
        username,
        password,
        transport="http",
        api_format="jsonrpc",
        port=None,
        timeout=30,
        verify=True,
    ):
        super().__init__(
            host,
            username,
            password,
            transport=transport,
            api_format=api_format,
            port=port,
            timeout=timeout,
            verify=verify,
        )
        if api_format == "jsonrpc":
            self.api = MockRPCClient(
                host,
                username,
                password,
                transport=transport,
                port=port,
                timeout=timeout,
                verify=verify,
            )
        elif api_format == "xml":
            self.api = MockXMLClient(
                host,
                username,
                password,
                transport=transport,
                port=port,
                timeout=timeout,
                verify=verify,
            )


class MockRPCClient(RPCClient):
    def _send_request(self, commands, method="cli"):
        payload = self._build_payload(commands, method)

        raw_text = True if method in ["cli_ascii", "cli_show_ascii"] else False
        mock_response = mock_post(
            self.url,
            timeout=self.timeout,
            data=payload,
            headers=self.headers,
            auth=HTTPBasicAuth(self.username, self.password),
            verify=self.verify,
            api_type="jsonrpc",
            raw_text=raw_text,
        )

        response_obj = FakeResponse()
        response_obj.text = mock_response
        response_obj.status_code = 200

        return response_obj.text


class MockXMLClient(XMLClient):
    def _send_request(self, commands, method="cli_show"):
        payload = self._build_payload(commands, method)

        raw_text = True if method in ["cli_ascii", "cli_show_ascii"] else False
        mock_response = mock_post(
            self.url,
            timeout=self.timeout,
            data=payload,
            headers=self.headers,
            auth=HTTPBasicAuth(self.username, self.password),
            verify=self.verify,
            api_type="xml",
            raw_text=raw_text,
        )

        response_obj = FakeResponse()
        response_obj.text = mock_response
        response_obj.status_code = 200

        return response_obj.text
