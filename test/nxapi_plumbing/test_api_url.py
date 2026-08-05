from urllib.parse import urlsplit

import pytest

from napalm.nxapi_plumbing import RPCClient, XMLClient


@pytest.mark.parametrize("client_class", [RPCClient, XMLClient])
@pytest.mark.parametrize(
    "host,expected_url",
    [
        ("nxos1.fake.com", "https://nxos1.fake.com:8443/ins"),
        ("10.0.0.1", "https://10.0.0.1:8443/ins"),
        ("2001:db8::1", "https://[2001:db8::1]:8443/ins"),
        ("[2001:db8::1]", "https://[2001:db8::1]:8443/ins"),
    ],
)
def test_api_url(client_class, host, expected_url):
    """Literal IPv6 hosts must be bracketed per RFC 3986 (see issue #2311)."""
    client = client_class(host, "admin", "foo", port=8443)
    assert client.url == expected_url

    parsed = urlsplit(client.url)
    assert parsed.hostname == host.strip("[]")
    assert parsed.port == 8443
