import os
import pytest

from napalm.eos import eos
from napalm.base.base import NetworkDriver


@pytest.fixture
def integration_device():
    with eos.EOSDriver(
        os.environ["NAPALM_INTEGRATION_HOST"],
        os.environ["NAPALM_USERNAME"],
        os.environ["NAPALM_PASSWORD"],
    ) as d:
        yield d


@pytest.mark.skipif(
    os.getenv("NAPALM_INTEGRATION_HOST") is None, reason="No integration host specified"
)
def test_eos_foo(integration_device):
    getters = [s for s in dir(NetworkDriver) if s.startswith("get_")]

    getter_options = {"get_route_to": {"destination": "0.0.0.0/0", "longer": True}}

    for getter in getters:
        try:
            ret = getattr(integration_device, getter)(**getter_options.get(getter, {}))
            assert ret
        except NotImplementedError:
            pass
