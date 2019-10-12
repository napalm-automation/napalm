"""Test fixtures."""
import ast
import json
import os

NAPALM_TEST_MOCK = ast.literal_eval(os.getenv("NAPALM_TEST_MOCK", default="1"))
NAPALM_HOSTNAME = os.getenv("NAPALM_HOSTNAME", default="127.0.0.1")
NAPALM_USERNAME = os.getenv("NAPALM_USERNAME", default="vagrant")
NAPALM_PASSWORD = os.getenv("NAPALM_PASSWORD", default="vagrant")
NAPALM_OPTIONAL_ARGS = json.loads(
    os.getenv("NAPALM_OPTIONAL_ARGS", default='{"port": 12443}')
)


def set_device_parameters(request):
    """Set up the class."""
    if NAPALM_TEST_MOCK:
        driver = request.cls.patched_driver
    else:
        driver = request.cls.driver

    request.cls.device = driver(
        NAPALM_HOSTNAME,
        NAPALM_USERNAME,
        NAPALM_PASSWORD,
        timeout=60,
        optional_args=NAPALM_OPTIONAL_ARGS,
    )
    request.cls.device.open()


def pytest_generate_tests(metafunc, basefile):
    """Generate test cases dynamically."""
    if metafunc.function.__dict__.get("build_test_cases", False):
        path = os.path.join(
            os.path.dirname(basefile), "mocked_data", metafunc.function.__name__
        )

        if os.path.exists(path):
            sub_folders = os.listdir(path)
        else:
            sub_folders = []

        test_cases = []
        for test_case in sub_folders:
            if os.path.isdir(os.path.join(path, test_case)):
                test_cases.append(test_case)

        if not test_cases:
            test_cases.append("no_test_case_found")

        metafunc.parametrize("test_case", test_cases)
