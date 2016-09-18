"""Test fixtures."""
import json
import os
import sys

NAPALM_TEST_MOCK = os.getenv('NAPALM_TEST_MOCK', default=True)
NAPALM_HOSTNAME = os.getenv('NAPALM_HOSTNAME', default='127.0.0.1')
NAPALM_USERNAME = os.getenv('NAPALM_USERNAME', default='vagrant')
NAPALM_PASSWORD = os.getenv('NAPALM_PASSWORD', default='vagrant')
NAPALM_OPTIONAL_ARGS = json.loads(os.getenv('NAPALM_OPTIONAL_ARGS', default='{"port": 12443}'))


def set_device_parameters(request):
    """Set up the class."""
    request.cls.device = request.cls.driver(NAPALM_HOSTNAME,
                                            NAPALM_USERNAME,
                                            NAPALM_PASSWORD,
                                            timeout=60,
                                            optional_args=NAPALM_OPTIONAL_ARGS)
    if NAPALM_TEST_MOCK:
        request.cls.device.device = request.cls.fake_driver()
        module_file = os.path.dirname(sys.modules[request.cls.__module__].__file__)
        request.cls.device.mocked_data_dir = os.path.join(module_file, 'mocked_data')
    else:
        request.cls.device.mocked_data_dir = None
    request.cls.device.open()


def pytest_generate_tests(metafunc, basefile):
    """Generate test cases dynamically."""
    path = os.path.join(os.path.dirname(basefile), 'mocked_data', metafunc.function.__name__)

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
