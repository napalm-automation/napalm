from eos import EOSDriver
from iosxr import IOSXRDriver
from junos import JunOSDriver


def get_network_driver(vendor):
    driver_mapping = {
        'EOS': EOSDriver,
        'ARISTA': EOSDriver,
        'IOS-XR': IOSXRDriver,
        'IOSXR': IOSXRDriver,
        'JUNOS': JunOSDriver,
        'JUNIPER': JunOSDriver,

    }
    try:
        return driver_mapping[vendor.upper()]
    except KeyError:
        raise Exception('Vendor/OS not supported: %s' % vendor)

