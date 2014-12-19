class Facts:
    def __init__(self, vendor, hostname, fqdn, hardware_model, serial_number, os_version, interfaces):
        """
        :param vendor: (str) Vendor of the device.
        :param hardware_model: (str) Specific hardware model of the device
        :param serial_number: (str) Serial number of the device
        :param os_version: (str) OS Version running the device
        :param interfaces: (list of str) List of interface names available on the device
        """
        self.vendor = vendor
        self.hostname = hostname
        self.fqdn = fqdn
        self.hardware_model = hardware_model
        self.serial_number = serial_number
        self.os_version = os_version
        self.interfaces = interfaces