class NetworkDriver:
    def __init__(self, hostname, user, password):
        """
        This is the base class you have to inherit from when writing your own Network Driver to manage any device. You
        will, in addition, have to override all the methods specified on this class. Make sure you follow the guidelines
        for every method and that you return the correct data.

        :param hostname: (str) IP or FQDN of the device you want to connect to.
        :param user: (str) Username you want to use
        :param password: (str) Password
        :return:
        """
        raise NotImplementedError

    def open(self):
        """
        Opens a connection to the device.

        :return: None
        """
        raise NotImplementedError

    def close(self):
        """
        Closes the connection to the device.
        :return: None
        """
        raise NotImplementedError

    def compare_configuration(self, candidate):
        """
        Compares the running configuration with a candidate configuration.
        :param candidate: (str) Configuration you want to compare with.
        :return: A string showing the difference between the running configuration and the candidate configuration.
        """
        raise NotImplementedError

    def replace_configuration(self, candidate):
        """
        Replaces the running configuration with the candidate configuration.
        :param candidate: (str) Configuration you want to have on the device.
        :return: None
        :raises SyntacticError: If configuration syntax was incorrect.
        :raises SemanticError: If the device reported semantic errors on the configuration.
        :raises UnknownConfigurationError: If none of the above.
        """
        raise NotImplementedError

    def get_facts(self):
        """
        Retrieves facts from the device.
        :return: (Facts) Facts from the device.
        """
        raise NotImplementedError

    def get_bgp_neighbors(self):
        """
        Retrieves BGP neighbors information from the device.
        :return: (list of BGPNeighbor) List of BGPNeighbor from the device.
        """
        raise NotImplementedError

    def get_interfaces(self):
        """
        Retrieves information from the available interfaces on the device.
        :return: (list of Interface) List of Interface from the device.
        """

        raise NotImplementedError

    def get_lldp_neighbors(self):
        """
        Retrieves LLDP information from the device.
        :return: (list of LLDPNeighbor) List of LLDPNeighbor.
        """
        raise NotImplementedError