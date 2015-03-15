# TODO check common API
# TODO install pyEOS


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

    def load_candidate_config(self, filename=None, config=None):
        """
        Populates the attribute candidate_config with the desired configuration. You can populate it from a file or
        from a string. If you send both a filename and a string containing the configuration, the file takes precedence.

        :param filename: Path to the file containing the desired configuration. By default is None.
        :param config: String containing the desired configuration.
        """
        raise NotImplementedError

    def compare_config(self):
        """

        :return: A string showing the difference between the running_config and the candidate_config. The running_config is
            loaded automatically just before doing the comparison so there is no neeed for you to do it.
        """
        raise NotImplementedError

    def commit_config(self):
        """
        Applies the configuration loaded with the method load_candidate_config on the device. Note that the current
        configuration of the device is replaced with the new configuration.
        """
        raise NotImplementedError

    def discard_config(self):
        """
        Discards the configuration loaded into the candidate.
        """
        raise NotImplementedError

    def rollback(self):
        """
        If changes have been made, revert changes to the original state.
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

    def get_interface(self, name):
        """
        Retrieves information from the available interfaces on the device.
        :param name: (string) Interface name of the interface you want to get.
        :return: (list of Interface) List of Interface from the device.
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
