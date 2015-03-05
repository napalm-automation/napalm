class LLDPNeighbor:
    def __init__(self, hostname, local_port, remote_port):
        """
        Represents and LLDP neighbor.

        :param hostname: (str) hostname of the LLDP Neighbor
        :param local_port: (str) Local port where the LLDP Neighbor is connected to.
        :param remote_port: (str) Remote port where the LLDP Neighbor is connected to.
        :return:
        """
        self.hostname = hostname
        self.local_port = local_port
        self.remote_port = remote_port

    def __str__(self):
        return self.hostname

    def __repr__(self):
        return 'LLDPNeighbor: %s' % self.__str__()