class BGPInstance:
    def __init__(self, vrf, asn, router_id, bgp_neighbors):
        """

        :param vrf: (str) VRF to which the BGP instance belongs to
        :param asn: (int) The ASN of the BGP instance
        :param router_id: (str) The router ID
        :param bgp_neighbors: (list of BGPNeighbor) A list of bgp peers
        :return:
        """
        self.vrf = vrf
        self.asn = asn
        self.router_id = router_id
        self.bgp_neighbors = bgp_neighbors

    def __str__(self):
        return 'BGP Instance: vrf=%s, asn=%s, router_id=%s' % (self.vrf, self.asn, self.router_id)


class BGPNeighbor:
    def __init__(self, ip, remote_as, state, time, prefixes_accepted):
        """

        :param ip: (str) IP of the BGP neighbor
        :param remote_as: (str) Remote AS of the BGP neighbor
        :param state: (str) State of the BGP neighbor relationship. Make sure you use the standard values as: Idle,
                            Connect, Active, OpenSent, OpenConfirm, Established
        :param time: (int) For how long the device has been on the up/down state
        :param prefixes_accepted: (int) Number of prefixes accepted
        :return:
        """
        self.ip = ip
        self.remote_as = remote_as
        self.state = state
        self.time = time
        self.prefixes_accepted = prefixes_accepted

    def __str__(self):
        return "BGP Neighbor: ip=%s, asn=%s, state=%s" % (self.ip, self.remote_as, self.state)