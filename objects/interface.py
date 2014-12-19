class Status:
    UP = 0
    OPER_DOWN = 1
    ADMIN_DOWN = 2


class Interface:
    def __init__(self, name, speed, interface_type, status):
        """
        Represents an interface on a switch.

        :param name: (str) Name of the interface
        :param speed: (int) Speed of the interface in Gbps.
        :param interface_type: (str) Type of the interface, i.e.
        :param status: (Status) Status of an interface. Make sure you use the values on the class Status.
        :return:
        """
        self.name
        self.speed
        self.type
        self.interface_type