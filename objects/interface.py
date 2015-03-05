class InterfaceStatus:
    UP = 1
    OPER_DOWN = -1
    ADMIN_DOWN = -2

class Interface:
    def __init__(self, name, speed, status):
        """
        Represents an interface on a switch.

        :param name: (str) Name of the interface
        :param speed: (int) Speed of the interface in Gbps.
        :param status: (Status) Status of an interface. Make sure you use the values on the class Status.
        :return:
        """
        self.name = name
        self.speed = speed
        self.status = status

    def __str__(self):
        return self.name