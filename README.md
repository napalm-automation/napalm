modify connection behavior of napalm for cisco devices.
 - move enable() from napalm baseconnection.open  to driver(
 - modify behavior to allow getters to connect without need of enable secret
   (move enable check to functions that rely on it)
