modify connection behavior of napalm for cisco devices.
 - move enable() from napalm baseconnection.open  to driver(not all network devices require a secret therefore it should be                  moved to the drivers longterm)
 - modify behavior to allow getters to work without need of enable secret(move enable() to functions that rely on priv exec, add internal flag to avoid permanent checking with enable() when calling multiple api commands)  
   (enable relies on https://github.com/ktbyers/netmiko/blob/develop/netmiko/cisco_base_connection.py:CiscoBaseConnection:enable()-> change would cause issues on other place)
  
