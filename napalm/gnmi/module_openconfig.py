# std libs
import json
# third party libs

# Functions
def get_facts(gnmi_object, orgs) -> dict:
    result = {}

    data = gnmi_object.get(path=["/openconfig-system:system", "openconfig-platform:components", "/openconfig-interfaces:interfaces"])
#    print(json.dumps(data, indent=4))

    # Get hostname
    try:
        hostname = data["notification"][0]["update"][0]["val"]["openconfig-system:config"]["hostname"]
        
    except:
        try: 
            hostname = data["notification"][0]["update"][0]["val"]["config"]["hostname"]

        except:
            hostname = ""

    result["hostname"] = hostname

    # Get fqdn
    try:
        domain = data["notification"][0]["update"][0]["val"]["openconfig-system:config"]["domain-name"]
    except:
        try: 
            domain = data["notification"][0]["update"][0]["val"]["config"]["domain-name"]

        except:
            domain = ""

    result["fqdn"] = hostname + "." + domain if domain else hostname

    # Get vendors
    known_vendors = {"cisco", "arista", "nokia", "juniper"}

    vendor = known_vendors & orgs

    result["vendor"] = vendor.pop()

    # commands = ["show version", "show hostname", "show interfaces"]

    # result = self.device.run_commands(commands)

    # version = result[0]
    # hostname = result[1]
    # interfaces_dict = result[2]["interfaces"]

    # uptime = time.time() - version["bootupTimestamp"]

    # interfaces = [i for i in interfaces_dict.keys() if "." not in i]
    # interfaces = string_parsers.sorted_nicely(interfaces)

    # return {
    #     "hostname": hostname["hostname"], +
    #     "fqdn": hostname["fqdn"], +
    #     "vendor": "Arista", +
    #     "model": version["modelName"],
    #     "serial_number": version["serialNumber"], 
    #     "os_version": version["internalVersion"],
    #     "uptime": int(uptime), 
    #     "interface_list": interfaces,
    # }

    return result