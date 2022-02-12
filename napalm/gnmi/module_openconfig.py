# std libs
import json
# third party libs

# Functions
def get_facts(gnmi_object) -> dict:
    result = {}

    data = gnmi_object.get(path=[""])
    print(json.dumps(data, indent=4))

    # commands = ["show version", "show hostname", "show interfaces"]

    # result = self.device.run_commands(commands)

    # version = result[0]
    # hostname = result[1]
    # interfaces_dict = result[2]["interfaces"]

    # uptime = time.time() - version["bootupTimestamp"]

    # interfaces = [i for i in interfaces_dict.keys() if "." not in i]
    # interfaces = string_parsers.sorted_nicely(interfaces)

    # return {
    #     "hostname": hostname["hostname"],
    #     "fqdn": hostname["fqdn"],
    #     "vendor": "Arista",
    #     "model": version["modelName"],
    #     "serial_number": version["serialNumber"],
    #     "os_version": version["internalVersion"],
    #     "uptime": int(uptime),
    #     "interface_list": interfaces,
    # }

    return result