from mypy_extensions import TypedDict
from typing import List, Dict


GetFacts = TypedDict(
    "GetFacts",
    {
        "uptime": int,
        "vendor": str,
        "os_version": str,
        "serial_number": str,
        "model": str,
        "hostname": str,
        "fqdn": str,
        "interface_list": List[str],
    },
)

GetInterfacesInner = TypedDict(
    "GetInterfacesInner",
    {
        "is_up": bool,
        "is_enabled": bool,
        "description": str,
        "last_flapped": float,
        "speed": int,
        "mtu": int,
        "mac_address": str,
    },
)
GetInterfaces = Dict[str, GetInterfacesInner]

GetLldpNeighborsInner = TypedDict(
    "GetLldpNeighborsInner", {"hostname": str, "port": str}
)
GetLldpNeighbors = Dict[str, List[GetLldpNeighborsInner]]
