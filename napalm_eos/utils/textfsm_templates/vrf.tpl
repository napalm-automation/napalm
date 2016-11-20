Value Required Name (\S+)
Value Route_Distinguisher (\d+:\d+|<not set>)
Value List Interfaces (\S.+)


Start
  ^\s\S+\s+(\d|<) -> Continue.Record
  ^\s+${Name}\s+${Route_Distinguisher}\s+(ipv4,ipv6\s+)?v4:(incomplete|(no )?routing(; multicast)?),\s+$Interfaces
  ^\s+${Name}\s+${Route_Distinguisher}\s+(ipv4,ipv6\s+)?v4:(incomplete|(no )?routing(; multicast)?),
  ^\s+v6:(incomplete|(no )?routing)\s+$Interfaces
  ^\s+v6:(incomplete|(no )?routing) -> Record
  ^\s+$Interfaces
