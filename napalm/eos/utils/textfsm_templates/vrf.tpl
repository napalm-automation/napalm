Value Required Name (\S+)
Value Route_Distinguisher (\d+:\d+|<not set>)
Value List Interfaces (.+?)


Start
  ^(\s+)?\S+\s+(\d|<) -> Continue.Record
  ^(\s+)?${Name}\s+${Route_Distinguisher}\s+(ipv4(,ipv6)?\s+)?v4:(incomplete|(no )?routing(; multicast)?),\s+${Interfaces}(?:,|\s|$$) -> Continue
  ^(\s+)?\S+\s+(?:\d+:\d+|<not set>)\s+(ipv4(,ipv6)?\s+)?v4:(incomplete|(no )?routing(; multicast)?),\s+(.+?),\s${Interfaces}(\s|,|$$) -> Continue
  ^(\s+)?\S+\s+(?:\d+:\d+|<not set>)\s+(ipv4(,ipv6)?\s+)?v4:(incomplete|(no )?routing(; multicast)?),\s+(.+?),\s(.+?),\s${Interfaces}(\s|,|$$) -> Continue
  ^(\s+)?${Name}\s+${Route_Distinguisher}\s+(ipv4(,ipv6)?\s+)?v4:(incomplete|(no )?routing(; multicast)?), -> Continue
  ^\s{30,37}v6:(incomplete|(no )?routing)\s+${Interfaces}(?:\s|,|$$) -> Continue
  ^\s{30,37}v6:(incomplete|(no )?routing)\s+(.+?),\s+${Interfaces}(?:\s|,|$$) -> Continue
  ^\s{30,37}v6:(incomplete|(no )?routing)\s+(.+?),\s+(.+?),\s+${Interfaces}(?:\s|,|$$) -> Continue
  ^\s{50,62}\s+${Interfaces}(?:\s|,|$$) -> Continue
  ^\s{50,62}\s+.+?,${Interfaces}(?:\s|,|$$) -> Continue
  ^\s{50,62}\s+.+?,.+?,${Interfaces}(?:\s|,|$$) -> Continue
