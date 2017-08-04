Value NEIGHBOR (\S+)
Value LOCAL_INTERFACE (\S+)
Value NEIGHBOR_INTERFACE (\S+)

Start
  ^Device.*ID -> LLDP

LLDP
  ^${NEIGHBOR}\s+${LOCAL_INTERFACE}\s+\d+\s+[\w+\s]+\S+\s+${NEIGHBOR_INTERFACE} -> Record
