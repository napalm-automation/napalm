Value NEIGHBOR (\S+)
Value REMOTE_AS (\d+)
Value BGP_TYPE (\w+)
Value VRF (\w+)
Value DESCRIPTION (.*)
Value ROUTER_ID (\S+)
Value BGP_STATE (\w+)
Value UP (\w+)
Value UPTIME (\S+)
Value LAST_READ (.*)
Value LAST_WRITE (.*)
Value HOLDTIME (\d+)
Value KEEPALIVE (\d+)
Value FOUR_BYTE_AS (.*)
Value MSG_OPEN_OUT (\d+)
Value MSG_OPEN_IN (\d+)
Value MSG_NOTI_OUT (\d+)
Value MSG_NOTI_IN (\d+)
Value MSG_UPDATE_OUT (\d+)
Value MSG_UPDATE_IN (\d+)
Value MSG_KEEPALIVE_OUT (\d+)
Value MSG_KEEPALIVE_IN (\d+)
Value MSG_REFRESH_OUT (\d+)
Value MSG_REFRESH_IN (\d+)
Value MSG_TOTAL_OUT (\d+)
Value MSG_TOTAL_IN (\d+)
Value LOCAL_ADDRESS (.*)
Value LOCAL_PORT (\d+)
Value REMOTE_ADDRESS (.*)
Value REMOTE_PORT (\d+)
Value ROUTING_TABLE (\d+)
Value CONN_STATE (\w+)

Start
  ^BGP neighbor is ${NEIGHBOR},(?:\s+vrf ${VRF},)?\s+remote AS\s+${REMOTE_AS},\s+${BGP_TYPE} link
  ^\s+Administratively shut ${UP}
  ^\s+Description:\s+${DESCRIPTION}
  ^\s+BGP version 4, remote router ID ${ROUTER_ID}
  ^\s+BGP state = ${BGP_STATE}(?:, ${UP} for ${UPTIME})?
  ^\s+Last read ${LAST_READ}, last write ${LAST_WRITE}, hold time is ${HOLDTIME}, keepalive interval is ${KEEPALIVE} seconds
  ^\s+Four-octets ASN Capability:\s+${FOUR_BYTE_AS}
  ^\s+Opens:\s+${MSG_OPEN_OUT}\s+${MSG_OPEN_IN}
  ^\s+Notifications:\s+${MSG_NOTI_OUT}\s+${MSG_NOTI_IN}
  ^\s+Updates:\s+${MSG_UPDATE_OUT}\s+${MSG_UPDATE_IN}
  ^\s+Keepalives:\s+${MSG_KEEPALIVE_OUT}\s+${MSG_KEEPALIVE_IN}
  ^\s+Route Refresh:\s+${MSG_REFRESH_OUT}\s+${MSG_REFRESH_IN}
  ^\s+Total:\s+${MSG_TOTAL_OUT}\s+${MSG_TOTAL_IN}
  ^\s*Connection state is ${CONN_STATE},
  ^\s*For address family -> Afi
  ^Local host: ${LOCAL_ADDRESS}, Local port: ${LOCAL_PORT}
  ^Foreign host: ${REMOTE_ADDRESS}, Foreign port: ${REMOTE_PORT}
  ^Connection tableid \(VRF\): ${ROUTING_TABLE}

Afi
  ^\s -> Next
  ^\w -> Start