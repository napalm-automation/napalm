Value Filldown ADDR_FAMILY (.*)
Value Filldown ROUTER_ID (\S+)
Value Filldown LOCAL_AS (\d+)
Value NEIGHBOR (\S+)
Value BGP_VER (\d)
Value REMOTE_AS (\d+)
Value MSG_RECV (\d+)
Value MSG_SENT (\d+)
Value TBL_VER (\d+)
Value IN_Q (\d+)
Value OUT_Q (\d+)
Value UP (\S+)
Value PREFIX_RECV (.*)

Start
  ^For address family\: ${ADDR_FAMILY}
  ^BGP router identifier ${ROUTER_ID}, local AS number ${LOCAL_AS}
  ^Neighbor\s+V -> Table

Table
  ^${NEIGHBOR} -> Continue
  ^\s+${BGP_VER}\s+${REMOTE_AS}\s+${MSG_RECV}\s+${MSG_SENT}\s+${TBL_VER}\s+${IN_Q}\s+${OUT_Q}\s+${UP}\s+${PREFIX_RECV} -> Record Table
  ^${NEIGHBOR}\s+${BGP_VER}\s+${REMOTE_AS}\s+${MSG_RECV}\s+${MSG_SENT}\s+${TBL_VER}\s+${IN_Q}\s+${OUT_Q}\s+${UP}\s+${PREFIX_RECV} -> Record Table
  ^$$ -> Clearall Start

EOF
