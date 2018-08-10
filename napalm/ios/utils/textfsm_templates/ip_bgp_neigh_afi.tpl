Value AFI (.*)
Value SESSION (\S+)
Value POLICY_IN (\S+)
Value POLICY_OUT (\S+)
Value PREFIX_CURR_OUT (\d+)
Value PREFIX_CURR_IN (\d+)
Value PREFIX_TOTAL_OUT (\d+)
Value PREFIX_TOTAL_IN (\d+)
Value WITHDRAW_IMPLICIT_OUT (\d+)
Value WITHDRAW_IMPLICIT_IN (\d+)
Value WITHDRAW_EXPLICIT_OUT (\d+)
Value WITHDRAW_EXPLICIT_IN (\d+)
Value BESTPATHS (\d+)
Value MULTIPATHS (\d+)
Value SECONDARIES (\d+)
Value REJECTED_PREFIX_IN (\d+)
Value REJECTED_PREFIX_OUT (\d+)
Value FLAP_COUNT (\d+)
Value LAST_EVENT (.*)
Value LOCAL_ADDR_CONF (peering address in same link)

Start
  ^\s*For address family: -> Continue.Record
  ^\s*For address family: ${AFI}
  ^\s+Session: ${SESSION}
  ^\s+Route map for incoming advertisements is ${POLICY_IN}
  ^\s+Route map for outgoing advertisements is ${POLICY_OUT}
  ^\s+Prefixes Current:\s+${PREFIX_CURR_OUT}\s+${PREFIX_CURR_IN}
  ^\s+Prefixes Total:\s+${PREFIX_TOTAL_OUT}\s+${PREFIX_TOTAL_IN}
  ^\s+Implicit Withdraw:\s+${WITHDRAW_IMPLICIT_OUT}\s+${WITHDRAW_IMPLICIT_IN}
  ^\s+Explicit Withdraw:\s+${WITHDRAW_EXPLICIT_OUT}\s+${WITHDRAW_EXPLICIT_IN}
  ^\s+Used as bestpath:\s+\S+\s+${BESTPATHS}
  ^\s+Used as multipath:\s+\S+\s+${MULTIPATHS}
  ^\s+Used as secondary:\s+\S+\s+${SECONDARIES}
  ^\s+Total:\s+${REJECTED_PREFIX_OUT}\s+${REJECTED_PREFIX_IN}
  ^\s+Connections established\s+\d+;\s+dropped\s+${FLAP_COUNT}
  ^\s+Last reset ${LAST_EVENT}
  ^\s+Interface associated: \S+ \(${LOCAL_ADDR_CONF}\)
  ^Connection state is -> Record

  