Value Location (\w+.*)
Value Contact (\w+.*)
Value Chassis_ID (\w+.*)
Value Community (\w+.*)
Value Mode (ro|rw)
Value ACL (\w+.*)

Start
  ^snmp-server\slocation\s${Location}
  ^snmp-server\scontact\s${Contact}
  ^snmp-server\schassis-id\s${Chassis_ID}
  ^snmp-server\scommunity\s${Community}\s((${Mode} ${ACL})|(group\s(.*))) -> Next.Record

EOF
