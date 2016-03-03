Value Location (.*)
Value Contact (.*)
Value Chassis_ID (.*)
Value Community (.*)
Value Mode (.*)
Value ACL (.*)

Start
  ^snmp-server location ${Location}
  ^snmp-server contact ${Contact}
  ^snmp-server chassis-id ${Chassis_ID}
  ^snmp-server community ${Community} ${Mode} ${ACL} -> Next.Record

EOF
