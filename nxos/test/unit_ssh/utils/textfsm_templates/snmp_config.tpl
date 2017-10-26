Value Location (.*)
Value Contact (.*)
Value Community (\S+)
Value Mode (network\-admin|network\-operator)
Value ACL (\S+)

Start
  ^snmp-server\slocation\s${Location} -> Record
  ^snmp-server\scontact\s${Contact} -> Record
  ^snmp-server\scommunity\s${Community}\s((group\s+${Mode}|use\-.+\s+${ACL})) -> Next.Record
