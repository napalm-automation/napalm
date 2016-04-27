Value Username (\w+.*)
Value Password (.*)
Value Role (\w+.*)
Value SSHKeyType (ssh-rsa|ssh-dsa)
Value SSHKeyValue (\w+.*)


Start
  ^username\s+${Username}\s+password\s+\d+\s+${Password}\s+role\s+${Role} -> Record
  ^username\s+${Username}\s+role\s+${Role} -> Record
  ^username\s+${Username}\s+sshkey\s+${SSHKeyType}\s+${SSHKeyValue} -> Record

EOF
