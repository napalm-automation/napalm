Value NTPPeer (\w+.*)

Start
  ^ntp\s+server\s+${NTPPeer} -> Record

EOF
