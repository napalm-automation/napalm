Value RemoteAS (\d+)
Value RemoteIP (\S+)
Value Uptime (.*[0-9h])
Value Active_V4 (\d+)
Value Received_V4 (\d+)
Value Accepted_V4 (\d+)
Value Damped_V4 (\d+)
Value Active_V6 (\d+)
Value Received_V6 (\d+)
Value Accepted_V6 (\d+)
Value Damped_V6 (\d+)
Value Status (.*)

Start
  # New format IPv4 & IPv6 split across newlines.
  ^\s+inet.0: ${Active_V4}/${Received_V4}/${Damped_V4}
  ^\s+inet6.0: ${Active_V6}/${Received_V6}/${Damped_V6} -> Next.Record
  ^${RemoteIP}\s+${RemoteAS}(\s+\d+){4}\s+${Uptime}\s+Establ
  ^${RemoteIP}\s+${RemoteAS}(\s+\d+){4}\s+${Uptime}\s+${Active_V4}/${Received_V4}/${Damped_V4}\s+${Active_V6}/${Received_V6}/${Damped_V6} -> Next.Record
  ^${RemoteIP}\s+${RemoteAS}(\s+\d+){4}\s+${Uptime}\s+${Active_V4}/${Received_V4}/${Accepted_V4}/${Damped_V4}\s+${Active_V6}/${Received_V6}/${Accepted_V6}/${Damped_V6} -> Next.Record
  ^${RemoteIP}\s+${RemoteAS}(\s+\d+){4}\s+${Uptime}\s+${Status} -> Next.Record
