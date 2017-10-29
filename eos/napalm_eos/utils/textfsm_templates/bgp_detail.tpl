Value up (\S+)
Value routing_table (\S+)
Value connection_state (\S+)
Value previous_connection_state (\S+)
Value multihop (\d+)
Value remote_as (\d+)
Value local_as (\d+)
Value router_id (\S+)
Value local_address (\S+)
Value local_port (\d+)
Value remote_address (\S+)
Value remote_port (\d+)
Value import_policy (\S+)
Value export_policy (\S+)
Value last_event (\S+)
Value holdtime (\d+)
Value keepalive (\d+)
Value configured_holdtime (\d+)
Value configured_keepalive (\d+)
Value input_messages (\d+)
Value output_messages (\d+)
Value input_updates (\d+)
Value output_updates (\d+)
Value messages_queued_out (\d+)
Value received_prefix_count (\d+)
Value advertised_prefix_count (\d+)

Start
  ^BGP neighbor is ${remote_address}, remote AS ${remote_as}, .*
  ^.* remote router ID ${router_id}, VRF ${routing_table}
  ^\s+Hold time is ${holdtime}, keepalive interval is ${keepalive} seconds
  ^\s+Configured hold time is ${configured_holdtime}, keepalive interval is ${configured_keepalive} seconds
  ^\s+BGP state is ${connection_state}, ${up} .*
  ^\s+Last state was ${previous_connection_state}
  ^\s+Last event was ${last_event}
  ^\s+OutQ depth is ${messages_queued_out}
  ^\s+Updates:\s+${output_updates}\s+${input_updates}
  ^\s+Total messages:\s+${output_messages}\s+${input_messages}
  ^\s+IPv4 Unicast:\s+${advertised_prefix_count}\s+${received_prefix_count}
  ^\s+Inbound route map is ${import_policy}
  ^\s+Outbound route map is ${export_policy}
  ^\s+Nexthop matches local IP address: ${multihop}
  ^Local AS is ${local_as}.*
  ^Local TCP address is ${local_address}, local port is ${local_port}
  ^.*, remote port is ${remote_port}
  ^Auto-Local-Addr .* -> Next.Record
