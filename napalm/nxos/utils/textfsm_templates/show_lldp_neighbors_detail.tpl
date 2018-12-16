Value LOCAL_INTERFACE (.*)
Value REMOTE_CHASSIS_ID (.*)
Value REMOTE_PORT (.*)
Value REMOTE_PORT_DESCRIPTION (.+)
Value REMOTE_SYSTEM_NAME (.*)
Value REMOTE_SYSTEM_DESCRIPTION (.+)
Value REMOTE_SYSTEM_CAPAB (.*)
Value REMOTE_SYSTEM_ENABLE_CAPAB (.*)

Start
  ^Chassis id:\s+${REMOTE_CHASSIS_ID}
  ^Port id:\s+${REMOTE_PORT}
  ^Local Port id:\s+${LOCAL_INTERFACE}
  ^Port Description:\s+${REMOTE_PORT_DESCRIPTION}
  ^System Name:\s+${REMOTE_SYSTEM_NAME}
  ^System Description:\s+${REMOTE_SYSTEM_DESCRIPTION}
  ^System Capabilities:\s+${REMOTE_SYSTEM_CAPAB}
  ^Enabled Capabilities:\s+${REMOTE_SYSTEM_ENABLE_CAPAB} -> Record