Value Interface (\S+)
Value MAC (\S+)
Value Method (\S+)
Value Domain (\S+)
Value State (\S+)
Value Session (\S+)
  
Start
  ^Interface.*ID
  ^${Interface}\s+${MAC}\s+${Method}\s+${Domain}\s+${State}\s+${Session} -> Record

