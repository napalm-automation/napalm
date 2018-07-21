Value LOCAL_INTERFACE ([^\s]{1,15})

Start
  # Start capturing after the line that start the table
  ^Device ID -> Record Neighbor

Neighbor
  ^Total entries displayed -> End
  # Stop at the first empty line
  ^$$ -> End
  # Skip 20 characters for the Device ID
  ^.{20}${LOCAL_INTERFACE} -> Record
