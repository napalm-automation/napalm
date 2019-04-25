Value CPU_ID (\d+)
Value CPU_IDLE ([0-9]+\.[0-9]+)

Start
  ^\s+CPU${CPU_ID} states  :.*kernel,\s+${CPU_IDLE}% idle -> Record
