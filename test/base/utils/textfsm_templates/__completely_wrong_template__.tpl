Value Model (\S+)
Value Memory (\S+)
Value ConfigRegister (0x\S+)
Value Uptime (.*)

Start
  ^Cisco IOS Software.*Version ${Version},
  ^.*uptime is ${Uptime}
  ^System returned to ROM by ${ReloadReason}
  ^System restarted at ${ReloadTime}
  ^System image file is "${ImageFile}"
  ^cisco ${Model} .* with ${Memory} bytes of memory
  ^Configuration register is ${ConfigRegister}
