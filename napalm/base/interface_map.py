from __future__ import print_function
from __future__ import unicode_literals

def _interface_map():
    interface_map = {
      "base_interfaces": {
        "ATM": [
          "ATM",
          "AT"
        ],
        "ATM_short": "At",
        "EOBC": [
          "EOBC",
          "EO"
        ],
        "EOBC_short": "EO",
        "Ethernet": [
          "Ethernet",
          "Eth",
          "Et"
        ],
        "Ethernet_short": "Et",
        "FastEthernet": [
          "FastEthernet",
          "FastEth",
          "FastE",
          "Fast",
          "Fas",
          "FE",
          "Fa"
        ],
        "FastEthernet_short": "Fa",
        "Fddi": [
          "Fddi",
          "FD"
        ],
        "Fddi_short": "FD",
        "FortyGigabitEthernet": [
          "FortyGigabitEthernet",
          "FortyGigEthernet",
          "FortyGigEth",
          "FortyGigE",
          "FortyGig",
          "FGE",
          "FO",
          "Fo"
        ],
        "FortyGigabitEthernet_short": "Fo",
        "GigabitEthernet": [
          "GigabitEthernet",
          "GigEthernet",
          "GigEth",
          "GigE",
          "Gig",
          "GE",
          "Gi"
        ],
        "GigabitEthernet_short": "Gi",
        "HundredGigabitEthernet": [
          "HundredGigabitEthernet",
          "HundredGigEthernet",
          "HundredGigEth",
          "HundredGigE",
          "HundredGig",
          "Hu"
        ],
        "HundredGigabitEthernet_short": "Hu",
        "Loopback": [
          "Loopback",
          "Lo"
        ],
        "Loopback_short": "Lo",
        "Management": [
          "Management",
          "Mgmt",
          "Ma"
        ],
        "Management_short": "Ma",
        "MFR": [
          "MFR"
        ],
        "MFR_short": "MFR",
        "Multilink": [
          "Multilink",
          "Mu"
        ],
        "Multilink_short": "Mu",
        "PortChannel": [
          "PortChannel",
          "Port-Channel",
          "Po"
        ],
        "PortChannel_short": "Po",
        "POS": [
          "POS",
          "PO"
        ],
        "POS_short": "PO",
        "Serial": [
          "Serial",
          "Se",
          "S"
        ],
        "Serial_short": "Se",
        "TenGigabitEthernet": [
          "TenGigabitEthernet",
          "TenGigEthernet",
          "TenGigEth",
          "TenGig",
          "TeGig",
          "Ten",
          "T",
          "Te"
        ],
        "TenGigabitEthernet_short": "Te",
        "Tunnel": [
          "Tunnel",
          "Tun",
          "Tu"
        ],
        "Tunnel_short": "Tu",
        "Virtual-Access": [
          "Virtual-Access",
          "Vi"
        ],
        "Virtual-Access_short": "Vi",
        "Virtual-Template": [
          "Virtual-Template",
          "Vt"
        ],
        "Virtual-Template_short": "Vt",
        "VLAN": [
          "VLAN",
          "V",
          "Vl"
        ],
        "VLAN_short": "Vl"
      },
      "os_map": {
        "cisco_ios": {
          "from_base": [
            "ATM",
            "EOBC",
            "Ethernet",
            "FastEthernet",
            "Fddi",
            "FortyGigabitEthernet",
            "GigabitEthernet",
            "HundredGigabitEthernet",
            "Loopback",
            "Management",
            "MFR",
            "Multilink",
            "PortChannel",
            "POS",
            "Serial",
            "TenGigabitEthernet",
            "Tunnel",
            "Virtual-Access",
            "Virtual-Template",
            "VLAN"
          ],
          "from_os": None
        },
        "cisco_nxos": {
          "from_base": [
            "Ethernet",
            "FastEthernet",
            "FortyGigabitEthernet",
            "GigabitEthernet",
            "HundredGigabitEthernet",
            "Loopback",
            "Management",
            "Multilink",
            "PortChannel",
            "Serial",
            "TenGigabitEthernet",
            "Tunnel",
            "VLAN"
          ]
        },
        "cisco_xr": {
          "from_base": [
            "ATM",
            "Ethernet",
            "FastEthernet",
            "FortyGigabitEthernet",
            "GigabitEthernet",
            "HundredGigabitEthernet",
            "Loopback",
            "Management",
            "MFR",
            "Multilink",
            "PortChannel",
            "POS",
            "Serial",
            "TenGigabitEthernet",
            "Tunnel",
            "Virtual-Access",
            "Virtual-Template",
            "VLAN"
          ],
          "from_os": None
        },
        "arista_eos": {
          "from_base": [
            "Ethernet",
            "Loopback",
            "Management",
            "Multilink",
            "PortChannel",
            "Tunnel",
            "VLAN"
          ],
          "from_os": None
        }
      }
    }

    return interface_map
