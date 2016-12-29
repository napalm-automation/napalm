
VYOS
---


Prerequisites
------------------

VyOS has no native HTTP API or NETCONF capability.
We are using Netmiko for ssh connections and scp file transfers.
Having Netmiko installed in your working box is a prerequisite.

netmiko >= 1.0.0
vyattaconfparser



Configuration file
------------------

Currently VyOS driver supports two different configuration formats:
* load_replace_candidate - Full config file (with brackets) like in /config/config.boot
Due to the OS nature,  we do not support a replace using
a set-style configuration format.
*load_merge_candidate - Currently driver supports set-style configuration format.
Example
  `set system login banner pre-login "test"`

Vyos require configuration file (load_replace) to contain comment like following

  `/* Warning: Do not remove the following line. */
/* === vyatta-config-version: "cluster@1:config-management@1:conntrack-sync@1:conntrack@1:cron@1:dhcp-relay@1:dhcp-server@4:firewall@5:ipsec@4:nat@4:qos@1:quagga@2:system@6:vrrp@1:wanloadbalance@3:webgui@1:webproxy@1:zone-policy@1" === */
/* Release version: VyOS 1.1.7 */`

Otherwise VyOS reject `load` operation

Notes
------------------
* The NAPALM-vyos driver supports all Netmiko arguments as either standard arguments (hostname, username, password, timeout) or as optional_args (everything else).

* The NAPALM-vyos driver supports authentication with ssh key. Please specify path to a key in optional_args
`'optional_args': {'key_file': '/home/user/ssh_private_key'}`
