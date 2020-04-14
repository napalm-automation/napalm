# Based on:
# https://code.getnoc.com/noc/noc/blob/6f3db2a6e4b1ece77aaf4c4c98413e35ff64643a/sa/profiles/Arista/EOS/get_lldp_neighbors.py#L76-79
LLDP_CAPAB_TRANFORM_TABLE = {
    "other": "other",
    "repeater": "repeater",
    "bridge": "bridge",
    "wlanaccesspoint": "wlan-access-point",
    "router": "router",
    "telephone": "telephone",
    "docsis": "docsis-cable-device",
    "station": "station",
    "stationonly": "station",
}
