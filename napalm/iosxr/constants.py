"""Constants for the IOS-XR driver."""

from napalm.base.constants import *  # noqa

SR_638170159_SOLVED = False
# this flag says if the Cisco TAC SR 638170159
# has been solved
#
# "XML Agent Does not retrieve correct BGP routes data"
# is a weird bug reported on 2016-02-22 22:54:21
# briefly, all BGP routes are handled by the XML agent
# in such a way they have the following details:
#
# - all neighbors are 0.0.0.0
# - all routes are 0.0.0.0/0
# - all RD = 0000000000000000
#
# because of this none of the data retrieved
# from the BGP oper is usable thus has direct implications
# in our implementation of `get_route_to` when retrieving
# the BGP protocol specific attributes.
