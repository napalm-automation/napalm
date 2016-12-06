from napalm_base.helpers import (
        ip as cast_ip,
        )


def to_seconds(time_format):
    seconds = minutes = hours = days = weeks = 0

    number_buffer = ''
    for current_character in time_format:
        if current_character.isdigit():
            number_buffer += current_character
            continue
        if current_character == 's':
            seconds = int(number_buffer)
        elif current_character == 'm':
            minutes = int(number_buffer)
        elif current_character == 'h':
            hours = int(number_buffer)
        elif current_character == 'd':
            days = int(number_buffer)
        elif current_character == 'w':
            weeks = int(number_buffer)
        else:
            raise ValueError('Invalid specifier - [{}]'.format(current_character))
        number_buffer = ''

    seconds += (minutes * 60)
    seconds += (hours * 3600)
    seconds += (days * 86400)
    seconds += (weeks * 604800)

    return seconds


def iface_addresses(rows, ifname):
    '''
    Return every found address and prefix length for given interface.

    example:
        {
        '192.168.1.1':
            {'prefix_length': 24}
        }
    '''
    found = (row['address'].split('/', 1) for row in rows if row['interface'] == ifname)
    pairs = ((cast_ip(address), int(prefix_length)) for address, prefix_length in found)
    return dict((address, dict(prefix_length=length)) for address, length in pairs)
