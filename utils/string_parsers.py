def colon_separated_string_to_dict(string):
    '''
    Converts a string in the format:

        Name: Et3
        Switchport: Enabled
        Administrative Mode: trunk
        Operational Mode: trunk
        MAC Address Learning: enabled
        Access Mode VLAN: 3 (VLAN0003)
        Trunking Native Mode VLAN: 1 (default)
        Administrative Native VLAN tagging: disabled
        Administrative private VLAN mapping: ALL
        Trunking VLANs Enabled: 2-3,5-7,20-21,23,100-200
        Trunk Groups:

    into a dictionary

    '''
    dictionary = dict()

    for line in string.splitlines():
        line_data = line.split(':')

        if len(line_data) > 1:
            dictionary[line_data[0].strip()] = ''.join(line_data[1:])
        elif len(line_data) == 1:
            dictionary[line_data[0].strip()] = None
        else:
            raise Exception('Something went wrong parsing the colo separated string {}'.format(line))

    return dictionary


def hyphen_range(string):
    '''
    Expands a string of numbers separated by commas and hyphens into a list of integers.
    For example:  2-3,5-7,20-21,23,100-200
    '''
    list_numbers = list()
    temporary_list = string.split(',')

    for element in temporary_list:
        sub_element = element.split('-')

        if len(sub_element) == 1:
            list_numbers.append(int(sub_element[0]))
        elif len(sub_element) == 2:
            for x in range(int(sub_element[0]), int(sub_element[1])+1):
                list_numbers.append(x)
        else:
            raise Exception('Something went wrong expanding the range'.format(string))

    return list_numbers
