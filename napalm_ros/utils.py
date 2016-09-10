import datetime
import re

def export_concat(export_config):
    export_section = None
    line_buffer = []

    concat_config = []
    for line in export_config:
        if line == '':
            continue
        if line[0] == '/':
            export_section = line
            continue
        elif line[0] == '#':
            continue
        elif line[-1:] == '\\':
            line_buffer.append(line[:-1].lstrip())
        else:
            if export_section is None:
                raise ValueError('No configuration section')
            line_buffer.append(line.lstrip())
            line_buffer.insert(0, '{} '.format(export_section))
            concat_config.append(''.join(line_buffer))
            line_buffer = []
    return concat_config

def index_values(values, key='name'):
    values_indexed = {}
    for value in values:
        if key in value:
            if value[key] not in values_indexed:
                values_indexed[value[key]] = []
            values_indexed[value[key]].append(value)
        else:
            raise KeyError('Key not seen - [{}]'.format(key))
    return values_indexed

def is_cli_error(output_line):
    re_match = re.match(r'[^\(]+\(line \d+ column \d+\)', output_line)
    if re_match is not None:
        return True
    return False

def is_cli_warning(output_line):
    re_match = re.match(r'\[([^\]]+)\]$', output_line)
    if re_match is not None:
        return True
    return False

def parse_as_key_value(keys_and_values):
    as_key_value = {}

    last_key = None
    for kv_part in keys_and_values:
        if kv_part.find('=') != -1:
            key, value = kv_part.split('=', 1)
            if key in as_key_value:
                raise KeyError('Key already seen - [{}]'.format(key))
            as_key_value[key] = value
            last_key = key
        elif last_key is not None:
            as_key_value[last_key] += ' {}'.format(kv_part)
        else:
            raise ValueError(kv_part)
    return as_key_value

def parse_print_as_value(print_as_values):
    as_value = []
    for line in print_as_values.replace('.id=*', '\n.id=*').splitlines():
        if line == '':
            continue
        as_value.append(parse_as_key_value(line.split(';')))
    return as_value

def print_concat(print_output):
    concat = []
    for line in print_output:
        if line == '':
            continue
        if line.startswith('   '):
            concat[-1] = ' '.join([concat[-1], line.strip()])
        else:
            if line.find(';;; ') != -1:
                line = line.replace(';;; ', 'comment=')
            concat.append(line.strip())
    return concat

def print_to_values(print_output):
    to_values = {}
    for line in print_output:
        if line == '':
            continue
        key, value = line.split(':', 1)
        if key in to_values:
            raise KeyError('Key already seen - [{}]'.format(key))
        to_values[key.strip()] = value.strip()
    return to_values

def print_to_values_structured(print_output):
    to_values_structured = []
    for line in print_output:
        line_parts = line.strip().split()
        if len(line_parts) == 0:
            continue
        if line_parts[0].isdigit():
            index_seen = line_parts.pop(0)
        else:
            index_seen = -1
        flags_seen = ''
        while True:
            if not len(line_parts):
                raise ValueError('No parts available')
            part = line_parts.pop(0)
            if part.find('=') == -1:
                flags_seen += part
            else:
                line_parts.insert(0, part)
                line_parts.insert(0, 'flags={}'.format(flags_seen))
                line_parts.insert(0, 'index={}'.format(index_seen))
                break
        to_values_structured.append(parse_as_key_value(line_parts))
    return to_values_structured

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
