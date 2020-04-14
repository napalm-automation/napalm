from lxml import etree


def xml_to_string(xml_object):
    return etree.tostring(xml_object).decode()
