from lxml import etree


def xml_to_string(xml_object: etree.Element) -> str:
    return etree.tostring(xml_object).decode()
