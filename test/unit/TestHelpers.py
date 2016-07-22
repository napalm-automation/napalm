"""
Test base helpers.
"""

# Python std lib
import os
import sys
import unittest

# third party libs
try:
    import jinja2
    HAS_JINJA = True
except ImportError:
    HAS_JINJA = False

try:
    import textfsm
    HAS_TEXTFSM = True
except ImportError:
    HAS_TEXTFSM = False

try:
    from lxml import etree as ET
    HAS_LXML = True
except ImportError:
    HAS_LXML = False

# NAPALM base
import napalm_base.helpers
import napalm_base.exceptions
from napalm_base.base import NetworkDriver


class TestBaseHelpers(unittest.TestCase):
    """Test helpers functions."""

    @classmethod
    def setUpClass(cls):
        cls.network_driver = FakeNetworkDriver()
        # neded when calling helpers

    def test_load_template(self):

        """
        Tests the helper function ```load_template```:

            * check if raises TemplateNotImplemented when trying to use inexisting template
            * check if can load empty template
            * check if raises TemplateRenderException when template is not correctly formatted
            * check if can load correct template
            * check if can load correct template even if wrong custom path specified
            * check if raises TemplateNotImplemented when trying to use inexisting template in custom path
            * check if can load correct template from custom path
            * check if template passed as string can be loaded
        """

        self.assertTrue(HAS_JINJA)  # firstly check if jinja2 is installed

        _NTP_PEERS_LIST = [
            '172.17.17.1',
            '172.17.17.2'
        ]
        _TEMPLATE_VARS = {
            'peers': _NTP_PEERS_LIST
        }

        self.assertRaises(napalm_base.exceptions.TemplateNotImplemented,
                          napalm_base.helpers.load_template,
                          self.network_driver,
                          '__this_template_does_not_exist__',
                          **_TEMPLATE_VARS)

        self.assertTrue(napalm_base.helpers.load_template(self.network_driver,
                                                          '__empty_template__',
                                                          **_TEMPLATE_VARS))

        self.assertRaises(napalm_base.exceptions.TemplateRenderException,
                          napalm_base.helpers.load_template,
                          self.network_driver,
                          '__completely_wrong_template__',
                          **_TEMPLATE_VARS)

        self.assertTrue(napalm_base.helpers.load_template(self.network_driver,
                                                          '__a_very_nice_template__',
                                                          **_TEMPLATE_VARS))

        self.assertTrue(napalm_base.helpers.load_template(self.network_driver,
                                                          '__a_very_nice_template__',
                                                          template_path='/this/path/does/not/exist',
                                                          **_TEMPLATE_VARS))

        install_dir = os.path.dirname(os.path.abspath(sys.modules[self.network_driver.__module__].__file__))
        custom_path = os.path.join(install_dir, 'test/custom/path/base')

        self.assertRaises(napalm_base.exceptions.TemplateNotImplemented,
                          napalm_base.helpers.load_template,
                          self.network_driver,
                          '__this_template_does_not_exist__',
                          template_path=custom_path,
                          **_TEMPLATE_VARS)

        self.assertTrue(napalm_base.helpers.load_template(self.network_driver,
                                                          '__a_very_nice_template__',
                                                          template_path=custom_path,
                                                          **_TEMPLATE_VARS))

        template_source = '{% for peer in peers %}ntp peer {{peer}}\n{% endfor %}'

        self.assertTrue(napalm_base.helpers.load_template(self.network_driver,
                                                          '_this_still_needs_a_name',
                                                          template_source=template_source,
                                                          **_TEMPLATE_VARS))

    def test_textfsm_extractor(self):

        """
        Tests the helper function ```textfsm_extractor```:

            * check if raises TemplateNotImplemented when template is not defined
            * check if raises TemplateRenderException when template is empty
            * check if raises TemplateRenderException when template is not properly defined
            * check if returns a non-empty list as output
        """

        self.assertTrue(HAS_TEXTFSM)  # before anything else, let's see if TextFSM is available

        _TEXTFSM_TEST_STRING = '''
        Groups: 3 Peers: 3 Down peers: 0
        Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending
        inet.0               947        310          0          0          0          0
        inet6.0              849        807          0          0          0          0
        Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Damped...
        10.247.68.182         65550     131725   28179233       0      11     6w3d17h Establ
          inet.0: 4/5/1
          inet6.0: 0/0/0
        10.254.166.246        65550     136159   29104942       0       0      6w5d6h Establ
          inet.0: 0/0/0
          inet6.0: 7/8/1
        192.0.2.100           65551    1269381    1363320       0       1      9w5d6h 2/3/0 0/0/0
        '''

        self.assertRaises(napalm_base.exceptions.TemplateNotImplemented,
                          napalm_base.helpers.textfsm_extractor,
                          self.network_driver,
                          '__this_template_does_not_exist__',
                          _TEXTFSM_TEST_STRING)

        self.assertRaises(napalm_base.exceptions.TemplateRenderException,
                          napalm_base.helpers.textfsm_extractor,
                          self.network_driver,
                          '__empty_template__',
                          _TEXTFSM_TEST_STRING)

        self.assertRaises(napalm_base.exceptions.TemplateRenderException,
                          napalm_base.helpers.textfsm_extractor,
                          self.network_driver,
                          '__completely_wrong_template__',
                          _TEXTFSM_TEST_STRING)

        self.assertIsInstance(napalm_base.helpers.textfsm_extractor(self.network_driver,
                                                                    '__a_very_nice_template__',
                                                                    _TEXTFSM_TEST_STRING),
                              list)

    def test_convert(self):

        """
        Tests helper function ```convert```:

            * cast of non-int str to int returns default value
            * cast of str to float returns desired float-type value
            * cast of None obj to string does not cast, but returns default
        """

        self.assertTrue(napalm_base.helpers.convert(int, 'non-int-value', default=-100) == -100)
        # default value returned
        self.assertIsInstance(napalm_base.helpers.convert(float, '1e-17'), float)
        # converts indeed to float
        self.assertFalse(napalm_base.helpers.convert(str, None) == 'None')
        # should not convert None-type to 'None' string
        self.assertTrue(napalm_base.helpers.convert(str, None) == u'')
        # should return empty unicode

    def test_find_txt(self):

        """
        Tests helper function ```find_txt```:

            * check if returns default when retrieving from wrong path
            * check if non-empty string inside existing tag
            * check if can parse boolean values as text
            * check if can retrieve int values
        """

        self.assertTrue(HAS_LXML)  # firstly check if lxml is installed

        _XML_STRING = '''
        <family>
            <parent1>
                <child1>
                    Hi, I am child1 of parent1.
                </child1>
                <child2>
                    Hi, I am child2 of parent1.
                </child2>
                <child3>
                    Hi, I am child3 of parent1.
                </child3>
            </parent1>
            <parent2>
                <child1>
                    Hi, I am child1 of parent2.
                </child1>
                <child2 special="true">
                    Haha.
                </child2>
            </parent2>
            <parent3 lonely="true"></parent3>
            <stats>
                <parents>3</parents>
                <children>4</children>
            </stats>
        </family>
        '''

        _XML_TREE = ET.fromstring(_XML_STRING)

        self.assertFalse(napalm_base.helpers.find_txt(_XML_TREE, 'parent100/child200', False))
        # returns default value (in this case boolean value False)

        self.assertTrue(len(
                            napalm_base.helpers.find_txt(_XML_TREE, 'parent1/child1')
                           ) > 0
                       )  # check if content inside the tag /parent1/child1
        self.assertTrue(eval(
                             napalm_base.helpers.find_txt(_XML_TREE, 'parent3/@lonely', 'false').title()
                            )
                       )  # check if able to eval boolean returned as text inside the XML tree
        self.assertIsInstance(int(
                                  napalm_base.helpers.find_txt(_XML_TREE, 'stats/parents')
                                 ),
                              int
                             )  #  int values

        _CHILD3_TAG = _XML_TREE.find('.//child3')  # get first match of the tag child3, wherever would be

        self.assertTrue(len(
                            napalm_base.helpers.find_txt(_CHILD3_TAG, '.')
                           ) > 0
                       )  # check if content inside the discovered tag child3

        _SPECIAL_CHILD2 = _XML_TREE.find('.//child2[@special="true"]')

        self.assertTrue(len(
                            napalm_base.helpers.find_txt(_SPECIAL_CHILD2, '.')
                           ) > 0
                       )

        _SPECIAL_CHILD100 = _XML_TREE.find('.//child100[@special="true"]')

        self.assertFalse(len(
                            napalm_base.helpers.find_txt(_SPECIAL_CHILD100, '.')
                           ) > 0
                       )

        _NOT_SPECIAL_CHILD2 = _XML_TREE.xpath('.//child2[not(@special="true")]')[0]
        # use XPath to get tags using predicates!

        self.assertTrue(len(
                            napalm_base.helpers.find_txt(_NOT_SPECIAL_CHILD2, '.')
                           ) > 0
                       )

    def test_mac(self):

        """
        Tests the helper function ```mac```:

            * check if empty reply when invalid MAC
            * check if MAC address returned as expected
        """

        self.assertEqual(napalm_base.helpers.mac('fake'), '')
        self.assertEqual(napalm_base.helpers.mac('0123456789ab'), '01:23:45:67:89:AB')
        self.assertEqual(napalm_base.helpers.mac('0123.4567.89ab'), '01:23:45:67:89:AB')
        self.assertEqual(napalm_base.helpers.mac('123.4567.89ab'), '01:23:45:67:89:AB')


class FakeNetworkDriver(NetworkDriver):

    def __init__(self):

        """Connection details not needed."""

        pass

    def load_merge_candidate(self, config=None):

        """
        This method is called at the end of the helper ```load_template```.
        To check whether the test arrives at the very end of the helper function,
        will return True instead of raising NotImplementedError exception.
        """

        return True
