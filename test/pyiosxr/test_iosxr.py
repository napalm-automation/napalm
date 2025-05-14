#!/usr/bin/env python
# coding=utf-8
"""Unit tests for pyiosxr, a module to interact with Cisco devices running IOS-XR."""

import os
import sys
import time
import unittest
from lxml import etree as ET
from six import binary_type

# ~~~ import pyIOSXR modules ~~~
from napalm.pyIOSXR import IOSXR

# exceptions
from napalm.pyIOSXR.exceptions import LockError
from napalm.pyIOSXR.exceptions import UnlockError
from napalm.pyIOSXR.exceptions import XMLCLIError
from napalm.pyIOSXR.exceptions import CommitError
from napalm.pyIOSXR.exceptions import TimeoutError
from napalm.pyIOSXR.exceptions import IteratorIDError
from napalm.pyIOSXR.exceptions import InvalidInputError
from napalm.pyIOSXR.exceptions import InvalidXMLResponse


class _MockedNetMikoDevice(object):
    """
    Defines the minimum attributes necessary to mock a SSH connection using netmiko.
    """

    def __init__(self):
        class _MockedParamikoTransport(object):
            def close(self):
                pass

        self.remote_conn = _MockedParamikoTransport()

    def disconnect(self):
        self.remote_conn.close()

    @staticmethod
    def get_mock_file(command, format="xml"):
        filename = (
            command.replace(
                '<?xml version="1.0" encoding="UTF-8"?><Request MajorVersion="1" MinorVersion="0">',
                "",
            )
            .replace("</Request>", "")
            .replace("<", "")
            .replace(">", "_")
            .replace("/", "")
            .replace("\n", "")
            .replace(".", "_")
            .replace(" ", "_")
            .replace('"', "_")
            .replace("=", "_")
            .replace("$", "")
            .replace(":", "")
            .replace("!", "")[:150]
        )
        curr_dir = os.path.dirname(os.path.abspath(__file__))
        filename = "{filename}.{fmt}".format(filename=filename, fmt=format)
        fullpath = os.path.join(curr_dir, "mock", filename)
        with open(fullpath) as file_data:
            return file_data.read()

    def find_prompt(self):
        return self.get_mock_file("\n", format="txt")

    def send_command(
        self,
        command_string,
        expect_string="",
        read_timeout=10,
        strip_prompt=True,
        strip_command=True,
    ):
        return self.get_mock_file(command_string)

    def send_command_timing(self, command_string, **kvargs):
        return self.get_mock_file(command_string)

    def receive_data_generator(self):
        return ["", ""]  # to have an iteration inside private method _netmiko_recv

    def send_command_expect(
        self,
        command_string,
        expect_string=None,
        delay_factor=0.2,
        max_loops=500,
        auto_find_prompt=True,
        strip_prompt=True,
        strip_command=True,
    ):
        # for the moment returns the output from send_command only
        # this may change in time
        return self.send_command(command_string)


class _MockedIOSXRDevice(IOSXR):
    """
    Overrides only the very basic methods from the main device driver, that cannot be mocked.
    """

    def open(self):
        self.device = _MockedNetMikoDevice()
        self._cli_prompt = self.device.find_prompt()
        self._enter_xml_mode()

    def is_alive(self):
        return True


class TestIOSXRDevice(unittest.TestCase):
    """
    Tests IOS-XR basic functions.
    """

    HOSTNAME = "localhost"
    USERNAME = "vagrant"
    PASSWORD = "vagrant"
    PORT = 12205
    TIMEOUT = 0.1  # for tests, smaller values are prefferred
    LOCK = False
    LOG = sys.stdout
    MOCK = True

    def __repr__(self):
        return (
            "Connected as {user}@{host}:{port}, timeout is {tout}".format(
                user=self.USERNAME,
                host=self.HOSTNAME,
                port=self.PORT,
                tout=self.TIMEOUT,
            )
            if not self.MOCK
            else "Simulates device behaviour using mocked data."
        )

    __str__ = __repr__

    @classmethod
    def setUpClass(cls):
        """
        Opens the connection with the IOS-XR device.
        """

        if cls.MOCK:
            __cls = _MockedIOSXRDevice
        else:
            __cls = IOSXR

        cls.device = __cls(
            cls.HOSTNAME,
            cls.USERNAME,
            cls.PASSWORD,
            port=cls.PORT,
            lock=cls.LOCK,
            logfile=cls.LOG,
            timeout=cls.TIMEOUT,
        )
        cls.device.open()

    @classmethod
    def tearDownClass(cls):
        """
        Closes the connection with the device.
        """

        cls.device.close()

    def test_mock_lock_connection_open(self):
        if self.MOCK:
            self.device.lock_on_connect = True
            # because there's one single mock file
            # and it is already used for the lock test
            # will tesst if raises LockError on connect
            self.assertRaises(LockError, self.device.lock)
            self.device.lock_on_connect = False
            # enough to see that will try to lock during connect

    def test_mock_close(self):
        """Testing if unlocking when connection is closed"""

        if self.MOCK:
            self.device.locked = True
            self.device.close()
            self.assertFalse(self.device.locked, msg="Cannot unlock the DB.")

    def test_execute_rpc_method(self):
        """Testing private method _execute_rpc"""

        self.assertIsInstance(
            self.device._execute_rpc(
                "<Get><Configuration><NTP></NTP></Configuration></Get>"
            ),
            ET._Element,
            msg="Privat emethod _execute_rpc did not return a valid XML object.",
        )

    def test__getttr__show_(self):
        """Testing special attribute __getattr___ against valid show command"""

        self.assertIsInstance(
            self.device.show_ntp_ass(),
            str,
            "Special attribute __getattr___ did not return a valid string.",
        )

    def test__getttr__show_args(self):
        """Testing special attribute __getattr___ against valid show command with arguments"""

        self.assertIsInstance(self.device.show_ntp("ass"), str)

    def test_acquire_xml_agent(self):
        """Testing if able to acquire the XML agent."""

        self.device._lock_xml_agent(time.time())
        self.assertTrue(self.device._xml_agent_locker.locked())
        self.device._unlock_xml_agent()

    def test_acquire_locked_agent_raises_timeout_error(self):
        """Testing if trying to acquire the XML agent while locked raises TimeoutError."""
        self.device._lock_xml_agent(time.time())  # acquiring
        self.assertRaises(
            TimeoutError,
            self.device._lock_xml_agent,  # trying to acquire again
            time.time(),
        )
        self.device._unlock_xml_agent()  # releasing back

    def test_release_xml_agent(self):
        """Testing releasing of XML agent."""
        self.device._lock_xml_agent(time.time())
        self.assertTrue(self.device._xml_agent_locker.locked())
        self.device._unlock_xml_agent()
        self.assertFalse(self.device._xml_agent_locker.locked())

    def test_in_cli_mode(self):
        """Testing the private method _in_cli_mode."""
        self.assertTrue(self.device._in_cli_mode())

    def test__getattr_show_config(self):
        """Testing special attribute __getattr___ against valid show config command"""

        self.assertIsInstance(self.device.show_run_ntp(config=True), str)

    def test__getattr__no_show(self):
        """Test special attribute __getattr__ against a no-show command"""

        raised = False

        try:
            self.device.configure_exclusive()
        except AttributeError:
            raised = True

        self.assertTrue(raised)

    def test_make_rpc_call_returns_XML(self):
        """Test if public method make_rpc_call returns str"""

        self.assertIsInstance(
            self.device.make_rpc_call(
                "<Get><Configuration><NTP></NTP></Configuration></Get>"
            ),
            binary_type,
        )

    def test_acquired_xml_agent(self):
        """
        Testing if raises TimeoutError if the XML agent is alredy acquired and released when
        exception thrown
        """

        self.device._lock_xml_agent(time.time())  # acquiring the XML agent

        self.assertRaises(
            TimeoutError,
            self.device.make_rpc_call,
            "<Get><Operational><SystemTime/><PlatformInventory/></Operational></Get>",
        )

        self.assertFalse(
            self.device._xml_agent_locker.locked()
        )  # Exception raised => xml agent released

    def test_try_to_read_till_timeout(self):
        """Testing if will try to read from the device till time out"""

        if self.MOCK:
            # hard to reproduce without mock data
            # as this event is not deterministic
            self.assertRaises(
                TimeoutError, self.device.make_rpc_call, "<This/><Does/><Not/><Exist/>"
            )

    def test_multiple_read_attempts_till_timeout(self):
        """Testing if will try to read non-empty replies from the device till time out"""

        if self.MOCK:
            # hard to reproduce without mock data
            # as this event is not deterministic
            self.assertRaises(
                TimeoutError, self.device.make_rpc_call, "<Empty/><Reply/>"
            )

    def test_iterator_id_raises_IteratorIDError(self):
        """Testing if reply containing the IteratorID attribute raises IteratorIDError"""

        self.device.load_candidate_config(config="xml agent tty iteration on size 1")
        # minimum iteration size
        self.device.commit_config(comment="pyIOSXR-test_xml-agent-iteration-on")
        # turning on iteration
        # and a very small value

        # requesting something that we know for sure will be a big output
        self.assertRaises(
            IteratorIDError,
            self.device.make_rpc_call,
            "<Get><Operational><IPV4Network></IPV4Network></Operational></Get>",
        )

        self.device.rollback()
        # going to prev state

    def test_channel_acquired_enter_xml_mode(self):
        """Test if not raises ConnectError when the channel is busy with other requests"""

        self.device._lock_xml_agent()

        self.assertIsNone(self.device._enter_xml_mode())

    def test_truncated_response_raises_InvalidXMLResponse(self):
        """Testing if truncated XML reply raises InvalidXMLResponse"""

        if self.MOCK:
            # hard to reproduce without mock data
            # as this event is not deterministic
            self.assertRaises(
                InvalidXMLResponse,
                self.device._execute_rpc,
                "<Get><Configuration><Fake/></Configuration></Get>",
            )

    def test_iosxr_bug_0x44318c06(self):
        """Tests if IOS-XR bug returns error 0x44318c06 and raise XMLCLIError"""

        if self.MOCK:
            # hard to reproduce this without mock data
            # as this event is not deterministic
            self.assertRaises(
                XMLCLIError,
                self.device._execute_config_show,
                "show commit changes diff",
            )

    def test_empty_reply_raises_TimeoutError(self):
        """Testing if empty reply raises TimeoutError"""

        if self.MOCK:
            # hard to reproduce this without mock data
            # as this event is not deterministic
            self.assertRaises(TimeoutError, self.device._execute_rpc, "<Empty/>")

    def test_multiple_requests_raise_0xa3679e00(self):
        """Testing if simultaneuous requests trigger XMLCLIError"""

        if self.MOCK:
            self.assertRaises(
                XMLCLIError,
                self.device._execute_rpc,
                "<Get><Operational><ARP></ARP></Operational></Get>",
            )
        else:
            # must create a multithreading and send a couple of simultaneous requests to the device
            pass

    def test_execute_show(self):
        """Testing private method _execute_show"""

        self.assertIsInstance(self.device._execute_show("show ntp ass"), str)

    def test_execute_invalid_show_raises_InvalidInputError(self):
        """Testing if invalid show command raises InvalidInputError"""

        self.assertRaises(InvalidInputError, self.device._execute_show, "sh fake")

    def test_execute_config_show(self):
        """Testing private method _execute_config_show"""

        self.assertIsInstance(self.device._execute_config_show("show run ntp"), str)

    def test_execute_invalid_config_show_raises_InvalidInputError(self):
        """Testing if invalid config show command raises InvalidInputError"""

        self.assertRaises(
            InvalidInputError, self.device._execute_config_show, "sh run fake"
        )

    def test_lock_raises_LockError(self):
        """Tests if DB already locked raises LockError"""

        if self.MOCK:
            self.assertRaises(LockError, self.device.lock)
            self.assertFalse(self.device.locked)
        else:
            self.device.unlock()  # make sure the config is not locked
            same_device = IOSXR(
                self.HOSTNAME,
                self.USERNAME,
                self.PASSWORD,
                port=self.PORT,
                lock=self.LOCK,
                logfile=self.LOG,
                timeout=self.TIMEOUT,
            )
            same_device.open()
            same_device.lock()
            # the other instance locks the config DB

            try:
                # trying to acquire the config DB
                self.device.lock()
            except LockError:
                self.assertFalse(self.device.locked)
            else:
                self.assertTrue(self.device.locked)

            same_device.close()

    def test_unlock(self):
        """Testing unlock feature"""

        if self.MOCK:
            self.device.lock = True  # make sure it is locked
            self.device.unlock()
            self.assertFalse(self.device.locked)
        else:
            # make sure this process acquires the config DB
            self.device.lock()
            try:
                self.device.unlock()
            except UnlockError:
                # still locked
                self.assertTrue(self.device.locked)
            else:
                # not locked anymore
                self.assertFalse(self.device.locked)

    def _load_dummy_config(self):
        """Helper that loads some dummy data before committing."""

        config = """
        ntp peer 172.17.17.1
        """

        return self.device.load_candidate_config(config=config)

    def test_load_invalid_config_raises_InvalidInputError(self):
        """Testing if loading config with mistakes raises InvalidInputError"""

        self.assertRaises(
            InvalidInputError,
            self.device.load_candidate_config,
            config="ntp beer 256.257.258.259",
        )
        self.device.discard_config()

    def test_load_candidate_config_file(self):
        """Testing loading candidate config from file"""

        self.assertIsNone(
            self.device.load_candidate_config(
                filename=os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), "mock", "good.cfg"
                )
            )
        )

    def test_load_invalid_candidate_config_file_raises_InvalidInputError(self):
        """Testing if loading invalid config from a file raises InvalidInputError"""

        self.assertRaises(
            InvalidInputError,
            self.device.load_candidate_config,
            filename=os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "mock", "bad.cfg"
            ),
        )

    def test_load_config(self):
        """Testing if able to load candidate config, then check commit diff and discard changes"""

        self._load_dummy_config()

        self.assertIsInstance(
            self.device.get_candidate_config(),
            str,
            msg="Unable to retrieve the candidate config",
        )

        self.assertIsInstance(
            self.device.get_candidate_config(merge=True),
            str,
            msg="Unable to retrieve merge candidate config",
        )

        self.assertIsInstance(
            self.device.get_candidate_config(formal=True),
            str,
            msg="Unable to retrieve formal candidate config",
        )

        compare_result = self.device.compare_config()

        self.assertIsInstance(
            compare_result, str, msg="Unable to compare running and candidate config"
        )
        # test if the result is string

        self.assertGreater(len(compare_result), 0, msg="No config changes applied.")
        # test if len > 0

        # discarding config
        self.device.discard_config()

        if not self.MOCK:
            # will get the same mock file as above
            self.assertEqual(
                len(self.device.compare_config()), 0, msg="Unable to discard changes"
            )

    def test_commit_config(self):
        """Testing commit config"""

        self._load_dummy_config()

        self.assertIsNone(self.device.commit_config())

        self.device.rollback()

    def test_commit_config_message(self):
        """Testing commit config with comment message"""

        self._load_dummy_config()

        self.assertIsNone(self.device.commit_config(comment="good"))

        self.device.rollback()

    def test_commit_config_label(self):
        """Testing commit config with label"""

        self._load_dummy_config()

        self.assertIsNone(self.device.commit_config(label="test"))

        self.device.rollback()

    def test_commit_config_confirmed(self):
        """Testing commit confirmed"""

        self._load_dummy_config()

        self.assertIsNone(self.device.commit_config(confirmed=60))

        self.device.rollback()

    def test_commit_config_confirmed_raise_InvalidInputError(self):
        """Testing if incorrect value for confirm time raises InvalidInputError"""

        self.assertRaises(InvalidInputError, self.device.commit_config, confirmed=1)

    def test_commit_empty_buffer_raises(self):
        """Testing if trying to commit empty changes raises CommitError"""

        self.assertRaises(CommitError, self.device.commit_config, comment="empty")

    def test_commit_after_other_session_commit(self):
        """Testing if trying to commit after another process commited does not raise CommitError"""

        if self.MOCK:
            # mock data contains the error message we are looking for
            self.assertIsNone(self.device.commit_config(comment="parallel"))
        else:
            # to test this will neet to apply changes to the same device
            # through a different SSH session
            same_device = IOSXR(
                self.HOSTNAME,
                self.USERNAME,
                self.PASSWORD,
                port=self.PORT,
                lock=self.LOCK,
                logfile=self.LOG,
                timeout=self.TIMEOUT,
            )
            same_device.open()
            # loading something
            same_device.load_candidate_config(
                config="interface MgmtEth0/RP0/CPU0/0 description testing parallel commits"
            )
            # committing
            same_device.commit_config(comment="pyIOSXR-test_parallel_commits")

            # trying to load something from the test instance
            self.device.load_candidate_config(
                config="interface MgmtEth0/RP0/CPU0/0 description this wont work"
            )
            # and will fail because of the commit above
            self.assertIsNone(self.device.commit_config(comment="parallel"))

            # let's rollback the committed changes
            same_device.rollback()
            # and close the auxiliary connection
            same_device.close()

            # because this error was raised
            self.device.close()
            self.device.open()

    def _prefetch_running_config_and_append(self):
        """Helper method to be used in the config-replace tests below"""

        running_config = "".join(self.device.show_run().splitlines(1)[3:])
        self.device.load_candidate_config(config=running_config)
        self.device.load_candidate_config(config="ntp server 8.8.8.8")

    def test_compare_replace_config(self):
        """Testing compare replace config"""

        self._prefetch_running_config_and_append()

        self.assertIsInstance(self.device.compare_replace_config(), str)

    def test_commit_replace_config(self):
        """Testing commit replace config"""

        self._prefetch_running_config_and_append()

        self.assertIsNone(self.device.commit_replace_config())

    def test_commit_replace_config_message(self):
        """Testing commit replace config with comment message"""

        self._prefetch_running_config_and_append()

        self.assertIsNone(self.device.commit_replace_config(comment="good"))

    def test_commit_replace_config_label(self):
        """Testing commit replace config with label"""

        self._prefetch_running_config_and_append()

        self.assertIsNone(self.device.commit_replace_config(label="test"))

    def test_commit_replace_config_confirmed(self):
        """Testing commit replace confirmed"""

        self._prefetch_running_config_and_append()

        self.assertIsNone(self.device.commit_replace_config(confirmed=60))

    def test_commit_replace_config_confirmed_raise_InvalidInputError(self):
        """Testing if incorrect value for confirmed replace commit time raises InvalidInputError"""

        self.assertRaises(
            InvalidInputError, self.device.commit_replace_config, confirmed=500
        )


if __name__ == "__main__":
    unittest.main()
