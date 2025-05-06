from unittest import mock
import pytest
from textwrap import dedent


@pytest.mark.usefixtures("set_device_parameters")
class TestConfigMangling(object):
    def test_heredoc(self):
        raw_config = dedent(
            """\
        hostname vEOS
        ip name-server 192.0.2.1
        !
        banner login
        This is a banner that spans
        multiple lines in order to test
        HEREDOC conversion
        EOF
        !
        management ssh
          idle-timeout 15
        !
        """
        )

        self.device.device.run_commands = mock.MagicMock()

        self.device._load_config(config=raw_config)

        expected_result = [
            "configure session {}".format(self.device.config_session),
            "rollback clean-config",
            "hostname vEOS",
            "ip name-server 192.0.2.1",
            "banner login",
            "This is a banner that spans",
            "multiple lines in order to test",
            "HEREDOC conversion",
            "EOF",
            "management ssh",
            "idle-timeout 15",
        ]

        self.device.device.run_commands.assert_called_with(expected_result)

    def test_mode_comment(self):
        raw_config = dedent(
            """\
        ip access-list standard test1
            !! This is a
            !! multiline mode comment
            !! for standard ACL test1
            permit host 192.0.2.1
        !
        ip access-list standard test2
            !! This is a single-line mode comment for standard ACL test2
            permit host 192.0.2.2
        !
        ip access-list standard test3
            comment
            This is a multi-line HEREDOC
            comment for standard ACL test3
            EOF
            permit host 192.0.2.3
        !
        """
        )

        self.device.device.run_commands = mock.MagicMock()

        self.device._load_config(config=raw_config, replace=False)

        expected_result = [
            "configure session {}".format(self.device.config_session),
            "ip access-list standard test1",
            "!! This is a",
            "!! multiline mode comment",
            "!! for standard ACL test1",
            "permit host 192.0.2.1",
            "ip access-list standard test2",
            "!! This is a single-line mode comment for standard ACL test2",
            "permit host 192.0.2.2",
            "ip access-list standard test3",
            "comment",
            "This is a multi-line HEREDOC",
            "comment for standard ACL test3",
            "EOF",
            "permit host 192.0.2.3",
        ]

        self.device.device.run_commands.assert_called_with(expected_result)

    def test_heredoc_with_bangs(self):
        raw_config = dedent(
            """\
        hostname vEOS
        ip name-server 192.0.2.1
        !
        banner login
        !! This is a banner that contains
        !!!bangs!
        EOF
        !
        management ssh
          idle-timeout 15
        !
        """
        )

        self.device.device.run_commands = mock.MagicMock()

        self.device._load_config(config=raw_config)

        expected_result = [
            "configure session {}".format(self.device.config_session),
            "rollback clean-config",
            "hostname vEOS",
            "ip name-server 192.0.2.1",
            "banner login",
            "!! This is a banner that contains",
            "!!!bangs!",
            "EOF",
            "management ssh",
            "idle-timeout 15",
        ]

        self.device.device.run_commands.assert_called_with(expected_result)

    def test_heredoc_with_blank_lines(self):
        raw_config = dedent(
            """\
        hostname vEOS
        ip name-server 192.0.2.1
        !
        banner login

        This is a banner that spans
        multiple lines in order to test
        HEREDOC conversion

        EOF
        !
        management api http-commands
          protocol https certificate
          ---BEGIN CERTIFICATE---
          FAKE-CERTIFICATE-DATA
          ---END CERTIFICATE---
          EOF
          ---BEGIN PRIVATE KEY---
          FAKE-KEY-DATA
          ---END PRIVATE KEY---
          EOF
        !
        management ssh
          idle-timeout 15
        !
        """
        )

        self.device.device.run_commands = mock.MagicMock()

        self.device._load_config(config=raw_config)

        expected_result = [
            "configure session {}".format(self.device.config_session),
            "rollback clean-config",
            "hostname vEOS",
            "ip name-server 192.0.2.1",
            "banner login",
            "",
            "This is a banner that spans",
            "multiple lines in order to test",
            "HEREDOC conversion",
            "",
            "EOF",
            "management api http-commands",
            "protocol https certificate",
            "---BEGIN CERTIFICATE---",
            "FAKE-CERTIFICATE-DATA",
            "---END CERTIFICATE---",
            "EOF",
            "---BEGIN PRIVATE KEY---",
            "FAKE-KEY-DATA",
            "---END PRIVATE KEY---",
            "EOF",
            "management ssh",
            "idle-timeout 15",
        ]

        self.device.device.run_commands.assert_called_with(expected_result)
