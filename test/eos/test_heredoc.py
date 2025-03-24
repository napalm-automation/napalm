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
            {
                "cmd": "banner login",
                "input": "This is a banner that spans\nmultiple lines in order to test\nHEREDOC conversion",  #  noqa
            },
            "management api http-commands",
            {
                "cmd": "protocol https certificate",
                "input": "---BEGIN CERTIFICATE---\nFAKE-CERTIFICATE-DATA\n---END CERTIFICATE---\nEOF\n---BEGIN PRIVATE KEY---\nFAKE-KEY-DATA\n---END PRIVATE KEY---",  # noqa
            },
            "management ssh",
            "idle-timeout 15",
            "end",
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
            {
                "cmd": "comment",
                "input": "This is a\nmultiline mode comment\nfor standard ACL test1",
            },
            "permit host 192.0.2.1",
            "ip access-list standard test2",
            {
                "cmd": "comment",
                "input": "This is a single-line mode comment for standard ACL test2",
            },
            "permit host 192.0.2.2",
            "ip access-list standard test3",
            {
                "cmd": "comment",
                "input": "This is a multi-line HEREDOC\ncomment for standard ACL test3",
            },
            "permit host 192.0.2.3",
            "end",
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
            {
                "cmd": "banner login",
                "input": "!! This is a banner that contains\n!!!bangs!",  #  noqa
            },
            "management ssh",
            "idle-timeout 15",
            "end",
        ]

        self.device.device.run_commands.assert_called_with(expected_result)
