import mock
import pytest


@pytest.mark.usefixtures("set_device_parameters")
class TestConfigMangling(object):
    def test_heredoc(self):

        raw_config = """hostname vEOS
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

        self.device.device.run_commands = mock.MagicMock()

        self.device._load_config(config=raw_config)

        expected_result = [
            "configure session {}".format(self.device.config_session),
            "rollback clean-config",
            "hostname vEOS",
            "ip name-server 192.0.2.1",
            {
                "cmd": "banner login",
                "input": "This is a banner that spans\nmultiple lines in order to test\nHEREDOC conversion" #  noqa
            },
            "management api http-commands",
            {
                "cmd": "protocol https certificate",
                "input": "---BEGIN CERTIFICATE---\nFAKE-CERTIFICATE-DATA\n---END CERTIFICATE---\nEOF\n---BEGIN PRIVATE KEY---\nFAKE-KEY-DATA\n---END PRIVATE KEY---"  # noqa
            },
            "management ssh",
            "idle-timeout 15"
        ]

        self.device.device.run_commands.assert_called_with(expected_result)
