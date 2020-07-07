"""pyeapi wrapper to fix cli syntax change"""
import pyeapi
from napalm.eos.utils.cli_syntax import cli_convert


class Node(pyeapi.client.Node):
    """
    pyeapi node wrapper to fix cli syntax change
    """

    def __init__(self, *args, **kwargs):
        if "cli_version" in kwargs:
            self.cli_version = kwargs["cli_version"]
            del kwargs["cli_version"]
        else:
            self.cli_version = 1

        super(Node, self).__init__(*args, **kwargs)

    def update_cli_version(self, version):
        """
        Update CLI version number for this device
        :param version: int: version number
        :return: None
        """
        self.cli_version = version

    def run_commands(self, commands, **kwargs):
        """
        Run commands wrapper
        :param commands: list of commands
        :param kwargs: other args
        :return: list of outputs
        """
        fn0039_transform = kwargs.pop("fn0039_transform", True)
        if fn0039_transform:
            if isinstance(commands, str):
                commands = [cli_convert(commands, self.cli_version)]
            else:
                commands = [cli_convert(cmd, self.cli_version) for cmd in commands]

        return super(Node, self).run_commands(commands, **kwargs)
