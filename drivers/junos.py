from base import NetworkDriver

from ncclient import manager


def __execute_rpc__(conn, rpc_command):
    output = conn.rpc(str(rpc_command))

    if len(output.xpath('/rpc-reply/error')) > 0:
        raise Exception(output.tostring)

    return output


class JunOSDriver(NetworkDriver):

    def __init__(self, hostname, user, password):
        self.hostname = hostname
        self.user = user
        self.password = password

    def open(self):
        self.device = manager.connect(
            host=self.hostname,
            port=830,
            username=self.user,
            password=self.password,
            timeout=10,
            hostkey_verify=False,
            device_params={'name':'junos'},
        )
        rpc_command = '<lock><target><candidate/></target></lock>'
        __execute_rpc__(self.device, rpc_command)

    def close(self):
        rpc_command = '<unlock><target><candidate/></target></unlock>'
        __execute_rpc__(self.device, rpc_command)
        self.device.close_session()

    def load_candidate_config(self, filename=None, config=None):

        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()

        rpc_command = '''
        <load-configuration format="text" action="replace">
            <configuration-text>
                %s
            </configuration-text>
        </load-configuration>
        ''' % configuration

        __execute_rpc__(self.device, rpc_command)

    def compare_config(self):
        rpc_command = '''
        <get-configuration changed="changed" database= "candidate" format="text" compare="rollback" rollback="0">
        </get-configuration>'''
        conf = __execute_rpc__(self.device, rpc_command)
        return conf.xpath('/rpc-reply/configuration-information/configuration-output')[0].text

    def commit_config(self):
        rpc_command = '<commit/>'
        __execute_rpc__(self.device, rpc_command)

    def discard_config(self):
        rpc_command = '<discard-changes/>'
        __execute_rpc__(self.device, rpc_command)

    def rollback(self):
        rpc_command = '<load-configuration rollback="1"/>'
        __execute_rpc__(self.device, rpc_command)
        self.commit_config()

