from base import NetworkDriver

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.factory import loadyaml

globals().update(loadyaml('/home/ejasinska/github/napalm/napalm/junos.views'))

class JunOSDriver(NetworkDriver):

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.device = Device(hostname, user=username, password=password)

    def open(self):
        self.device.open()
        self.device.bind(cu=Config)
        self.device.cu.lock()

    def close(self):
        self.device.cu.unlock()
        self.device.close()

    def load_replace_candidate(self, filename=None, config=None):
        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()

        self.device.cu.load(configuration, format='text', overwrite=True)

    def load_merge_candidate(self, filename=None, config=None):
        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()

        self.device.cu.load(configuration, format='text')

    def compare_config(self):
        diff = self.device.cu.diff()

        if diff is None:
            return ''
        else:
            return diff

    def commit_config(self):
        self.device.cu.commit()

    def discard_config(self):
        self.device.cu.rollback(rb_id=0)

    def rollback(self):
        self.device.cu.rollback(rb_id=1)
        self.commit_config()

    def get_bgp_neighbors(self):
	bgp_neighbors = bgp_neigh_tbl(self.device)
        return bgp_neighbors.get()
	
