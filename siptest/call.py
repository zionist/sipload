from collections import OrderedDict
import hashlib

__author__ = 'slaviann'


class Call:
    def __init__(self, check_rule):
        self.packages = []
        self.eth_packages = []
        self.session = None
        self.a_call_id = None
        self.b_call_id = None
        self.hash = hashlib.sha512()
        self.check_rule = check_rule

    def add_to_packages(self, package):
        self.packages.append(package)
        self.hash.update(package.gen_message)

    def add_eth_packages(self, package):
        self.eth_packages = []

    def gen_test(self):
        raise NotImplemented

    def gen_pcap(self):
        raise NotImplemented

    @property
    def hash(self):
        return self.hash.hexdigest()

    def check_call(self, package):
        if self.check_rule(package):
            return True
        else:
            return False



