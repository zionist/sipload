import logging

__author__ = 'slaviann'

class BaseMessage(object):
    def __init__(self, headers={}, body=None, ts=None):
        self.logger = logging.getLogger()
        self.headers = headers
        self.body = body
        self.pcap_package = None
        self.ts = None
        self.num = 0

    @classmethod
    def parse(cls, msg):
        raise NotImplemented

    def gen_message(cls):
        raise NotImplemented

    def set_ts(self, ts):
        self.ts = ts

    def set_num(self, num):
        self.num = num

    def set_pcap_package(self, pcap_package):
        self.pcap_package = pcap_package

