import logging

__author__ = 'slaviann'


class BaseMessage(object):
    def __init__(self, headers={}, body=None, ts=None):
        self.headers = headers
        self.body = body
        self.pcap_package = None
        self.ts = None
        self.num = 0
        self.pcap_num = 0
        self.ip_dst = None
        self.ip_src = None

    @classmethod
    def parse(cls, msg):
        raise NotImplemented

    def gen_message(cls):
        raise NotImplemented

    def compare(self, other):
        raise NotImplemented

    def set_ts(self, ts):
        self.ts = ts

    def set_num(self, num):
        self.num = num

    def set_pcap_num(self, pcap_num):
        self.pcap_num = pcap_num

    def set_pcap_package(self, pcap_package):
        self.pcap_package = pcap_package

    def set_ip_src(self, ip_src):
        self.ip_src = ip_src

    def set_ip_dst(self, ip_dst):
        self.ip_dst = ip_dst
