import logging

__author__ = 'slaviann'

class BaseMessage(object):
    def __init__(self, headers={}, body=None):
        self.logger = logging.getLogger()
        self.headers = headers
        self.body = body

    @classmethod
    def parse(cls, msg):
        raise NotImplemented

    def gen_message(cls):
        raise NotImplemented
