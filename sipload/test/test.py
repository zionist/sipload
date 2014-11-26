import unittest
from sipload.common.utils import TptfIterator

__author__ = 'slaviann'

class TestIterator(unittest.TestCase):

    def test_main(self):
        iterator = TptfIterator("/tmp/cut.pcap")
        for i in iterator:
            pass
