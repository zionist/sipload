__author__ = 'slaviann'

class ParseException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class NoFicsDataException(Exception):
    def __init__(self, value, package):
        self.value = value
        self.package = package
    def __str__(self):
        return repr("No fics %s for %s" % (self.value, self.package))


class WrongFileFormatException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr("File %s has wrong format. Must be pcap with linux cookie"
                    % self.value)
