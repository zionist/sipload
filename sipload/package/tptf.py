from collections import OrderedDict
import logging
import struct
from sipload.exceptions import ParseException, NoFicsDataException
from sipload.package.base import BaseMessage

__author__ = 'slaviann'

class TptfFics(object):
    def __init__(self, params={}):
        self.params = params
        self.name = params["name"]
        self.data = params["data"]
        # self.logger = logging.getLogger()


    def __str__(self):
        return "%s: %s" % (self.params["name"], self.params["data"])

    @classmethod
    def parse(cls, body):
        """
        Create object from body data. Must not contains headers
        :param body:
        :return: TptfFics object or None if no more objects to parse
        """
        try:
            params = {}
            fics_format = [
                ["name", 10, "<10s"],
                ["flags", 1, "<b"],
                ["eye", 1, "<b"],
                ["length", 4, "<i"],
            ]
            for frm in fics_format:
                params[frm[0]] = struct.unpack(frm[2], body[:frm[1]])[0]
                body = body[frm[1]:]
            # we have the length of the fics. So we can load data using it
            params["data"] = struct.unpack("<%ss" % params["length"],
                                           body[:params["length"]])[0]
            # we can skip last separate empty byte
            params["data"] = params["data"][:-1]
            # cleanup name from empty bytes
            name = []
            for c in params["name"]:
                if not c is '\x00':
                    name.append(c)
            params["name"] = "".join(name)
        except struct.error as e:
            logging.warning("TPTF parse fics error")
            logging.warning("Data for parse was: #%s#" % body)
            raise e
        return TptfFics(params=params)


    def size(self):
        """
        Get bytes count
        """
        # Name + Flags + Eye + Length + data size + blank F
        return 10 + 1 + 1 + 4 + self.params["length"]


class TptfMessage(BaseMessage):

    def __init__(self, headers={}, body=None, ficses=[]):
        super(TptfMessage, self).__init__(headers=headers, body=body)
        self.ficses = ficses

    def __str__(self):
        result = "\n# TPTF %s %s " % (self.num, self.state) + \
                 "%s "% self.headers["retfunc"] + " -> %s\n" \
                                                 % self.headers["tofunc"]

        result += "# headers \n"
        for key, value in self.headers.iteritems():
            result += "%s: %s, " % (key, value)
        if self.ficses:
             result += "\n# data \n"
        for fics in self.ficses:
            result += str(fics) + ", "
        return result

    def get_fics_value_by_name(self, name):
        for fics in self.ficses:
            if name == fics.name:
                return fics.data
        return None
        # raise NoFicsDataException(name, self)

    def compare(self, other):
        """
        Compare packages.
        """
        if type(self) != type(other):
            return False
        if not self.headers["tofunc"] == other.headers["tofunc"]:
            return False
        if not self.headers["retfunc"][:3] == other.headers["retfunc"][:3]:
            return False
        if not self.headers["flags"] == other.headers["flags"]:
            return False
        if not self.headers["cc"] == other.headers["cc"]:
            return False
        if not self.headers["rsn"] == other.headers["rsn"]:
            return False
        return True

    @property
    def state(self):
        if self.headers["flags"] == 2048:
            return "Reply"
        elif self.headers["flags"] == -32768:
            return "Ack"
        elif self.headers["flags"] == 0:
            return "New"


    @classmethod
    def parse_header(cls, msg):
        header_format = [
            ["issuestamp", 4, "<i"],
            ["compstamp", 4, "<i"],
            ["eye", 4, "<4s"],
            ["version", 4, "<4s"],
            ["type", 4, "<4s"],
            ["cc", 2, "<h"],
            ["rsn", 2, "<h"],
            ["prio", 2, "<h"],
            ["class", 2, "<h"],
            ["transnumb", 4, "<i"],
            ["tofunc", 8, "<8s"],
            ["retfunc", 8, "<8s"],
            ["flags", 2, "<h"],
            ["comptransnumb", 2, "<h"],
            ["datalen", 4, "<i"],
            ["udata", 8, "<8s"],
            ]

        headers = {}
        header_str = msg[:64]
        for frm in header_format:
            headers[frm[0]] = struct.unpack(frm[2], header_str[:frm[1]])[0]
            header_str = header_str[frm[1]:]
        return headers


    @classmethod
    def parse(cls, msg):
        """
        Create objects from text message. Can be two or more
        messages in one message text
        :param msg: text message
        :return: TptfMessage object
        """
        try:
            while msg:
                headers = cls.parse_header(msg)
                # we know header size
                msg = msg[64:]

                if not headers["datalen"]:
                    yield TptfMessage(headers=headers)

                ficses = []
                data = msg[:headers["datalen"]]
                while data:
                    fics = TptfFics.parse(data)
                    ficses.append(fics)
                    data = data[fics.size():]
                msg = msg[headers["datalen"]:]
                yield TptfMessage(headers=headers, ficses=ficses)
        except struct.error as e:
            logging.warning("TPTF parse header error")
            logging.warning("Data for parse was: #%s#" % msg)
            raise ParseException("Can't parse TPTF data")


