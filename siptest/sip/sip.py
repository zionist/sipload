from collections import OrderedDict
import logging
import hashlib
import uuid

from siptest.common.constants import DOMAIN_NAME, AUTH_HEADER_REGEX, URI, \
    AUTH_HEADER, SIP_STATUSES, GET_METHOD_FROM_CSEQ_REGEX


class SipMessage:
    """
    Very simple SIP Message
    """
    def __init__(self, method=None, headers={}, body=None,
                 status=None, is_request=True):
        self.logger = logging.getLogger()
        self.method = method
        self.headers = headers
        self.body = body
        self.status = status
        self.is_request = is_request
        self.logger = logging.getLogger()

        # parse headers
        self.to = self.headers.get("To")[0].split(";")[0].\
            replace("<", "").replace(">", "")
        self.frm = self.headers.get("From")[0].split(";")[0]
        self.call_id = self.headers.get("Call-ID")[0]

    def copy(self):
        msg = SipMessage(method=self.method, headers=self.headers,
                         body=self.body, status=self.status,
                         is_request=self.is_request, to=self.to, frm=self.frm)
        return msg

    def gen_message(self):
        """
        Generate text SIP message
        :return:
        """
        # request
        result = ""
        if self.is_request:
            if self.to:
                result += "%(method)s tel:%(to)s@%(domain)s SIP/2.0\n" % {
                    'method': self.method,
                    'domain': DOMAIN_NAME,
                    'to': self.to,
                }
            else:
                result += "%(method)s tel:%(domain)s SIP/2.0\n" % {
                    'method': self.method,
                    'domain': DOMAIN_NAME,
                }
        else:
            result += "SIP/2.0 %s %s\n" % (self.status,
                                         SIP_STATUSES[self.status])
        for key, value in self.headers.items():
            for header in value:
                result += "%s: %s\n" % (key, header)
        result += "\n"
        if self.body:
            result += self.body
            # result += "\n"
        # result = result.encode('utf8')
        return result

    @classmethod
    def parse(cls, msg):
        """
        Create objects from text message. Can be two or more
        messages in one message text
        :param msg: text message
        :return: List of SipMessage objects
        """
        lines = msg.split("\n")
        status = None
        is_request = None
        method = None
        if lines[0].startswith("SIP/2.0"):
            is_request = False
            # this is answer
            status = int(lines[0].split()[1])
        elif lines[0].endswith("SIP/2.0\r"):
            is_request = True
            method = lines[0].split()[0]
            to = lines[0].split()[1].split(":")[1]
        lines = lines[1:]
        headers = OrderedDict()

        lines_count = 0
        for line in lines:
            lines_count += 1
            if not line or line == "\r":
                break
            l = line.split(":")
            key = l[0]
            l = l[1:]
            value = ":".join(l).strip()
            if headers.get(key):
                headers[key].append(value)
            else:
                headers[key] = [value]
        # get method from CSeq header
        if not is_request:
            if headers.get("CSeq"):
                m = GET_METHOD_FROM_CSEQ_REGEX.match(headers.get("CSeq")[0])
                if m:
                    method = m.group(1)
        # may be there is a body in package
        body = None
        lines = lines[lines_count:]
        if headers.get("Content-Length") and int(headers["Content-Length"][0]):
            body = []
            for line in lines:
                #if not line or line == "\r":
                #    break
                body.append(line)
            body = "\n".join(body)
        return SipMessage(headers=headers, status=status,
                          is_request=is_request, method=method,
                          body=body)
