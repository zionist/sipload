import re

DOMAIN_NAME = "svyaznoy.ru"
SIP_HOST = "82.144.65.34"
SIP_PORT = 5060
RUNS_COUNT = 1
# seconds
CALL_DURATION = 8
INTERVAL = 0.1
WAIT_TIME = 200
AUTH_HEADER_REGEX = 'Digest\s+nonce="(.*?)",' \
                    '\s+opaque="(.*?)",\s+algorithm=md5,' \
                    '\s+realm="(.*?)", qop="auth"'
AUTH_HEADER_REGEX = re.compile(AUTH_HEADER_REGEX)
GET_METHOD_FROM_CSEQ_REGEX = '^\d+\s+(\D+)$'
GET_METHOD_FROM_CSEQ_REGEX = re.compile(GET_METHOD_FROM_CSEQ_REGEX)
AUTH_HEADER = 'Digest realm="%(realm)s", nonce="%(nonce)s", ' \
              'opaque="%(opaque)s", username="%(msisdn)s",  ' \
              'uri="%(uri)s", response="%(response)s", ' \
              'cnonce="%(cnonce)s", nc=%(nonce_count)s, qop=auth'
URI = "sip:svyaznoy.ru"
SDP_DATA = """v=0
o=%(msisdn)s %(num)s 3466 IN IP4 10.0.2.15
s=Talk
c=IN IP4 10.0.2.15
b=AS:380
t=0 0
m=audio 7076 RTP/AVP 120 111 110 0 8 101
a=rtpmap:120 SILK/16000
a=rtpmap:111 speex/16000
a=fmtp:111 vbr=on
a=rtpmap:110 speex/8000
a=fmtp:110 vbr=on
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
"""
SIP_STATUSES = {
    100: "Trying",
    180: "Ringing",
    181: "Call Is Being Forwarded",
    182: "Queued",
    183: "Session Progress",

    200: "OK",

    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Moved Temporarily",
    303: "See Other",
    305: "Use Proxy",
    380: "Alternative Service",

    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict", # Not in RFC3261
    410: "Gone",
    411: "Length Required", # Not in RFC3261
    413: "Request Entity Too Large",
    414: "Request-URI Too Large",
    415: "Unsupported Media Type",
    416: "Unsupported URI Scheme",
    420: "Bad Extension",
    421: "Extension Required",
    422: "Session Interval Too Small",
    423: "Interval Too Brief",
    432: "Test by semali02, not existed",
    480: "Temporarily Unavailable",
    481: "Call/Transaction Does Not Exist",
    482: "Loop Detected",
    483: "Too Many Hops",
    484: "Address Incomplete",
    485: "Ambiguous",
    486: "Busy Here",
    487: "Request Terminated",
    488: "Not Acceptable Here",
    491: "Request Pending",
    493: "Undecipherable",

    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway", # no donut
    503: "Service Unavailable",
    504: "Server Time-out",
    505: "SIP Version not supported",
    513: "Message Too Large",

    600: "Busy Everywhere",
    603: "Decline",
    604: "Does not exist anywhere",
    606: "Not Acceptable",

    4294967301: "Long code"
}

SIP_METHODS = [
    "INVITE",
    "ACK",
    "BYE",
    "CANCEL",
    "OPTIONS",
    "REGISTER",
    "PRACK",
    "SUBSCRIBE",
    "NOTIFY",
    "PUBLISH",
    "INFO",
    "REFER",
    "MESSAGE",
    "UPDATE"
]





