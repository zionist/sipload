from sipload.common.constants import SIP_METHODS
from sipload.package import SipMessage, TptfMessage

__author__ = 'slaviann'


def determine_package_type(msg):
    """
    :param msg:  raw data
    :return: class of package
    """
    for header in SIP_METHODS:
        if msg.startswith(header):
            return SipMessage
    if msg.startswith("SIP/2.0"):
        return SipMessage
    if msg[8:12] == "TPTF" and msg[12:16] == "0010":
        return TptfMessage

