import struct
import dpkt
from dpkt import hexdump
from dpkt.tcp import TCP
from dpkt.udp import UDP
from dpkt.pcap import Writer
from sipload.common.constants import SIP_METHODS
from sipload.exceptions import ParseException, WrongFileFormatException
from sipload.package import SipMessage, TptfMessage
from sipload.package import SipMessage
from sipload.package import TptfMessage

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
    return None


def parse_packages(filename):
    """
    Parse packages from filename.
    :param filename:
    :return: Iterator with packages
    """
    num = 0
    pcap_num = 0
    with open(filename) as f:
        pcap = dpkt.pcap.Reader(f)
        if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
            for ts, buf in pcap:
                pcap_num += 1
                sll = dpkt.sll.SLL(buf)
                ip = sll.data
                #if type(ip.data) != TCP and type(ip.data) != UDP:
                #    continue
                if ip.data.data:
                    package_type = determine_package_type(ip.data.data)
                    if package_type:
                        try:
                            for package in package_type.parse(ip.data.data):
                                num += 1
                                package.set_ts(ts)
                                package.set_pcap_package(sll)
                                package.set_num(num)
                                package.set_pcap_num(pcap_num)
                                yield package
                        except ParseException:
                            continue
        else:
            raise WrongFileFormatException(filename)


