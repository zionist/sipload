import logging
from multiprocessing import Manager, Pool, cpu_count, TimeoutError
import socket
import struct
import dpkt
from dpkt import hexdump
from dpkt.tcp import TCP
from dpkt.udp import UDP
from dpkt.pcap import Writer
import time
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


def get_packages(filename):
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
                if type(ip.data) != TCP and type(ip.data) != UDP:
                    continue
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
                                package.set_ip_dst(socket.inet_ntoa(ip.dst))
                                package.set_ip_src(socket.inet_ntoa(ip.src))

                                # socket.inet_ntoa(struct.unpack("<L", ip.dst))
                                #package.set_ip_dst(socket.inet_ntoa(struct.pack("<L", ip.dst)))
                                # package.set_ip_src(socket.inet_ntoa(struct.pack("<L", ip.src)))
                                yield package
                        except ParseException:
                            continue
        else:
            raise WrongFileFormatException(filename)

def _iter(filename):
    pcap_num = 0
    with open(filename) as f:
        pcap = dpkt.pcap.Reader(f)
        if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
            for ts, buf in pcap:
                # setattr(buf, "pcap_num", pcap_num)
                yield buf
                pcap_num += 1

def _get_packages(buf):
    sll = dpkt.sll.SLL(buf)
    ip = sll.data
    packages = []
    if type(ip.data) != TCP and type(ip.data) != UDP:
        return packages
    if ip.data.data:
        package_type = determine_package_type(ip.data.data)
        if package_type:
            try:
                for package in package_type.parse(ip.data.data):
                    package.set_pcap_package(sll)
                    # package.set_pcap_num(buf.pcap_num)
                    package.set_ip_dst(socket.inet_ntoa(ip.dst))
                    package.set_ip_src(socket.inet_ntoa(ip.src))

                    # socket.inet_ntoa(struct.unpack("<L", ip.dst))
                    #package.set_ip_dst(socket.inet_ntoa(struct.pack("<L", ip.dst)))
                    # package.set_ip_src(socket.inet_ntoa(struct.pack("<L", ip.src)))
                    packages.append(package)
            except ParseException:
                return packages
    return packages

def get_packages_async_2(filename):
    """
    Parse packages from filename.
    :param filename:
    :return: Iterator with packages
    """
        #else:
        #    raise WrongFileFormatException(filename)

    pool = Pool(processes=cpu_count() + 2)
    num = 0
    # print pool.map(_get_packages, [buf for buf in _iter(filename)])
    for packages in pool.map(_get_packages, [buf for buf in _iter(filename)]):
        if packages:
            for package in packages:
                package.set_num(num)
                num += 1
                yield package

