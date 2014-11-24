import socket
import struct
import dpkt
from dpkt import hexdump
from dpkt.tcp import TCP
from dpkt.udp import UDP
from dpkt.pcap import Writer
from memory_profiler import profile
from sipload.common.constants import SIP_METHODS
from sipload.exceptions import ParseException, WrongFileFormatException
from sipload.package import SipMessage, TptfMessage
from sipload.package import SipMessage
from sipload.package import TptfMessage
from multiprocessing import Process, Manager, Pool
from sipload.scenario.eli_call import get_eli_inbc_scen_from_call_start

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


def parse_calls_start_aync(buf, ts):
    sll = dpkt.sll.SLL(buf)
    ip = sll.data
    if type(ip.data) != TCP and type(ip.data) != UDP:
        return None
    calls = []
    if ip.data.data:
        package_type = determine_package_type(ip.data.data)
        if package_type:
            try:
                for package in package_type.parse(ip.data.data):
                    package.set_ts(ts)
                    # package.set_pcap_package(sll)
                    package.set_ip_dst(socket.inet_ntoa(ip.dst))
                    package.set_ip_src(socket.inet_ntoa(ip.src))

                    # socket.inet_ntoa(struct.unpack("<L", ip.dst))
                    #package.set_ip_dst(socket.inet_ntoa(struct.pack("<L", ip.dst)))
                    # package.set_ip_src(socket.inet_ntoa(struct.pack("<L", ip.src)))
                    call_start = get_eli_inbc_scen_from_call_start(package)
                    if call_start:
                        calls.append(call_start)
            except ParseException:
                return None
    return calls


def get_calls_start_async(filename):
    """
    Parse packages from filename.
    :param filename:
    :return: Iterator with packages
    """
    num = 0
    pcap_num = 0
    with open(filename) as f:
        pcap = dpkt.pcap.Reader(f)
        pool = Pool(processes=1)
        results = []
        if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
            for ts, buf in pcap:
                pcap_num += 1
                results.append(pool.apply_async(parse_calls_start_aync,
                                                args=(buf, ts)))
                del ts
                del buf
        reses = []
        [reses.extend(result.get()) for result in results if result.get()]
        del pcap
        del buf
        return reses
        # yield reses
        #for result in reses:
        #    yield result


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
            for ts, buf in pcap.__iter__():
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
                                # package.set_pcap_package(sll)
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


