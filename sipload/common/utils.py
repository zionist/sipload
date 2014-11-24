import pickle
import socket
import struct
import dpkt
import gc
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
from multiprocessing import Process, Manager, Pool, Lock, cpu_count, Queue

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

def parse_packages_aync(buf, ts, queue, pcap_num):
    sll = dpkt.sll.SLL(buf)
    ip = sll.data
    if type(ip.data) != TCP and type(ip.data) != UDP:
        return None
    if ip.data.data:
        package_type = determine_package_type(ip.data.data)
        if package_type:
            try:
                for package in package_type.parse(ip.data.data):
                    package.set_pcap_num(pcap_num)
                    package.set_ts(ts)
                    package.set_pcap_package(sll)
                    package.set_ip_dst(socket.inet_ntoa(ip.dst))
                    package.set_ip_src(socket.inet_ntoa(ip.src))

                    # socket.inet_ntoa(struct.unpack("<L", ip.dst))
                    #package.set_ip_dst(socket.inet_ntoa(struct.pack("<L", ip.dst)))
                    # package.set_ip_src(socket.inet_ntoa(struct.pack("<L", ip.src)))
                    # packages.append(package)
                    #lock.acquire()
                    #lock.release()
                    queue.put(package)
            except ParseException:
                return None
    del ip
    del sll
    del buf
    del ts
    return None

def get_packages_async(filename):
    pcap_num = 0
    f = open(filename)
    manager = Manager()
    queue = manager.Queue()
    lock = manager.Lock()
    pcap = dpkt.pcap.Reader(f)
    pool = Pool(processes=cpu_count() + 2)
    results = []
    if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
        for ts, buf in pcap:
            pcap_num += 1
            results.append(pool.apply_async(parse_packages_aync,
                                            args=(buf, ts, queue, pcap_num)))
            del ts
            del buf
    #pickle_file = open("/tmp/pickle", 'wb')
    while True:
        if queue.empty():
            break
        yield queue.get()
        # pickle.dump(queue.get(), pickle_file, -1)
    #pickle_file.close()
    #reses = []
    #[reses.extend(result.get()) for result in results if result.get()]
    #del pcap
    #f.close()
    #return reses


