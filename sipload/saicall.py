from collections import OrderedDict
import hashlib
import os
from dpkt.pcap import Writer, DLT_LINUX_SLL
from sipload.package import SipMessage
from sipload.package import TptfMessage

__author__ = 'slaviann'



class SaiCall:
    def __init__(self, opts, start_package):
        """
        Main call class. Must be separate class for each call logic
        :param start_package:
        :return:
        """
        self.asm_exec_start = None
        self.packages = []
        self.opts = opts
        self.add_package(start_package)
        # get SDP session value from ELI CRED transaction
        self.sdp_session = start_package.get_fics_value_by_name("SDPOSID")
        self.sip_call_id = None
        self.session = None
        self.eli_instance = start_package.headers["retfunc"][4:]
        self.first_trans_num = start_package.headers["transnumb"]
        self.start_num = start_package.num

    def __str__(self):
        out = "### SAI Call start no #%s \n" % self.start_num
        for package in self.packages:
            out += str(package)
        out += "### end of SAI Call"
        return out

    @classmethod
    def is_call_start(cls, package):
        """
        Check is this package call start or no
        :param package:
        :return: True if package is call start
        """
        if type(package) == TptfMessage and package.state == "New":
            #if package.headers["retfunc"].startswith("ELI"):
            if package.headers["tofunc"].startswith("SAI"):
                if package.headers["tofunc"].endswith("CRED"):
                    if "SESSION" not in [fics.name for fics in package.ficses]:
                        return True

                            #if package.headers["retfunc"].startswith("SAI"):
                            #    if package.headers["tofunc"].startswith("ASM"):
                            #        if package.headers["tofunc"].endswith("EXEC"):
                            #            return True
        return False

    def add_package(self, package):
        self.packages.append(package)
        # self.hash.update(package.gen_message)

    def gen_test(self):
        raise NotImplemented

    def save_pcap(self):
        """
        Saves pcap file for given call
        pcap file name is first call pcap frame number
        """
        file_name = "%s.pcap" % self.start_num
        full_name = os.path.join(self.opts.outdir, file_name)
        out_file = Writer(open(full_name, 'wb'), linktype=DLT_LINUX_SLL)
        for package in self.packages:
            out_file.writepkt(package.pcap_package, package.ts)
        out_file.close()


    def _is_first_reply(self, package):
        """
        Check is transaction is first reply against SAI CRED transaction
        Get SAI generated session ID
        :param package: TptfMessage or SipMessage
        :return: True if yes
        """
        if self.session:
            return False
        if type(package) == TptfMessage:
            if package.headers["retfunc"][4:] == self.eli_instance:
                if package.headers["transnumb"] == self.first_trans_num:
                    if package.headers["retfunc"].startswith("ELI"):
                        if package.headers["tofunc"].startswith("SAI"):
                            if package.headers["tofunc"].endswith("CRED"):
                                self.session = package.get_fics_value_by_name("SESSION")
                                return True
        return False

    def _is_first_invite(self, package):
        """
        Check is package is SipMessage and is first INVITE with sdp
        and sdp session from first reply against CRED
        Get Sip Call id for all legs
        :param package: - TptfMessage or SipMessage
        :return: True if related
        """
        # get first sip message with SDP
        if not self.session:
            return False
        if self.sip_call_id:
            return False
        if type(package) == SipMessage and package.method == "INVITE":
            if package.body:
                if package.sdp_session == self.sdp_session:
                    self.sip_call_id = package.call_id
                    return True
        return False

    def _is_call_package(self, package):
        if type(package) == SipMessage:
            if package.call_id == self.sip_call_id:
                return True
        if type(package) == TptfMessage:
            #if package.headers["retfunc"].endswith(self.eli_instance):
            #    return True
            if package.get_fics_value_by_name("SESSION"):
                if package.get_fics_value_by_name("SESSION") == self.session:
                    # print package.num
                    return True
        return False

    def is_call_package(self, package):
        """
        Check is package related to given call
        :param package: - TptfMessage or SipMessage
        :return: True if related
        """
        # get session
        if self._is_first_reply(package):
            return True
        # get sip_call_id
        if self._is_first_invite(package):
            return True
        return self._is_call_package(package)

    def remove_duplicate_packages(self):
        """
        Remove duplicate packages from call
        """
        def is_not_duplicate(package):
            # remove all transaction with trans num == 0
            if type(package) == TptfMessage:
                if package.headers["transnumb"] == 0:
                    return False
                for pack in self.packages:
                    if type(pack) == TptfMessage:
                        if package.num == pack.num:
                            return True
                        if package.headers["transnumb"] == pack.headers["transnumb"]:
                            if package.headers["tofunc"] == pack.headers["tofunc"]:
                                if package.headers["retfunc"] == pack.headers["retfunc"]:
                                    if package.headers["flags"] == pack.headers["flags"]:
                                        return False
            return True
        self.packages = filter(is_not_duplicate, self.packages)


    def compare(self, other):
        def is_tptf(package):
            if type(package) == TptfMessage:
                return True
            return False
        def is_sip(package):
            if type(package) == SipMessage:
                return True
            return False

        if len(self.packages) != len(other.packages):
            return False

        tptf_packages = filter(is_tptf, self.packages)
        other_tptf_packages = filter(is_tptf, other.packages)
        if len(tptf_packages) != len(other_tptf_packages):
            return False
        for idx in range(len(tptf_packages)):
            if not tptf_packages[idx].compare(other_tptf_packages[idx]):
                return False

        sip_packages = filter(is_sip, self.packages)
        other_sip_packages = filter(is_sip, other.packages)
        if len(sip_packages) != len(other_sip_packages):
            return False
        for idx in range(len(sip_packages)):
            if not sip_packages[idx].compare(other_sip_packages[idx]):
                return False

        return True


    def remove_duplicate_calls(self, calls):
        """
        Remove all duplicate calls
        :param calls: list of SaiCall objects
        """
        def get_duplicates(call):
            if call.start_num == self.start_num:
                return False
            return self.compare(call)
        calls_for_remove = filter(get_duplicates, calls)
        for call_for_remove in calls_for_remove:
            if call_for_remove in calls:
                calls.remove(call_for_remove)















