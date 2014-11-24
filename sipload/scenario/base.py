from dpkt.pcap import Writer, DLT_LINUX_SLL
import os
from sipload.package import TptfMessage, SipMessage


class BaseScenario(object):
    def __init__(self, start_package):
        """
        Main call class. Must be separate class for each call logic
        :param start_package:
        :return:
        """
        self.packages = []
        self.packages_nums = []
        self.add_package(start_package)
        # get SDP session value from ELI CRED transaction
        self.sip_call_id = None
        self.session = None
        self.start_num = start_package.pcap_num

    def add_package(self, package):
        self.packages.append(package)
        self.packages_nums.append(package.num)
        # self.hash.update(package.gen_message)

    def gen_test(self):
        raise NotImplemented

    def _sort(self):
        self.packages = sorted(self.packages, key=lambda key: key.num)

    def save_pcap(self, dir_name):
        """
        Saves pcap file for given call
        pcap file name is first call pcap frame number
        """
        self._sort()
        file_name = "%s.pcap" % self.start_num
        full_name = os.path.join(dir_name, file_name)
        out_file = Writer(open(full_name, 'wb'), linktype=DLT_LINUX_SLL)
        for package in self.packages:
            out_file.writepkt(package.pcap_package, package.ts)
        out_file.close()

    def remove_duplicate_packages(self):
        """
        Remove duplicate packages from call
        """
        def is_not_duplicate(package):
            # remove all transaction with trans num == 0
            if type(package) == TptfMessage:
                if package.headers["transnumb"] == 0 \
                        and not package.headers["tofunc"] == "ASM?EXEC":
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
        # remove duplicates with same num
        new_packages_nums = []
        new_packages = []
        for package in self.packages:
            if type(package) == TptfMessage:
                if package.state == "Ack":
                    continue
            if package.num not in new_packages_nums:
                new_packages.append(package)
                new_packages_nums.append(package.num)
        self.packages = new_packages

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

    def __str__(self):
        out = "### Scenario start no #%s \n" % self.start_num
        for package in self.packages:
            out += str(package)
        out += "### end of Scenarion"
        return out

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
