from collections import OrderedDict
import hashlib
from sipload.package import SipMessage
from sipload.package import TptfMessage

__author__ = 'slaviann'



class SaiCall:
    def __init__(self, start_package):
        """
        Main call class. Must be separate class for each call logic
        :param start_package:
        :return:
        """
        self.packages = []
        self.add_package(start_package)
        # get SDP session value from ELI CRED transaction
        self.sdp_session = start_package.get_fics_value_by_name("SDPOSID")
        self.sip_call_id = None
        self.session = None
        self.eli_instance = start_package.headers["retfunc"][4:]
        self.first_trans_num = start_package.headers["transnumb"]
        self.start_num = start_package.num
        # self.hash = hashlib.sha512()

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
            if package.headers["retfunc"].startswith("ELI"):
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
        raise NotImplemented

    @property
    def hash(self):
        return self.hash.hexdigest()

    def is_first_reply(self, package):
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

    def is_first_invite(self, package):
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
        if self.is_first_reply(package):
            return True
        # get sip_call_id
        if self.is_first_invite(package):
            return True
        return self._is_call_package(package)



