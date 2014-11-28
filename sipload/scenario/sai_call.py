from collections import OrderedDict
import hashlib
import os
from dpkt.pcap import Writer, DLT_LINUX_SLL
from sipload.package import SipMessage
from sipload.package import TptfMessage
from sipload.scenario.base import BaseScenario

__author__ = 'slaviann'


class CredSaiScenario(BaseScenario):
    def __init__(self, opts, start_package):
        # get SDP session value from ELI CRED transaction
        super(CredSaiScenario, self).__init__(opts, start_package)
        self.sdp_session = start_package.get_fics_value_by_name("SDPOSID")
        self.eli_instance = start_package.headers["retfunc"][4:]
        self.first_trans_num = start_package.headers["transnumb"]

    @classmethod
    def is_call_start(cls, opts, package):
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
        return False

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
        #if not self.session:
        #    return False
        if self.sip_call_id:
            return False
        if type(package) == SipMessage and package.method == "INVITE":
            if package.body:
                if package.sdp_session == self.sdp_session:
                    self.sip_call_id = package.call_id
                    return True
        return False

    def is_call_package(self, package):
        """
        Check is package related to given call
        :param package: - TptfMessage or SipMessage
        :return: True if related
        """
        # get session
        if self._is_first_reply(package) or self._is_first_invite(package):
            return True
        # get sip_call_id
        #if self._is_first_invite(package):
        #    return True
        return self._is_call_package(package)

    @property
    def is_broken(self):
        """
        Slug
        """
        return False


class InviteSaiScenario(BaseScenario):
    def __init__(self, opts, start_package):
        super(InviteSaiScenario, self).__init__(opts, start_package)
        self.sip_call_id = start_package.call_id

    @classmethod
    def is_call_start(cls, opts, package):
        """
        Check is this package call start or no
        :param package:
        :return: True if package is call start
        """
        if type(package) == SipMessage and package.method == "INVITE" \
                and opts.config.get("main", "frontend.ip") in package.request_line:
                    return True

        return False

    def _is_first_exec(self, package):
        """
        Check is transaction is first exec after sip INVITE using SIP call id
        Get SAI generated session ID
        :param package: TptfMessage or SipMessage
        :return: True if yes
        """
        if self.session:
            return False
        if type(package) == TptfMessage:
            if package.headers["retfunc"].startswith("SAI"):
                if package.headers["tofunc"].startswith("ASM") and \
                        package.headers["tofunc"].endswith("EXEC"):
                    if package.state == "New":
                        if package.get_fics_value_by_name("CALL_ID") == self.sip_call_id:
                            self.session = package.get_fics_value_by_name("SESSION")
                            return True
        return False

    def is_call_package(self, package):
        """
        Check is package related to given call
        :param package: - TptfMessage or SipMessage
        :return: True if related
        """
        # get session
        if self._is_first_exec(package):
            return True
        return self._is_call_package(package)

    @property
    def is_broken(self):
        """
        Slug
        """
        return False
