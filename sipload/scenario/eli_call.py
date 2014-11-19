from sipload.package import SipMessage, TptfMessage
from sipload.scenario.base import BaseScenario

__author__ = 'slaviann'


class InviteEliScenario(BaseScenario):
    def __init__(self, opts, start_package):
        super(InviteEliScenario, self).__init__(opts, start_package)
        self.sipsessid = None
        self.li_sessid = None
        self.session = None
        self.eli_instances = []
        self.sip_call_id = start_package.get_fics_value_by_name("CALL_ID")

    @classmethod
    def is_call_start(cls, opts, package):
        """
        Check is this package call start or no
        :param package:
        :return: True if package is call start
        """
        if type(package) == TptfMessage:
            if package.headers["transnumb"] == 0:
                if package.headers["tofunc"].startswith("ELI") and \
                        package.headers["tofunc"].endswith("INBC"):
                    if package.state == "New":
                        return True
        return False

    def _is_first_exec(self, package):
        """
        Check is transaction is first exec after sip INVITE using SIP call id
        Get SAI generated session ID
        :param package: TptfMessage or SipMessage
        :return: True if yes
        """
        if package.pcap_num == 254 or package.pcap_num == 244:
            pass
        if type(package) == TptfMessage:
            if package.headers["tofunc"].startswith("ASM") and \
                    package.headers["tofunc"].endswith("EXEC"):
                if package.headers["retfunc"].startswith("ELI"):
                    if self.sip_call_id == package.get_fics_value_by_name("CALL_ID"):
                        self.sipsessid = package.get_fics_value_by_name("SIPSESSID")
                        self.li_sessid = package.get_fics_value_by_name("LI_SESSID")
                        self.session = package.get_fics_value_by_name("SESSION")
                        return True
        return False

    def _is_call_package(self, package):
        """
        Check is package related to given call
        :param package: - TptfMessage or SipMessage
        :return: True if related
        """
        if self.sip_call_id and self.sip_call_id == package.get_fics_value_by_name("CALL_ID"):
            return True
        if self.sipsessid:
            if self.sipsessid == package.get_fics_value_by_name("SIPSESSID"):
                return True
            if package.get_fics_value_by_name("SESSION"):
                if package.get_fics_value_by_name("SESSION") == self.session:
                    return True
                if package.headers["tofunc"].startswith("SAI"):
                    if len(self.sipsessid.split("/")) == 2:
                        if package.get_fics_value_by_name("SESSION") == self.sipsessid.split("/")[0]:
                            return True
                    else:
                        if self.sipsessid == package.get_fics_value_by_name("SESSION"):
                            return True
        if self.li_sessid:
            if self.li_sessid == package.get_fics_value_by_name("LI_SESSID"):
                return True
            if package.headers["tofunc"].startswith("MLI") or package.headers["tofunc"].startswith("_LI"):
                if self.li_sessid == package.get_fics_value_by_name("SESSION"):
                    return True
        if self.session and self.session == package.get_fics_value_by_name("SESSION"):
            return True

    def is_call_package(self, package):
        # get session
        if not type(package) == TptfMessage:
            return False
        if self._is_first_exec(package):
            return True
        if self._is_call_package(package):
            # get ELI instance
            if package.headers["retfunc"].startswith("ELI"):
                instance = package.headers["retfunc"][-4:]
                if instance not in self.eli_instances:
                    self.eli_instances.append(instance)
            return True
        # get all transcation for instance
        for instance in self.eli_instances:
            if package.headers["retfunc"].startswith("ELI"):
                if package.headers["retfunc"][-4:] == instance:
                    return True
        return False

    def remove_duplicate_packages(self):
        super(InviteEliScenario, self).remove_duplicate_packages()
        packages = []
        for package in self.packages:
            if package.headers["retfunc"].startswith("ELI") \
                    or package.headers["tofunc"].startswith("ELI"):
                if not package.headers["tofunc"].startswith("ASM?"):
                    packages.append(package)
        self.packages = packages
