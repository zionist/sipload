from collections import OrderedDict
import hashlib
from sipload.package import TptfMessage

__author__ = 'slaviann'

def sai_get_call_start(package):
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



class SaiCall:
    def __init__(self, start_package):
        """
        Start package must be package from sai_get_call_start function
        :param start_package:
        :return:
        """
        self.start_package = start_package
        # self.hash = hashlib.sha512()

    def add_packages(self, package):
        self.packages.append(package)
        # self.hash.update(package.gen_message)

    def set_rules(self, rules):
        """
        Rules for check packages iterator.
        Is package related to this call or no
        """
        self.rules = rules

    def gen_test(self):
        raise NotImplemented

    def save_pcap(self):
        raise NotImplemented

    @property
    def hash(self):
        return self.hash.hexdigest()

    def check_call(self, package):
        if self.check_rule(package):
            return True
        else:
            return False

    @classmethod
    def dsds(cls):
        pass

    def sai_package_related_to_call(self, package):
        """
        Check is package related to given call
        :param package: - TptfMessage or SipMessage
        :return: True if related
        """
        pass
        print "#"
        # print self.start_package




