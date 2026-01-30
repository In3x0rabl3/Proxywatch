# -*- coding:utf-8 -*-

class Node():
    """Represents an object of the realm, abstract class."""

    def __init__(self, dn: str, cn: str, ipaUniqueID: str, domainsid: str):
        self.dn = dn
        self.cn = str(cn)
        self.ipaUniqueID = str(ipaUniqueID)
        self.desc = ""
        self.domainsid = str(domainsid)

    def get_dn(self) -> str:
        """Returns the DN of the node.
        :return: DN of the node."""

        return self.dn

    def get_cn(self) -> str:
        """Returns the CN of the node.
        :return: CN of the node."""

        return self.cn

    def get_id(self) -> str:
        """Returns the ipaUniqueID of the node.
        :return: ipaUniqueID of the node."""

        return self.ipaUniqueID

    def set_desc(self, desc: str):
        """Set the description attribute of the edge.
        :param desc: description to set."""

        self.desc = str(desc)

class Domain(Node):
    """Represents a domain."""

    def __init__(self, dn: str, cn: str, ipaNTDomainGUID: str, ipaNTFlatName: str, domainsid: str):

        super().__init__(dn, cn, ipaNTDomainGUID, domainsid)
        self.ipaNTFlatName = str(ipaNTFlatName)

    def to_json(self) -> dict:
        """Convert a domain as a dictionary (JSON) representation.
        :return: edges as a list of dictionary."""

        return {"id": self.ipaUniqueID, "Properties": {"name": self.ipaNTFlatName,
                                                       "domain": self.cn,
                                                       "domainsid": self.domainsid,
                                                       "distinguishedname": self.dn,
                                                       "highvalue":True,
                                                       "description":self.desc
                                                       },
                "kinds": ["Domain"]}


class User(Node):
    "Represents a user."

    def __init__(self, dn: str, cn: str, gecos: str, homeDirectory: str, ipaUniqueID: str, krbCanonicalName: str, krbPrincipalName: str, loginShell: str, sn: str,
                 uid: str, uidNumber: str, domainsid: str):

        super().__init__(dn, cn, ipaUniqueID, domainsid)

        self.gecos = str(gecos)
        self.homeDirectory = str(homeDirectory)
        self.krbCanonicalName = str(krbCanonicalName)
        self.krbPrincipalName = str(krbPrincipalName)
        self.loginShell = str(loginShell)
        self.sn = str(sn)
        self.uid = str(uid)
        self.uidNumber = str(uidNumber)
        self.enabled = True


    def to_json(self) -> dict:
        """Convert a user as a dictionary (JSON) representation.
        :return: edges as a list of dictionary."""

        return {"id": self.ipaUniqueID,
                "properties": {"name": self.krbCanonicalName,
                               "distinguishedname": self.dn,
                               "cn": self.cn,
                               "domainsid":self.domainsid,
                               "gecos": self.gecos,
                               "enabled": self.enabled,
                               "homedirectory": self.homeDirectory,
                               "sn": self.sn,
                               "uid": self.uid,
                               "uidNumber": self.uidNumber,
                               "description": self.desc},
                "kinds": ["User"]}



class Computer(Node):
    """Represent a computer."""

    def __init__(self, dn: str, cn: str, ipaUniqueID: str, krbCanonicalName: str, krbPrincipalName: str, fqdn: str, domainsid: str):

        super().__init__(dn, cn, ipaUniqueID, domainsid)

        self.krbCanonicalName = str(krbCanonicalName)
        self.krbPrincipalName = str(krbPrincipalName)
        self.fqdn = str(fqdn)
        self.spn = []
        self.hasspn = False

    def to_json(self) -> dict:
        """Convert a computer as a dictionary (JSON) representation.
        :return: edges as a list of dictionary."""

        return {"id": self.ipaUniqueID,
                "properties": {"distinguishedname": self.dn,
                               "name": self.fqdn,
                               "description": self.desc,
                               "domainsid": self.domainsid,
                               "hasspn": self.hasspn,
                               "service krbprincipalname": "\n".join(self.spn)},
                "kinds": ["Computer"]}

    def set_spn(self, spn: str):
        """Add a service principal name to the computer.
        :param spn: service principal name to add."""

        self.hasspn = True
        self.spn.append(str(spn))

class Service(Node):
    """Represent a service."""

    def __init__(self, dn: str, cn: str, ipaUniqueID: str, krbPrincipalName: str, domainsid: str):

        super().__init__(dn, cn, ipaUniqueID, domainsid)

        self.krbPrincipalName = str(krbPrincipalName)
        self.hasspn = True

    def to_json(self) -> dict:
        """Convert a service as a dictionary (JSON) representation.
        :return: edges as a list of dictionary."""

        return {"id": self.ipaUniqueID,
                "properties": {"distinguishedname": self.dn,
                               "name": self.krbPrincipalName,
                               "description": self.desc,
                               "domainsid": self.domainsid,
                               "hasspn": self.hasspn},
                "kinds": ["User"]}



class Group(Node):
    """Represent a group."""

    def __init__(self, dn: str, cn: str, ipaUniqueID: str, member: list, domainsid: str):

        super().__init__(dn, cn, ipaUniqueID, domainsid)

        self.member_dn = list(member)
        self.member = []

    def resolve_member_dn(self, accounts: list[Node]):
        """Build the list of members ipaUniqueID based on the DN of the nodes.
        :param accounts: list of accounts to use to convert the DN to ipaUniqueID."""

        for account in accounts:
            if isinstance(account, (User,Computer)) and account.get_dn() in self.member_dn:
                self.member.append(account.get_id())


    def to_json(self) -> dict:
        """Convert a group as a dictionary (JSON) representation.
        :return: edges as a list of dictionary."""

        return {"id": self.ipaUniqueID,
                "Properties": {"distinguishedname": self.dn,
                               "name": self.cn,
                               "description": self.desc,
                               "domainsid": self.domainsid},
                "kinds": ["Group"]}

class HBACService(Node):
    """Represents an HBACService."""

    def __init__(self, dn: str, cn: str, ipaUniqueID:str, domainsid:str):

        cn = str(cn).replace("-", "")
        super().__init__(dn, cn, ipaUniqueID, domainsid)

class HBACServicesGroup(Node):
    """Represents an HBACServicesGroup."""

    def __init__(self, dn: str, cn: str, ipaUniqueID: str, member: list, domainsid: str):

        super().__init__(dn, cn, ipaUniqueID, domainsid)

        self.member_dn = list(member)
        self.member = []

    def resolve_member_dn(self, accounts: list[Node]):
        """Build the list of members ipaUniqueID based on the DN of the nodes.
        :param accounts: list of accounts to use to convert the DN to ipaUniqueID."""

        for account in accounts:
            if isinstance(account, (HBACService)) and account.get_dn() in self.member_dn:
                self.member.append(account.get_cn())

class SudoCmd(Node):
    """Represents an SudoCmd."""

    def __init__(self, dn: str, cn: str, ipaUniqueID:str, domainsid:str):

        cn = str(cn).replace("-", "")
        super().__init__(dn, cn, ipaUniqueID, domainsid)
class SudoCmdGroup(Node):
    """Represent a group of sudo commands."""

    def __init__(self, dn: str, cn:str, ipaUniqueID: str, member: list, domainsid: str):

        super().__init__(dn, cn, ipaUniqueID, domainsid)
        self.member_dn = list(member)
        self.member = []

    def resolve_member_dn(self, accounts: list[Node]):
        """Build the list of members ipaUniqueID based on the DN of the nodes.
        :param accounts: list of accounts to use to convert the DN to ipaUniqueID."""

        for account in accounts:
            if isinstance(account, (SudoCmd)) and account.get_dn() in self.member_dn:
                self.member.append(account.get_cn())

if __name__ == "__main__":
    pass