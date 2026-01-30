# -*- coding:utf-8 -*-

class LegacyNode():
    """Represents an object of the realm, abstract class."""

    def __init__(self, dn: str, cn: str, ipaUniqueID: str, ipaNTSecurityIdentifier: str, domainsid: str):
        self.dn = dn
        self.cn = str(cn)
        self.ipaUniqueID = str(ipaUniqueID)
        self.ipaNTSecurityIdentifier = str(ipaNTSecurityIdentifier)
        self.desc = ""
        self.acl = []
        self.domainsid = str(domainsid)


    def get_dn(self) -> str:
        """Returns the DN of the node.
        :return: DN of the node."""

        return self.dn

    def get_cn(self) -> str:
        """Returns the DN of the node.
        :return: DN of the node."""

        return self.cn

    def get_id(self) -> str:
        """Returns the ipaUniqueID of the node.
        :return: ipaUniqueID of the node."""

        return self.ipaNTSecurityIdentifier

    def set_desc(self, desc: str):
        """Set the description attribute of the edge.
        :param desc: description to set."""

        self.desc = str(desc)


class LegacyDomain(LegacyNode):
    """Represents a domain."""

    def __init__(self, dn: str, cn: str, ipaNTDomainGUID: str, ipaNTFlatName: str, ipaNTSecurityIdentifier: str, domainsid: str):

        super().__init__(dn, cn, ipaNTDomainGUID, ipaNTSecurityIdentifier, domainsid)
        self.ipaNTFlatName = str(ipaNTFlatName)

    def to_json(self) -> dict:
        """Convert a domain as a dictionary (JSON) representation.
        :return: edges as a list of dictionary."""

        return {"ObjectIdentifier": self.ipaNTSecurityIdentifier,
                "Properties": {"name": self.ipaNTFlatName,
                               "domain": self.cn,
                               "domainsid": self.domainsid,
                               "distinguishedname": self.dn,
                               "highvalue":True,
                               "description":self.desc},
                "Aces": self.acl}


class LegacyUser(LegacyNode):
    "Represents a user."

    def __init__(self, dn: str, cn: str, gecos: str, homeDirectory: str, ipaUniqueID: str, ipaNTSecurityIdentifier: str, krbCanonicalName: str, krbPrincipalName: str, loginShell: str, sn: str,
                 uid: str, uidNumber: str, domainsid: str):

        super().__init__(dn, cn, ipaUniqueID, ipaNTSecurityIdentifier, domainsid)

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

        return {"ObjectIdentifier": self.ipaNTSecurityIdentifier,
                "Properties": {"name": self.krbCanonicalName,
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
                "Aces": self.acl}



class LegacyComputer(LegacyNode):
    """Represent a computer."""

    def __init__(self, dn: str, cn: str, ipaUniqueID: str, ipaNTSecurityIdentifier: str, krbCanonicalName: str, krbPrincipalName: str, fqdn: str, domainsid: str):
        super().__init__(dn, cn, ipaUniqueID, ipaNTSecurityIdentifier, domainsid)

        self.krbCanonicalName = str(krbCanonicalName)
        self.krbPrincipalName = str(krbPrincipalName)
        self.fqdn = str(fqdn)
        self.spn = []
        self.hasspn = False

    def to_json(self) -> dict:
        """Convert a computer as a dictionary (JSON) representation.
        :return: edges as a list of dictionary."""

        return {"ObjectIdentifier": self.ipaNTSecurityIdentifier,
                "Properties": {"distinguishedname": self.dn,
                               "name": self.fqdn,
                               "description": self.desc,
                               "domainsid": self.domainsid,
                               "hasspn": self.hasspn,
                               "serviceprincipalnames": "\n".join(self.spn)},
                "Aces": self.acl}

    def set_spn(self, spn):
        """Add a service principal name to the computer.
        :param spn: service principal name to add."""

        self.hasspn = True
        self.spn.append(str(spn))

class LegacyService(LegacyNode):
    """Represent a service."""

    def __init__(self, dn: str, cn: str, ipaUniqueID: str, ipaNTSecurityIdentifier: str, krbPrincipalName: str, domainsid: str):
        super().__init__(dn, cn, ipaUniqueID, ipaNTSecurityIdentifier, domainsid)

        self.krbPrincipalName = str(krbPrincipalName)
        self.hasspn = True

    def to_json(self) -> dict:
        """Convert a computer as a dictionary (JSON) representation.
        :return: edges as a list of dictionary."""

        return {"ObjectIdentifier": self.ipaNTSecurityIdentifier,
                "Properties": {"distinguishedname": self.dn,
                               "name": self.krbPrincipalName,
                               "description": self.desc,
                               "domainsid": self.domainsid,
                               "hasspn": self.hasspn},
                "Aces": self.acl}
class LegacyGroup(LegacyNode):
    """Represent a group."""

    def __init__(self, dn: str, cn: str, ipaUniqueID: str, ipaNTSecurityIdentifier: str, member: list, domainsid: str):

        super().__init__(dn, cn, ipaUniqueID, ipaNTSecurityIdentifier, domainsid)

        self.member_dn = list(member)
        self.member = []

    def resolve_member_dn(self, accounts: list[LegacyNode]):
        """Build the list of members ipaUniqueID based on the DN of the nodes.
        :param accounts: list of accounts to use to convert the DN to ipaUniqueID."""

        for account in accounts:
            if isinstance(account, LegacyUser) and account.get_dn() in self.member_dn:
                self.member.append({"ObjectIdentifier": account.get_id(), "ObjectType": "User"})
            elif isinstance(account, LegacyComputer) and account.get_dn() in self.member_dn:
                self.member.append({"ObjectIdentifier": account.get_id(), "ObjectType": "Computer"})
            elif isinstance(account, LegacyGroup) and account.get_dn() in self.member_dn:
                self.member.append({"ObjectIdentifier": account.get_id(), "ObjectType": "Group"})

    def to_json(self) -> dict:
        """Convert a group as a dictionary (JSON) representation.
        :return: edges as a list of dictionary."""

        return {"ObjectIdentifier": self.ipaNTSecurityIdentifier,
                "Properties": {"distinguishedname": self.dn,
                               "name": self.cn,
                               "description": self.desc,
                               "domainsid":self.domainsid},
                "Members": self.member,
                "Aces": self.acl}


if __name__ == "__main__":
    pass