# -*- coding:utf-8 -*-
import re
from idmhound.graph.legacy_nodes import *
from idmhound.graph.nodes import *


class Edges():
    """Represent an edge or a group of edges, abstract class."""

    def __init__(self, starts: list[str], ends: list[str], kinds: list[str], ipaUniqueID: str | None):
        self.ipaUniqueID = str(ipaUniqueID)
        self.starts_dn = [str(start) for start in starts]
        self.ends_dn = [str(end) for end in ends]
        self.kinds = [str(kind) for kind in kinds]
        self.desc = ""
        self.ends = []
        self.starts = []

    def set_desc(self, desc: str):
        """Set the description attribute of the edge.
        :param desc: description to set."""

        self.desc = str(desc)

    def resolve_member_dn(self, accounts: list[Node]):
        """Build the list of start and end nodes ipaUniqueID based on the DN of the nodes.
        :param accounts: list of accounts to use to convert the DN to ipaUniqueID."""

        for account in accounts:
            if account.get_dn() in self.ends_dn or (
                    "all" in self.ends_dn and isinstance(account, (LegacyComputer, Computer))):
                self.ends.append(account.get_id())
            if account.get_dn() in self.starts_dn or (
                    "all" in self.starts_dn and isinstance(account, (LegacyUser, User))):
                self.starts.append(account.get_id())


class HBAC(Edges):
    """Represent a Host-Based Access Control entry."""

    def __init__(self, starts: list[str], ends: list[str], services: list[str], ipaUniqueID: str):

        super().__init__(starts, ends, services, ipaUniqueID)

    def to_json(self) -> list:
        """Convert an HBAC entry to a list of edges as a dictionary (JSON) representation.
        :return: edges as a list of dictionary."""

        edges = []
        for kind in self.kinds:
            for start in self.starts:
                for end in self.ends:
                    edges.append({"kind": f"HBAC_{kind}", "start": {"value": start, "match_by": "id"},
                                  "end": {"value": end, "match_by": "id"}})
        return edges

    def resolve_member_dn(self, accounts: list[Node]):
        """Build the list of start and end nodes ipaUniqueID based on the DN of the nodes.
        :param accounts: list of accounts to use to convert the DN to ipaUniqueID."""

        services = []
        for account in accounts:
            if account.get_dn() in self.ends_dn or (
                    "all" in self.ends_dn and isinstance(account, (LegacyComputer, Computer))):
                self.ends.append(account.get_id())
            if account.get_dn() in self.starts_dn or (
                    "all" in self.starts_dn and isinstance(account, (LegacyUser, User))):
                self.starts.append(account.get_id())
            if account.get_dn() in self.kinds and not "all" in self.kinds:
                if isinstance(account, HBACService):
                    services.append(account.get_cn())
                elif isinstance(account, HBACServicesGroup):
                    services.extend(account.member)
        if not "all" in self.kinds:
            self.kinds = services

class Sudoer(Edges):
    """Represent a sudoer rights entry."""

    def __init__(self, starts: list[str], ends: list[str], commands: list[str], asusers: list[str], ipaUniqueID: str):

        super().__init__(starts, ends, commands, ipaUniqueID)
        self.asusers_dn = asusers
        self.asusers = []


    def resolve_member_dn(self, accounts: list):
        """Build the list of start and end nodes ipaUniqueID based on the DN of the nodes.
        :param accounts: list of accounts to use to convert the DN to ipaUniqueID."""

        services = []
        for account in accounts:
            if account.get_dn() in self.ends_dn or (
                    "all" in self.ends_dn and isinstance(account, (LegacyComputer, Computer))):
                self.ends.append(account.get_id())
            if account.get_dn() in self.starts_dn or (
                    "all" in self.starts_dn and isinstance(account, (LegacyUser, User))):
                self.starts.append(account.get_id())
            if account.get_dn() in self.kinds and not "all" in self.kinds:
                if isinstance(account, SudoCmd):
                    services.append(account.get_cn())
                elif isinstance(account, SudoCmdGroup):
                    services.extend(account.member)
            if account.get_dn() in self.asusers_dn and isinstance(account, (LegacyUser, User, LegacyGroup, Group)) and not "all" in self.asusers:
                self.asusers.append(account.get_cn())


        if "all" in self.asusers_dn:
            self.asusers = self.asusers_dn
        if not "all" in self.kinds:
            self.kinds = services


    def to_json(self) -> list:
        """Convert a sudoer entry to a list of edges as a dictionary (JSON) representation.
        :return: edges as a list of dictionary."""

        edges = []
        for kind in self.kinds:
            for start in self.starts:
                for end in self.ends:
                    for asuser in self.asusers:
                        edges.append({"kind": f"Sudoer_{kind}_as_{asuser}", "start": {"value": start, "match_by": "id"},
                                      "end": {"value": end, "match_by": "id"}})
        return edges

class Membership(Edges):
    """Represent a membership in a group entry."""

    def __init__(self, starts: list[str], ends: list[str]):

        super().__init__(starts, ends, ["MemberOf"], None)

    def to_json(self) -> list:
        """Convert a membership entry to a list of edges as a dictionary (JSON) representation.
        :return: edges as a list of dictionary."""

        edges = []
        for start in self.starts:
            for end in self.ends:
                edges.append({"kind": f"MemberOf", "start": {"value": start, "match_by": "id"},
                              "end": {"value": end, "match_by": "id"}})
        return edges

class IpaRight(Edges):
    """Represent rights on the IPA (ipaAllowedToPerform attributes)."""

    def __init__(self, starts: list[str], ends: list[str], kinds: list[str]):

        super().__init__(starts, ends, kinds, None)


    def to_json(self) -> list:
        """Convert rights on the IPA entry to a list of edges as a dictionary (JSON) representation.
        :return: edges as a list of dictionary."""

        edges = []
        for start in self.starts:
            for end in self.ends:
                for kind in self.kinds:
                    edges.append({"kind": kind, "start": {"value": start, "match_by": "id"},
                              "end": {"value": end, "match_by": "id"}})
        return edges