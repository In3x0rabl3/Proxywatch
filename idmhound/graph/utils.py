# -*- coding:utf -*-

import re
import json
import logging
from datetime import datetime

logger = logging.getLogger()

def member_lookup(principals: list, subjects: list):
    """Convert the DN of an account to its SID for graphing.
    :param principals: principals to resolve the DN.
    :param subjects: subjects whose DN should be resolved."""

    for subject in subjects:
        subject.resolve_member_dn(principals)


def to_json(data: list, object_type) -> dict:
    """Convert objects to legacy JSON file format.
    :param data: list of objects to convert.
    :param object_type: type of the objects to convert.
    :return: legacy JSON containing the converted objects."""

    data = [entry.to_json() for entry in data]
    return {"data": data, "meta": {
        "methods": 0,
        "type": object_type,
        "count": len(data), "version": 5
    }}


def to_opengraph(nodes: list, edges: list) -> dict:
    """Convert objects to Opengraph file format.
    :param nodes: nodes to convert.
    :param edges: edges to convert.
    :return: Opengraph JSON containing the converted objects."""

    formatted_nodes = [node.to_json() for node in nodes]
    formatted_edges = []
    for edge in edges:
        formatted_edges.extend(edge.to_json())
    return {"metadata": {"source_kind": "IDMHound"}, "graph": {"nodes": formatted_nodes, "edges": formatted_edges}}


def to_opengraph_hbac(data: list) -> dict:
    """Convert HBAC to Opengraph file format.
    :param data: list of HBAC.
    :return: Opengraph JSON containing the converted HBAC."""

    opengraph = []
    for entry in data:
        opengraph.extend(entry.to_json())
    return {"graph": {"nodes": [], "edges": opengraph}}


def identify_realm_sid(data: list, realm: str) -> str:
    """Identify the SID of the realm.
    :param data: list of LDAP entry to parse.
    :param realm: name of the realm.
    :return: SID of the realm."""

    ldap_realm = "".join([",dc=" + dc for dc in realm.split(".")])
    for entry in data:
        if re.match(f"cn={realm},cn=ad,cn=etc{ldap_realm}", entry.entry_dn) and "ipaNTSecurityIdentifier" in entry.entry_attributes_as_dict.keys():
            sid = str(entry["ipaNTSecurityIdentifier"])
            return sid
        elif re.match(f"cn=Default SMB Group,cn=groups,cn=accounts{ldap_realm}", entry.entry_dn) and "ipaNTSecurityIdentifier" in entry.entry_attributes_as_dict.keys():
            logger.warning(f"Cannot reliably identify the domain SID. An LDAP anonymous bind was likely used. Graphable data will be limited.")
            sid = str(entry["ipaNTSecurityIdentifier"])
            sid = "-".join(sid.split("-")[:-1])
            return sid
    else:
        raise ValueError("Cannot identify realm SID.")


def legacy_save(domains, users, groups, computers, hbac, sudoer, iparights):
    """Save data in the legacy file format.
    :param domains: domains in legacy JSON format.
    :param users: users and services in legacy JSON format.
    :param groups: groups in legacy JSON format.
    :param computers: computers in legacy JSON format.
    :param hbac: HBAC in Opengraph format.
    :param sudoer: Sudoer in Opengraph format.
    :param iparights: IPA rights in Opengraph format."""

    now = datetime.now().strftime("%Y%m%d%H%M%S")
    logger.info(f"Saved domains to legacy file format: domains_{now}.json")
    logger.info(f"Saved users to legacy file format: users_{now}.json")
    logger.info(f"Saved groups to legacy file format: groups_{now}.json")
    logger.info(f"Saved computers to legacy file format: computers_{now}.json")
    logger.info(f"Saved HBAC to Opengraph file format: hbac_{now}.json")
    logger.info(f"Saved sudoer to Opengraph file format: sudoer_{now}.json")
    logger.info(f"Saved IPA rights to Opengraph file format: iparights_{now}.json")

    with open(f"domains_{now}.json", "w") as output:
        output.write(json.dumps(to_json(domains, "domains")))
    with open(f"users_{now}.json", "w") as output:
        output.write(json.dumps(to_json(users, "users")))
    with open(f"groups_{now}.json", "w") as output:
        output.write(json.dumps(to_json(groups, "groups")))
    with open(f"computers_{now}.json", "w") as output:
        output.write(json.dumps(to_json(computers, "computers")))
    with open(f"hbac_{now}.json", "w") as output:
        output.write(json.dumps(to_opengraph_hbac(hbac)))
    with open(f"sudoer_{now}.json", "w") as output:
        output.write(json.dumps(to_opengraph_hbac(sudoer)))
    with open(f"iparights_{now}.json", "w") as output:
        output.write(json.dumps(to_opengraph_hbac(iparights)))