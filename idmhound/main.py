# -*- coding:utf -*-

import json
from idmhound.graph.utils import *
from idmhound.collectors import ldap
import argparse
import logging
import sys
from datetime import datetime


def main():

    parser = argparse.ArgumentParser(add_help=True, description="Bloodhound collector for FreeIPA/Red Hat IdM environment.")
    parser.add_argument("-d", "--domain", action="store", required=True, help="Domain / realm to query.")
    parser.add_argument("-u", "--username", action="store", default="", help="Username to query the realm.")
    parser.add_argument("-p", "--password", action="store", default="", help="Password of the account to query the realm.")
    parser.add_argument("-dc", "--domain-controller", action="store", required=True, help="Server to query.")
    parser.add_argument("-dn", "--base-dn", action="store", default="", help="Base DN to query.")
    parser.add_argument("-l", "--legacy", action="store_true", default=False, help="Output the file in the legacy Bloodhound format.")
    parser.add_argument("-k", "--kerberos", action="store_true", default=False, help="Use kerberos authentication.")
    args = parser.parse_args()

    logging.basicConfig(stream=sys.stdout, encoding="utf-8", filemode="w", level=logging.INFO,
                        format="{asctime} - {levelname}: {message}", style="{", datefmt="%d-%m-%Y %H:%M:%S")
    logger = logging.getLogger()

    logger.info(f"Getting LDAP data of {args.domain}...")
    ldap_realm = "".join([",dc=" + dc for dc in args.domain.split(".")])
    bind_dn = f"uid={args.username},cn=users,cn=accounts{ldap_realm}"
    data = ldap.collect(args.domain_controller, args.base_dn, bind_dn, args.password, args.kerberos)
    logger.info(f"Found {len(data)} LDAP entries.")
    sid = identify_realm_sid(data, args.domain)
    logger.info(f"Realm SID: {sid}")

    logger.info("Parsing LDAP data...")
    if args.legacy:
        domains, users, services, groups, computers, hbac, sudoer, hbacservicesgroups, hbacservices, sudocmdgroups, sudocmds, iparights = ldap.legacy_parse(data, args.domain, sid)
        member_lookup(users + computers + services + groups, groups)
        member_lookup(hbacservices, hbacservicesgroups)
        member_lookup(users + computers + groups +hbacservices + hbacservicesgroups, hbac)
        member_lookup(sudocmds, sudocmdgroups)
        member_lookup(users + computers + groups + sudocmds + sudocmdgroups, sudoer)
        member_lookup(users + computers + services + groups, iparights)
        logger.info("Save output to legacy JSON file format.")
        legacy_save(domains, users+services, groups, computers, hbac, sudoer, iparights)
    else:
        domains, users, services, groups, computers, hbac, sudoer, membership, hbacservicesgroups, hbacservices, sudocmdgroups, sudocmds, iparights = ldap.parse(data, args.domain, sid)
        member_lookup(users + computers + services + groups, membership)
        member_lookup(hbacservices, hbacservicesgroups)
        member_lookup(users + computers + groups + hbacservices + hbacservicesgroups, hbac)
        member_lookup(sudocmds, sudocmdgroups)
        member_lookup(users + computers + groups + sudocmds + sudocmdgroups, sudoer)
        member_lookup(users + computers + services + groups, iparights)
        now = datetime.now().strftime("%Y%m%d%H%M%S")
        logger.info(f"Save output to Opengraph file format: idmhound_{now}.json")

        with open(f"idmhound_{now}.json","w") as output:
            output.write(json.dumps(to_opengraph(domains+users+groups+computers+services, hbac+membership+sudoer+iparights)))






if __name__ == "__main__":
    main()

