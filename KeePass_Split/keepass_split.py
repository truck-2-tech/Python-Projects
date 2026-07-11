#!/usr/bin/env python3
"""
Rebuilds two one-liners you'd otherwise run by hand on every box:

  netexec smb <target> -u <user> -p '<pass>' --users \
      | grep -vF -e '[' -e '-Username-' | awk '{print $5}'

  keepassxc.cli export --format csv <db.kdbx> | cut -d'"' -f8

into a single script. Point it at a saved copy of each command's raw
output and it writes users.txt and passwords.txt in the current
directory, same as running the pipelines yourself.

Usage:
    python3 kp_split.py --nxc nxc_users_raw.txt --keepass keepass_export_raw.csv

Either flag can be omitted if you only have one side of the data,
in which case only the corresponding output file is written.

Getting the raw input files:
    netexec smb puppy.htb -u levi.james -p 'KingofAkron2025!' --users > nxc_users_raw.txt
    keepassxc.cli export --format csv recovery.kdbx > keepass_export_raw.csv
    (keepassxc.cli will still prompt for the vault password interactively
    when run this way, that's expected)
"""

import argparse
import os
import sys


def parse_nxc_users(path):
    """
    Mirrors: grep -vF -e '[' -e '-Username-' | awk '{print $5}'
    """
    users = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "[" in line or "-Username-" in line:
                continue
            fields = line.split()
            if len(fields) >= 5:
                users.append(fields[4])
    return users


def parse_keepass_passwords(path):
    """
    Mirrors: cut -d'"' -f8
    CSV columns are Group,Title,Username,Password,... so splitting on
    the literal double-quote character and taking the 8th field lands
    on Password, same as the shell one-liner. The literal header value
    "Password" is skipped so it doesn't end up in the wordlist.
    """
    passwords = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            fields = line.split('"')
            if len(fields) >= 8:
                value = fields[7]
                if value and value != "Password":
                    passwords.append(value)
    return passwords


def main():
    parser = argparse.ArgumentParser(description="Extract users.txt and passwords.txt from nxc and keepassxc output")
    parser.add_argument("--nxc", help="path to raw netexec --users output")
    parser.add_argument("--keepass", help="path to raw keepassxc-cli CSV export")
    args = parser.parse_args()

    if not args.nxc and not args.keepass:
        parser.print_help()
        sys.exit(1)

    if args.nxc:
        if not os.path.isfile(args.nxc):
            print(f"[!] File not found: {args.nxc}")
            sys.exit(1)
        users = parse_nxc_users(args.nxc)
        with open("users.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(users) + "\n")
        print(f"[+] Wrote {len(users)} usernames to users.txt")

    if args.keepass:
        if not os.path.isfile(args.keepass):
            print(f"[!] File not found: {args.keepass}")
            sys.exit(1)
        passwords = parse_keepass_passwords(args.keepass)
        with open("passwords.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(passwords) + "\n")
        print(f"[+] Wrote {len(passwords)} passwords to passwords.txt")


if __name__ == "__main__":
    main()
