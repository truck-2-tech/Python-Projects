#!/usr/bin/env python3
"""
Splits a keepassxc-cli CSV export into two flat text files for wordlist use,
one username per line and one password per line, same order so they line
up if you want to hand them to something like a paired credential spray.

Usage:
    python3 kp_split.py recovery_export.csv

Produces:
    keepass_users.txt
    keepass_pass.txt

If the Username field is blank (common when creds were only ever stored
under Title, like "JAMIE WILLIAMSON"), falls back to the Title field so
you still get a usable line instead of an empty one.
"""

import csv
import sys
import os

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <keepass_export.csv>")
        sys.exit(1)

    infile = sys.argv[1]
    if not os.path.isfile(infile):
        print(f"[!] File not found: {infile}")
        sys.exit(1)

    users_out = "keepass_users.txt"
    pass_out = "keepass_pass.txt"

    users = []
    passwords = []

    with open(infile, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            username = (row.get("Username") or "").strip()
            title = (row.get("Title") or "").strip()
            password = (row.get("Password") or "").strip()

            # fall back to Title when Username is blank
            user_value = username if username else title

            if user_value:
                users.append(user_value)
            if password:
                passwords.append(password)

    with open(users_out, "w", encoding="utf-8") as f:
        f.write("\n".join(users) + "\n")

    with open(pass_out, "w", encoding="utf-8") as f:
        f.write("\n".join(passwords) + "\n")

    print(f"[+] Wrote {len(users)} usernames to {users_out}")
    print(f"[+] Wrote {len(passwords)} passwords to {pass_out}")

if __name__ == "__main__":
    main()
