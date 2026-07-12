#!/usr/bin/env python3
import sys

def extract_usernames(input_text):
    """Extract usernames from nxc SMB user enumeration output"""
    usernames = []

    lines = input_text.strip().split('\n')

    for line in lines:
        parts = line.split()

        # Expect: SMB  <ip>  445  <hostname>  <username>  ...
        if len(parts) < 5:
            continue
        if parts[0] != 'SMB' or parts[2] != '445':
            continue

        username = parts[4]

        # Skip header row, status lines, and anything that isn't a real username
        if username in ('-Username-',) or username.startswith('['):
            continue

        usernames.append(username)

    # Remove duplicates while preserving order
    seen = set()
    unique_usernames = []
    for user in usernames:
        if user not in seen:
            seen.add(user)
            unique_usernames.append(user)

    return unique_usernames

def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            input_text = f.read()
    else:
        input_text = sys.stdin.read()

    usernames = extract_usernames(input_text)

    for username in usernames:
        print(username)

if __name__ == "__main__":
    main()
