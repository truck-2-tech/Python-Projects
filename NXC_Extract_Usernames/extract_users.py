#!/usr/bin/env python3
import sys
import re

def extract_usernames(input_text):
    """Extract usernames from nxc SMB user enumeration output"""
    usernames = []
    
    # Split into lines
    lines = input_text.strip().split('\n')
    
    for line in lines:
        # Look for lines that contain actual user data
        # Pattern: SMB IP 445 DC username date time number description
        if 'SMB' in line and '445' in line and 'DC' in line:
            # Split by whitespace and filter
            parts = line.split()
            
            # Find the username (comes after "DC")
            try:
                dc_index = parts.index('DC')
                # Username is right after DC
                if dc_index + 1 < len(parts):
                    username = parts[dc_index + 1]
                    
                    # Skip header lines and metadata
                    if username not in ['-Username-', '[*]', '[+]', '[-]'] and \
                       not username.startswith('[') and \
                       not username.startswith('10.'):
                        usernames.append(username)
            except (ValueError, IndexError):
                continue
    
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
        # Read from file
        with open(sys.argv[1], 'r') as f:
            input_text = f.read()
    else:
        # Read from stdin
        input_text = sys.stdin.read()
    
    usernames = extract_usernames(input_text)
    
    # Print usernames, one per line
    for username in usernames:
        print(username)

if __name__ == "__main__":
    main()
