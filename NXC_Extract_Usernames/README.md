# extract_usernames.py

A small Python script for pulling a clean, deduplicated list of usernames out of nxc (NetExec) SMB user enumeration output.

## What it does

nxc's SMB user enumeration prints one line per discovered user, mixed in with status prefixes, headers, and metadata. This script scans that output, isolates the actual usernames, strips out header rows and stray IP addresses, removes duplicates while preserving the original order, and prints one clean username per line.

## Requirements

Python 3, no external dependencies.

## Usage

There are two ways to run it.

### Option 1: Pipe directly from nxc

```
nxc smb dc01.htb.local -u '' -p '' --users | python3 extract_usernames.py
```

This lets you go straight from enumeration to a clean username list without saving intermediate output.

### Option 2: Run against a saved output file

```
python3 extract_usernames.py nxc_output.txt
```

Save your nxc output to a file first, then pass the file path as an argument.

## Output

The script prints one username per line to stdout, in the order each username first appeared, with duplicates removed. This makes it easy to chain into further tooling, for example redirecting into a file for use in a password spraying or Kerberoasting wordlist:

```
nxc smb dc01.htb.local -u '' -p '' --users | python3 extract_usernames.py > users.txt
```

## How matching works

A line is only considered for extraction if it contains all three of the following markers: `SMB`, `445`, and `DC`. This matches the standard nxc SMB output format. The script then locates the `DC` token on that line and treats the following whitespace separated token as the username.

Lines are excluded from the results if the extracted value is a known header artifact (`-Username-`), a status prefix (`[*]`, `[+]`, `[-]`), any token starting with `[`, or any token starting with `10.` (to avoid picking up an IP address by mistake).

## Notes

The matching logic assumes the standard nxc SMB output column layout. If nxc changes its output format in a future version, or if you're working with output from a different tool, the line filtering and `DC` index lookup may need to be adjusted.
