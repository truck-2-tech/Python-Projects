# keepass-split

A small utility that splits a `keepassxc-cli` CSV export into two flat wordlist files, one for usernames and one for passwords, in matching line order. Built for pentest workflows where a KeePass database has been recovered from a target and the credentials inside need to be reshaped into a format tools like Kerbrute, nxc, or Hydra can consume directly.

## Why

`keepassxc-cli export --format csv` produces a structured CSV with Group, Title, Username, Password, URL, Notes, and timestamp columns. Most offensive tooling doesn't want that, it wants one username per line and one password per line. This script handles that conversion in one step, and accounts for the common case where an entry's Username field is left blank and the actual identifier only exists in the Title field.

## Requirements

- Python 3.6+
- No third party dependencies, uses only the standard library `csv` module

## Usage

Export the KeePass database to CSV first.

```bash
keepassxc.cli export --format csv target.kdbx > export.csv
```

Then run the script against the export.

```bash
python3 keepass_split.py export.csv
```

This produces two files in the current directory.

```
keepass_users.txt
keepass_pass.txt
```

Each line in `keepass_users.txt` corresponds to the same line number in `keepass_pass.txt`, so the output can be used for paired credential testing as well as a straight wordlist spray.

## Behavior notes

If the Username field is empty for an entry, which is common when credentials were only ever stored under Title, the script falls back to the Title field so the line isn't dropped or left blank. Entries with no password value are skipped in the password file but still contribute a line to the username file if a name was recovered, and vice versa, so the two files may not always be perfectly aligned if the source data itself is inconsistent. Review the output before assuming a strict 1:1 mapping if the export contains partial entries.

Display names pulled from Title, such as `JAMIE WILLIAMSON`, are not usable Active Directory usernames as-is. Consider running the output through a username permutation tool such as usernamer, username-anarchy, or a custom script to generate likely AD-style formats (`jamie.williamson`, `j.williamson`, `jwilliamson`) before using the list against Kerbrute, nxc, or similar.

## Example

Input CSV row:

```
"Root","JAMIE WILLIAMSON","","JamieLove2025!","puppy.htb","","","0","2025-03-10T08:57:58Z","2025-03-10T08:57:01Z"
```

Output:

`keepass_users.txt`
```
JAMIE WILLIAMSON
```

`keepass_pass.txt`
```
JamieLove2025!
```

## License

MIT
