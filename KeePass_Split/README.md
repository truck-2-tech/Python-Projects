# keepass_split

A small utility that rebuilds two common recon one-liners into a single script. It takes the raw output of a `netexec --users` enumeration and a `keepassxc-cli` CSV export and writes them out as flat wordlist files, one username per line and one password per line, ready to hand off to tools like Kerbrute, nxc, or Hydra.

## Why

On an AD box you'll often pull a valid domain user list with netexec and separately recover a KeePass database with credentials in it. Getting both into plain wordlists usually means remembering a grep/awk pipeline for one and a cut pipeline for the other, every single time. This script replaces both with one command.

It specifically mirrors these two pipelines.

```bash
netexec smb <target> -u <user> -p '<pass>' --users \
    | grep -vF -e '[' -e '-Username-' | awk '{print $5}'

keepassxc.cli export --format csv <db.kdbx> | cut -d'"' -f8
```

## Requirements

- Python 3.6+
- No third party dependencies, standard library only

## Usage

Save the raw output of each command to a file first. keepassxc-cli needs an interactive prompt for the vault password, so it can't be piped directly into the script.

```bash
netexec smb puppy.htb -u levi.james -p 'KingofAkron2025!' --users > nxc_users_raw.txt
keepassxc.cli export --format csv recovery.kdbx > keepass_export_raw.csv
```

Then run the script against one or both files.

```bash
python3 keepass_split.py --nxc nxc_users_raw.txt --keepass keepass_export_raw.csv
```

This produces the following files in the current directory, depending on which flags were passed.

```
users.txt
passwords.txt
```

Either flag can be used on its own if you only have one side of the data, for example just extracting passwords from a recovered vault without an nxc user list.

```bash
python3 keepass_split.py --keepass keepass_export_raw.csv
```

## Behavior notes

The nxc parser drops the banner line and the `-Username-` header line, then takes the fifth whitespace-separated field from each remaining row, matching the column position netexec prints the account name in.

The keepass parser splits each CSV line on the literal double-quote character and takes the eighth field, which lands on the Password column given the CSV's `Group,Title,Username,Password,...` layout. The literal header value `Password` is filtered out so it doesn't end up in the wordlist. This is a positional cut, not a proper CSV parse, so it expects the export to keep the default keepassxc-cli column order.

The two output files are independent lists rather than paired line-for-line entries, since usernames come from live domain enumeration and passwords come from a separate recovered vault, and the two sources won't always be in the same order or represent the same accounts.

## Example

Given this nxc output.

```
SMB   puppy.htb 445  DC01  levi.james                     2025-03-10 08:00:00 0
SMB   puppy.htb 445  DC01  jamie.williams                 2025-03-10 08:00:00 0
```

And this keepass export.

```
"Root","JAMIE WILLIAMSON","","JamieLove2025!","puppy.htb","","","0","2025-03-10T08:57:58Z","2025-03-10T08:57:01Z"
```

Running the script produces:

`users.txt`
```
levi.james
jamie.williams
```

`passwords.txt`
```
JamieLove2025!
```

## License

MIT
