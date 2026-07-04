# Directory Brute-Force Scanner

A Python script for discovering hidden directories and files on web servers by systematically testing common paths from a wordlist. This tool is essential for reconnaissance during penetration testing and CTF challenges.

> **⚠️ Legal Warning**: Only use this tool on systems you own or have explicit written permission to test. Unauthorized scanning violates computer fraud laws in most jurisdictions.

## Features

- **External Wordlist Support**: Load comprehensive directory lists from files (e.g., SecLists, `raft-large-directories.txt`)
- **Smart Status Code Detection**: Identifies valid directories using multiple HTTP status codes (200, 301, 302, 403)
- **False Positive Reduction**: Filters out common false positives by comparing response sizes
- **Concise Output**: Only displays discovered directories by default (suppresses 404 noise)
- **Verbose Mode**: Optional detailed output showing all attempts and response details
- **Custom Extensions**: Test directories with specific file extensions (`.php`, `.html`, `.bak`)
- **User-Agent Rotation**: Configurable User-Agent headers to avoid basic detection

## Requirements

- Python 3.6+
- `requests` library

Install dependencies:
```bash
pip install requests
```

## Usage

### Basic Syntax
```bash
python3 dir_scanner.py -u <URL> -w <WORDLIST> [options]
```

### Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--url` | `-u` | Target base URL (e.g., `http://target.com`) | Required |
| `--wordlist` | `-w` | Path to directory wordlist file | Required |
| `--extensions` | `-e` | File extensions to test (comma-separated) | None |
| `--status-codes` | `-c` | Status codes to report (comma-separated) | 200,301,302,403 |
| `--exclude-codes` | `-x` | Status codes to hide (comma-separated) | 404 |
| `--timeout` | `-T` | Request timeout in seconds | 10 |
| `--verbose` | `-v` | Show all attempts including 404s | False |
| `--user-agent` | `-A` | Custom User-Agent string | Mozilla/5.0 |
| `--output` | `-o` | Save results to file | None |

### Example Commands

**Basic scan with common wordlist:**
```bash
python3 dir_scanner.py -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

**Scan with extensions:**
```bash
python3 dir_scanner.py -u http://target.com -w directories.txt -e php,html,bak,txt
```

**Verbose mode with custom timeout:**
```bash
python3 dir_scanner.py -u http://target.com -w raft-large-directories.txt -v -T 15
```

**Save results to file:**
```bash
python3 dir_scanner.py -u http://target.com -w directories.txt -o results.txt
```

**Filter specific status codes:**
```bash
python3 dir_scanner.py -u http://target.com -w directories.txt -c 200,301,403 -x 404,500
```

## How It Works

1. **Wordlist Loading**: Reads directory/file names from an external text file (one entry per line)
2. **URL Construction**: Appends each wordlist entry to the base URL
3. **HTTP Request**: Sends GET requests to each constructed URL
4. **Response Analysis**: Checks HTTP status codes and response sizes
5. **False Positive Filtering**: Compares response sizes to detect custom 404 pages
6. **Result Reporting**: Displays valid directories with status codes and content lengths

## Status Code Reference

Understanding HTTP status codes is critical for accurate results:

- **200 OK**: Directory/file exists and is accessible
- **301 Moved Permanently**: Directory exists (often redirects to add trailing slash)
- **302 Found**: Temporary redirect (may indicate authentication requirement)
- **307/308 Temporary/Permanent Redirect**: Similar to 301/302
- **403 Forbidden**: Directory exists but access is denied (worth investigating)
- **404 Not Found**: Directory does not exist (typically filtered out)
- **500 Internal Server Error**: Server error (may indicate vulnerability)

## Recommended Wordlists

Use comprehensive wordlists for thorough scanning:

### SecLists (Recommended)
```bash
# Small, fast scan
/usr/share/seclists/Discovery/Web-Content/common.txt

# Medium comprehensive scan
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Large thorough scan
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
```

### Dirb Default Wordlists
```bash
/usr/share/dirb/wordlists/common.txt
/usr/share/dirb/wordlists/big.txt
/usr/share/dirb/wordlists/vulns.txt
```

### Custom Wordlists
Generate targeted wordlists using:
- **CeWL**: Scrape words from the target website
- **Crunch**: Generate pattern-based lists
- **Manual curation**: Based on technology stack (CMS-specific lists)

## Example Output

```text
============================================================
DIRECTORY BRUTE-FORCE SCANNER
============================================================
[*] Target: http://hackers-rule.hack
[*] Wordlist: /usr/share/seclists/Discovery/Web-Content/common.txt
[*] Extensions: None
[*] Reporting status codes: 200, 301, 302, 403
[*] Timeout: 10s
============================================================
[*] Loaded 4614 entries from wordlist
[*] Starting scan...

[+] 200  -  http://hackers-rule.hack/admin (Size: 5432)
[+] 301  -  http://hackers-rule.hack/images (Size: 312)
[+] 200  -  http://hackers-rule.hack/uploads (Size: 1024)
[+] 403  -  http://hackers-rule.hack/private (Size: 287)
[+] 200  -  http://hackers-rule.hack/test (Size: 8921)

============================================================
[+] Scan complete! Found 5 valid directories
============================================================
[*] Results saved to: results.txt
```

## Advanced Techniques

### 1. Recursive Scanning
After discovering initial directories, scan subdirectories:
```bash
python3 dir_scanner.py -u http://target.com/admin -w directories.txt
```

### 2. Extension Fuzzing
Test files with multiple extensions:
```bash
python3 dir_scanner.py -u http://target.com -w files.txt -e php,asp,aspx,html,js,json,xml,bak,old,txt,conf,config
```

### 3. CMS-Specific Scanning
Use targeted wordlists for known CMS platforms:
```bash
# WordPress
python3 dir_scanner.py -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.txt

# Joomla
python3 dir_scanner.py -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/CMS/joomla.txt

# Drupal
python3 dir_scanner.py -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/CMS/drupal.txt
```

### 4. API Endpoint Discovery
Find hidden API endpoints:
```bash
python3 dir_scanner.py -u http://target.com/api -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt
```

## Reducing False Positives

Web servers often return custom 404 pages with status code 200. To reduce false positives:

1. **Compare Response Sizes**: Valid directories typically have consistent sizes; custom 404s vary
2. **Check Multiple Codes**: Look for 301 redirects (indicates real directory)
3. **Analyze Content**: Real directories often contain directory listings or specific content
4. **Use Multiple Wordlists**: Cross-reference findings across different lists
5. **Manual Verification**: Always manually verify critical findings

## Alternative Tools

For production-grade directory enumeration, consider:

- **Gobuster**: Fast, multi-threaded Go-based scanner with DNS and VHost modes
- **FFUF**: Extremely fast web fuzzer with advanced filtering and recursion
- **Dirsearch**: Feature-rich Python scanner with recursive scanning and extensions
- **Dirb**: Classic directory brute-forcer with built-in wordlists
- **Nikto**: Comprehensive web server scanner with directory detection

## Defensive Recommendations

Protect your web servers from directory enumeration:

1. **Disable Directory Listing**: Configure web server to prevent auto-indexing
2. **Custom 404 Pages**: Return consistent responses for non-existent paths
3. **Rate Limiting**: Throttle requests from single IPs
4. **WAF Rules**: Block automated scanning patterns
5. **Remove Unnecessary Directories**: Delete default/backup directories
6. **Access Controls**: Restrict sensitive directories with authentication
7. **Logging & Monitoring**: Alert on high-volume 404 errors
8. **Use Unpredictable Names**: Avoid common names like `/admin`, `/backup`

## Legal & Ethical Warning

**⚠️ IMPORTANT**: This tool is for **educational purposes**, **authorized penetration testing**, and **CTF competitions** only.

- **Always obtain written permission** before scanning any system you don't own
- **Unauthorized scanning is illegal** under computer fraud laws
- **Respect robots.txt**: While not legally binding, it indicates owner preferences
- **Avoid production systems**: Test in lab environments (DVWA, Metasploitable, etc.)
- **Responsible disclosure**: Report discovered vulnerabilities to system owners

## References

- [OWASP Testing Guide - Directory Enumeration](https://owasp.org/www-project-web-security-testing-guide/)
- [SecLists GitHub Repository](https://github.com/danielmiessler/SecLists)
- [CWE-548: Information Exposure Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)
- [Gobuster Documentation](https://github.com/OJ/gobuster)
- [FFUF Wiki](https://github.com/ffuf/ffuf/wiki)





