# Enhanced HTTP Login Brute-Force Script

This upgraded version includes **external wordlist support**, **rate limiting**, **advanced success detection**, **multi-threading**, and **proxy support** for professional security auditing.

## Features (see further down for more information)

- **External Wordlist Support**: Load password lists from files (e.g., `rockyou.txt`)
- **Configurable Rate Limiting**: Prevent detection with customizable delays between attempts
- **Advanced Success Detection**: Multiple detection methods (status codes, response content, redirects, cookies)
- **Multi-threading**: Concurrent requests for faster testing with configurable thread count
- **Proxy Support**: Route traffic through HTTP/HTTPS proxies or Burp Suite
- **Graceful Shutdown**: Stop all threads immediately when password is found
- **Verbose Output**: Real-time progress tracking with attempt counters

## Requirements

- Python 3.6+
- `requests` library
- `concurrent.futures` (built-in)

Install dependencies:
```bash
pip install requests
```

## Usage

### Basic Syntax
```bash
python3 brute_force_enhanced.py -u <URL> -U <USERNAME> -w <WORDLIST> [options]
```

### Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--url` | `-u` | Target login URL | Required |
| `--username` | `-U` | Target username | Required |
| `--wordlist` | `-w` | Path to password wordlist file | Required |
| `--threads` | `-t` | Number of concurrent threads | 5 |
| `--delay` | `-d` | Delay between attempts (seconds) per thread | 0.1 |
| `--proxy` | `-p` | Proxy URL (e.g., `http://127.0.0.1:8080`) | None |
| `--success-string` | `-s` | String to detect successful login | "Login successful" |
| `--success-code` | `-c` | HTTP status code indicating success | 302 |
| `--timeout` | `-T` | Request timeout in seconds | 10 |
| `--verbose` | `-v` | Show all attempts (not just failures) | False |

### Example Commands

**Basic usage with wordlist:**
```bash
python3 brute_force_enhanced.py -u http://target.com/login -U admin -w /usr/share/wordlists/rockyou.txt
```

**With rate limiting and threading:**
```bash
python3 brute_force_enhanced.py -u http://target.com/login -U admin -w passwords.txt -t 10 -d 0.5
```

**Through Burp Suite proxy:**
```bash
python3 brute_force_enhanced.py -u http://target.com/login -U admin -w passwords.txt -p http://127.0.0.1:8080 --timeout 15
```

**Custom success detection:**
```bash
python3 brute_force_enhanced.py -u http://target.com/login -U admin -w passwords.txt -s "Welcome" -c 200
```

## Features In-Depth

### 1. External Wordlist Support
The script now reads passwords from any text file, enabling use of comprehensive wordlists like `rockyou.txt`, `seclists`, or custom lists.

**Usage:**
```bash
python3 brute_force_enhanced.py -u http://target.com/login -U admin -w /usr/share/wordlists/rockyou.txt
```

### 2. Rate Limiting & Delays
Prevents IP bans and IDS triggers by adding configurable delays between requests. Each thread respects the delay independently.

**Recommended delays:**
- **Aggressive**: 0.0-0.1s (fast, high detection risk)
- **Moderate**: 0.2-0.5s (balanced)
- **Stealthy**: 1.0-3.0s (slow, low detection risk)

### 3. Advanced Success Detection
Multiple detection methods increase accuracy across different applications:

- **String matching**: Searches response body for success messages
- **Status code**: Detects redirects (302) or success codes (200)
- **Session cookies**: Identifies new session tokens
- **Redirect location**: Checks for dashboard/home redirects

**Customize detection:**
```bash
# Look for "Welcome" in response and expect 200 OK
python3 brute_force_enhanced.py -u http://target.com/login -U admin -w passwords.txt -s "Welcome" -c 200
```

### 4. Multi-threading
Concurrent requests dramatically reduce testing time. Use 5-20 threads for most scenarios.

**Thread count recommendations:**
- **Local/lab**: 20-50 threads
- **Remote testing**: 5-10 threads
- **WAF-protected**: 1-3 threads with delays

### 5. Proxy Support
Route traffic through proxies for anonymity or interception:

**Burp Suite:**
```bash
python3 brute_force_enhanced.py -u http://target.com/login -U admin -w passwords.txt -p http://127.0.0.1:8080
```

**Tor:**
```bash
python3 brute_force_enhanced.py -u http://target.com/login -U admin -w passwords.txt -p socks5://127.0.0.1:9050
```

## Example Output

```text
======================================================================
ENHANCED HTTP LOGIN BRUTE-FORCE
======================================================================
[*] Target URL: http://target.com/login
[*] Username: admin
[*] Wordlist: /usr/share/wordlists/rockyou.txt
[*] Threads: 10
[*] Delay: 0.2s per attempt
[*] Proxy: None
[*] Success Detection: String='Login successful', Code=302
======================================================================
[*] Loaded 14344392 passwords from /usr/share/wordlists/rockyou.txt
[*] Starting attack...

[*] Progress: 1523/14344392 (0.01%) - Current: password123

======================================================================
[+] LOGIN SUCCESSFUL!
======================================================================
Username: admin
Password: admin123
======================================================================
```

## Legal & Ethical Warning

**⚠️ IMPORTANT**: This tool is for **educational purposes**, **authorized penetration testing**, and **CTF competitions** only.

- **Always obtain written permission** before testing any system you don't own
- **Unauthorized access is illegal** under computer fraud laws (CFAA, Computer Misuse Act, etc.)
- **Responsible disclosure**: Report vulnerabilities to system owners
- **Lab environments only**: Test on systems you control (DVWA, Metasploitable, etc.)

## Defensive Recommendations

Protect your applications against brute-force attacks:

1. **Implement rate limiting** (max 5 attempts per minute per IP)
2. **Use account lockout** policies (lock after 5-10 failures)
3. **Deploy CAPTCHA** after 2-3 failed attempts
4. **Enable MFA** for all accounts
5. **Monitor and alert** on unusual login patterns
6. **Use fail2ban** or similar tools to block attacking IPs
7. **Log all authentication attempts** with IP, timestamp, and outcome





