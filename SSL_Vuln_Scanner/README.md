# SSL/TLS Vulnerability Scanner

A comprehensive Python tool for auditing SSL/TLS configurations, detecting deprecated protocols, identifying weak ciphers, validating certificates, and testing for known vulnerabilities like Heartbleed. Provides an A-F security grade similar to Qualys SSL Labs.

## Features

- **Protocol Detection**: Tests support for SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, and 1.3
- **Deprecated Protocol Warning**: Flags outdated protocols (SSLv2/SSLv3 = CRITICAL, TLS 1.0 = HIGH, TLS 1.1 = MEDIUM)
- **Cipher Suite Analysis**: Identifies weak ciphers (RC4, DES, NULL, EXPORT, MD5, ANON) and validates strong AEAD ciphers
- **Certificate Validation**: Checks expiration dates, signature algorithms (SHA-1/MD5 detection), issuer information, and serial numbers
- **Heartbleed Test**: Actively tests for CVE-2014-0160 vulnerability using heartbeat extension probes
- **Security Grading**: Calculates A-F grade based on vulnerabilities (A: 90-100, B: 70-89, C: 50-69, D: 30-49, F: <30)
- **Color-Coded Output**: Terminal colors for severity levels (RED=CRITICAL/HIGH, YELLOW=MEDIUM, GREEN=Secure)
- **JSON Export**: Save scan results for automation, reporting, and integration with SIEM tools
- **Remediation Advice**: Provides actionable fixes for each detected vulnerability
- **Graceful Error Handling**: Manages connection timeouts, SSL errors, and interrupted scans

## Requirements

- Python 3.6+
- No external dependencies (uses only standard libraries: `ssl`, `socket`, `json`, `argparse`, `datetime`)

## Installation

No installation required. The script uses only Python standard libraries.

## Usage

### Basic Syntax
```bash
python3 ssl_scanner.py -t <TARGET> [options]
```

### Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--target` | `-t` | Target domain or IP address | Required |
| `--port` | `-p` | Target port | 443 |
| `--timeout` | `-T` | Connection timeout in seconds | 10 |
| `--json` | `-j` | Save results to JSON file | None |

### Example Commands

**Basic scan:**
```bash
python3 ssl_scanner.py -t example.com
```

**Custom port and timeout:**
```bash
python3 ssl_scanner.py -t api.example.com -p 8443 -T 15
```

**Save results to JSON:**
```bash
python3 ssl_scanner.py -t example.com -j results.json
```

**Scan multiple targets (bash loop):**
```bash
for domain in site1.com site2.com site3.com; do
    python3 ssl_scanner.py -t $domain -j ${domain}_ssl_report.json
done
```

## How It Works

### 1. Protocol Testing
The scanner attempts connections using different SSL/TLS protocol versions to determine which are supported. Deprecated protocols trigger immediate vulnerability flags:
- **SSLv2/SSLv3**: CRITICAL severity (immediate F grade)
- **TLS 1.0**: HIGH severity (caps grade at B)
- **TLS 1.1**: MEDIUM severity (reduces score by 15 points)

### 2. Cipher Suite Analysis
Establishes a TLS 1.2 connection and retrieves the negotiated cipher suite. Checks against known weak cipher patterns:
- **Weak**: NULL, EXPORT, DES, RC4, RC2, MD5, ANON, PSK, SRP, CBC
- **Strong**: AES-GCM, ChaCha20-Poly1305, ECDHE key exchange

### 3. Certificate Validation
Retrieves and parses the X.509 certificate to check:
- **Expiration**: Flags certificates expired or expiring within 30 days
- **Signature Algorithm**: Detects weak SHA-1 or MD5 signatures
- **Issuer/Subject**: Displays certificate chain information
- **Serial Number**: Logs for inventory and revocation checking

### 4. Heartbleed Detection (CVE-2014-0160)
Sends a malformed TLS heartbeat request with an oversized payload length. If the server responds with more data than sent, it indicates memory leakage vulnerability. Affects OpenSSL 1.0.1 through 1.0.1f (March 2012 - April 2014).

### 5. Security Grading Algorithm
Calculates a score starting at 100 points, then deducts based on severity:
- **CRITICAL**: -40 points (expired cert, SSLv2, Heartbleed)
- **HIGH**: -25 points (TLS 1.0, weak ciphers, SHA-1 cert)
- **MEDIUM**: -15 points (TLS 1.1, cert expiring soon)
- **LOW**: -5 points (minor configuration issues)

Final grade mapping:
- **A**: 90-100 points (Excellent)
- **B**: 70-89 points (Good)
- **C**: 50-69 points (Acceptable)
- **D**: 30-49 points (Poor)
- **F**: <30 points (Critical failures)

## Example Output

```text
[*] Starting SSL/TLS scan for example.com:443
======================================================================

[1] Checking SSL/TLS Protocols...
  [-] SSLv2: NOT SUPPORTED
  [-] SSLv3: NOT SUPPORTED
  [-] TLSv1.0: NOT SUPPORTED
  [-] TLSv1.1: NOT SUPPORTED
  [+] TLSv1.2: SUPPORTED
  [+] TLSv1.3: SUPPORTED

[2] Checking Cipher Suites...
  [+] Current Cipher: TLS_AES_256_GCM_SHA384 (STRONG)

[3] Checking Certificate...
  [*] Subject: example.com
  [*] Issuer: DigiCert Inc
  [*] Valid From: Jan 15 00:00:00 2026 GMT
  [*] Valid To: Jan 15 23:59:59 2027 GMT
  [+] Valid for 195 more days
  [+] Signature algorithm: sha256WithRSAEncryption

[4] Checking for Heartbleed (CVE-2014-0160)...
  [+] Not vulnerable to Heartbleed

======================================================================
SCAN RESULTS SUMMARY
======================================================================

Overall Security Grade: A

[+] No vulnerabilities detected!

Recommendations:
  [+] SSL/TLS configuration appears secure

======================================================================

[*] Scan completed at 2026-07-04T14:32:15.123456+00:00
```

### Vulnerable Output Example

```text
[1] Checking SSL/TLS Protocols...
  [-] SSLv3: SUPPORTED (DEPRECATED - CRITICAL)
  [-] TLSv1.0: SUPPORTED (DEPRECATED - HIGH)
  [+] TLSv1.2: SUPPORTED

[2] Checking Cipher Suites...
  [-] Current Cipher: DES-CBC3-SHA (WEAK)

[3] Checking Certificate...
  [*] Subject: vulnerable-site.com
  [-] EXPIRED (45 days ago)
  [-] Weak signature algorithm: sha1WithRSAEncryption

[4] Checking for Heartbleed (CVE-2014-0160)...
  [-] VULNERABLE to Heartbleed!

======================================================================
SCAN RESULTS SUMMARY
======================================================================

Overall Security Grade: F

Vulnerabilities Found: 5

  [1] Deprecated Protocol (CRITICAL)
      Description: SSLv3 is supported and should be disabled
      Remediation: Disable SSLv3 and use TLS 1.2 or higher

  [2] Deprecated Protocol (HIGH)
      Description: TLSv1.0 is supported and should be disabled
      Remediation: Disable TLSv1.0 and use TLS 1.2 or higher

  [3] Weak Cipher Suite (HIGH)
      Description: Weak cipher in use: DES-CBC3-SHA
      Remediation: Disable weak ciphers and enable only strong AEAD ciphers

  [4] Expired Certificate (CRITICAL)
      Description: Certificate expired 45 days ago
      Remediation: Renew the certificate immediately

  [5] Weak Signature Algorithm (HIGH)
      Description: Certificate uses weak signature algorithm: sha1WithRSAEncryption
      Remediation: Reissue certificate with SHA-256 or SHA-384

  [6] Heartbleed (CRITICAL)
      Description: Server is vulnerable to Heartbleed (CVE-2014-0160)
      Remediation: Upgrade OpenSSL to version 1.0.1g or later

Recommendations:
  • Disable SSLv3 and use TLS 1.2 or higher
  • Disable TLSv1.0 and use TLS 1.2 or higher
  • Disable weak ciphers and enable only strong AEAD ciphers
  • Renew the certificate immediately
  • Reissue certificate with SHA-256 or SHA-384
  • Upgrade OpenSSL to version 1.0.1g or later

======================================================================
```

## JSON Output Format

When using `-j`, results are saved as structured JSON:

```json
{
  "target": "example.com",
  "port": 443,
  "scan_time": "2026-07-04T14:32:15.123456+00:00",
  "vulnerabilities": [
    {
      "type": "Deprecated Protocol",
      "severity": "HIGH",
      "description": "TLSv1.0 is supported and should be disabled",
      "remediation": "Disable TLSv1.0 and use TLS 1.2 or higher"
    }
  ],
  "protocols": {
    "TLSv1.2": {"supported": true, "version": "TLSv1.2"},
    "TLSv1.3": {"supported": true, "version": "TLSv1.3"}
  },
  "ciphers": ["TLS_AES_256_GCM_SHA384"],
  "certificate": {
    "subject": "example.com",
    "issuer": "DigiCert Inc",
    "valid_from": "Jan 15 00:00:00 2026 GMT",
    "valid_to": "Jan 15 23:59:59 2027 GMT",
    "serial_number": "1234567890ABCDEF",
    "version": 3
  },
  "grade": "A",
  "recommendations": []
}
```

## Vulnerability Reference

### Deprecated Protocols

| Protocol | Severity | Risk | Remediation |
|----------|----------|------|-------------|
| SSLv2 | CRITICAL | Broken encryption, trivial to break | Disable immediately |
| SSLv3 | CRITICAL | POODLE attack (CVE-2014-3566) | Disable immediately |
| TLS 1.0 | HIGH | BEAST attack, weak SHA-1 | Disable unless legacy required |
| TLS 1.1 | MEDIUM | No forward secrecy, SHA-1 | Disable, migrate to 1.2+ |

### Weak Cipher Indicators

- **NULL**: No encryption
- **EXPORT**: Export-grade (40-56 bit), trivially breakable
- **DES/3DES**: Small block size, vulnerable to Sweet32
- **RC4**: Biased keystream, completely broken
- **MD5**: Collision attacks, broken hash function
- **ANON**: Anonymous key exchange, no authentication
- **CBC mode**: Vulnerable to padding oracle attacks (Lucky13, POODLE)

### Certificate Issues

- **Expired**: Immediate security risk, browsers block access
- **Expiring Soon (<30 days)**: Service disruption risk
- **SHA-1 Signature**: Collision attacks demonstrated (SHAttered)
- **Self-Signed**: No trust chain, vulnerable to MITM

### Heartbleed (CVE-2014-0160)

- **Affected**: OpenSSL 1.0.1 through 1.0.1f (March 2012 - April 2014)
- **Impact**: Memory disclosure (up to 64KB per request), can leak private keys, session tokens, passwords
- **Fix**: Upgrade to OpenSSL 1.0.1g or later, regenerate all certificates and keys

## Integration & Automation

### CI/CD Pipeline Integration

```bash
#!/bin/bash
# Add to your deployment pipeline to fail builds with poor SSL grades

python3 ssl_scanner.py -t $DEPLOY_TARGET -j ssl_report.json

GRADE=$(jq -r '.grade' ssl_report.json)
if [[ "$GRADE" == "F" || "$GRADE" == "D" ]]; then
    echo "SSL/TLS grade is $GRADE - deployment blocked"
    exit 1
fi
```

### Bulk Scanning Script

```bash
#!/bin/bash
# Scan multiple domains from a list

while read domain; do
    echo "Scanning $domain..."
    python3 ssl_scanner.py -t $domain -j reports/${domain}_ssl.json
done < domains.txt

# Generate summary
echo "Scan Summary:"
for report in reports/*.json; do
    domain=$(basename $report _ssl.json)
    grade=$(jq -r '.grade' $report)
    vulns=$(jq '.vulnerabilities | length' $report)
    echo "$domain: Grade $grade ($vulns vulnerabilities)"
done
```

### SIEM Integration

Parse JSON output and forward to SIEM tools (Splunk, ELK, QRadar):

```python
import json
with open('ssl_report.json') as f:
    data = json.load(f)
    # Forward to SIEM via HTTP/Syslog
```

## Limitations

- **Single-threaded**: Scans one target at a time (use bash loops for bulk scanning)
- **No STARTTLS**: Does not test SMTP/IMAP/FTP STARTTLS upgrades (requires protocol-specific handling)
- **Basic Heartbleed Test**: Simple probe may miss edge cases; use specialized tools for comprehensive testing
- **No HSTS Check**: Does not verify HTTP Strict Transport Security headers
- **No Chain Validation**: Does not validate full certificate chain trust (relies on OS trust store)

For enterprise-grade scanning, consider:
- **SSLyze**: Comprehensive Python library with plugin architecture
- **testssl.sh**: Bash-based comprehensive TLS scanner
- **Qualys SSL Labs**: Industry-standard online scanner
- **Nmap NSE Scripts**: `ssl-enum-ciphers`, `ssl-heartbleed`, `ssl-poodle`

## Defensive Recommendations

### Immediate Actions for Poor Grades

1. **Disable Deprecated Protocols**:
   ```nginx
   # Nginx
   ssl_protocols TLSv1.2 TLSv1.3;
   ```
   ```apache
   # Apache
   SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
   ```

2. **Configure Strong Ciphers**:
   ```nginx
   ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES256-GCM-SHA384';
   ssl_prefer_server_ciphers on;
   ```

3. **Renew Expired Certificates**: Use Let's Encrypt or commercial CA
4. **Upgrade OpenSSL**: Patch Heartbleed and other vulnerabilities
5. **Enable HSTS**: Add `Strict-Transport-Security` header
6. **Implement Certificate Transparency**: Monitor for unauthorized certificates

### Ongoing Monitoring

- Schedule weekly SSL scans
- Set up alerts for certificate expiration (30, 14, 7 days)
- Monitor SSL Labs grade changes
- Track new CVEs affecting TLS implementations

## Legal & Ethical Warning

**⚠️ IMPORTANT**: This tool is for **educational purposes**, **authorized security auditing**, and **compliance testing** only.

- **Only scan systems you own or have written permission to test**
- **Unauthorized scanning may violate computer fraud laws** (CFAA, Computer Misuse Act)
- **Respect rate limits**: Aggressive scanning can trigger IDS/IPS alerts
- **Responsible disclosure**: Report vulnerabilities to system owners
- **Production caution**: Test in staging environments before production audits

## References

- [Qualys SSL Labs Rating Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)
- [NIST TLS Guidelines (SP 800-52 Rev. 2)](https://pages.nist.gov/800-52-Rev2/)
- [OWASP TLS Configuration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [CVE-2014-0160 (Heartbleed)](https://nvd.nist.gov/vuln/detail/CVE-2014-0160)
- [IETF TLS 1.3 RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
- [PCI DSS TLS Requirements](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.html)





