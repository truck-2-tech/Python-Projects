#!/usr/bin/env python3
"""
Enhanced SSL/TLS Vulnerability Scanner
Checks for deprecated protocols, weak ciphers, certificate validity, and known vulnerabilities.
"""

import ssl
import socket
import sys
import argparse
import json
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any
import struct

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def colorize(text: str, color: str) -> str:
    """Apply color to text if terminal supports it."""
    return f"{color}{text}{Colors.RESET}"

class SSLScanner:
    """Comprehensive SSL/TLS vulnerability scanner."""
    
    # Deprecated protocols
    DEPRECATED_PROTOCOLS = {
        'SSLv2': 'CRITICAL',
        'SSLv3': 'CRITICAL',
        'TLSv1.0': 'HIGH',
        'TLSv1.1': 'MEDIUM'
    }
    
    # Weak cipher patterns
    WEAK_CIPHER_PATTERNS = [
        'NULL', 'EXPORT', 'DES', 'RC4', 'RC2', 'MD5', 
        'ANON', 'PSK', 'SRP', 'CBC'
    ]
    
    # Strong cipher patterns
    STRONG_CIPHER_PATTERNS = [
        'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-CHACHA20-POLY1305',
        'DHE-RSA-AES256-GCM-SHA384'
    ]
    
    def __init__(self, target: str, port: int = 443, timeout: int = 10):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.results: Dict[str, Any] = {
            'target': target,
            'port': port,
            'scan_time': datetime.now(timezone.utc).isoformat(),
            'vulnerabilities': [],
            'protocols': {},
            'ciphers': [],
            'certificate': {},
            'grade': 'A',
            'recommendations': []
        }
    
    def scan(self) -> Dict[str, Any]:
        """Execute full SSL/TLS scan."""
        print(colorize(f"\n[*] Starting SSL/TLS scan for {self.target}:{self.port}", Colors.CYAN))
        print(colorize("=" * 70, Colors.WHITE))
        
        # Check supported protocols
        self._check_protocols()
        
        # Check cipher suites
        self._check_ciphers()
        
        # Check certificate
        self._check_certificate()
        
        # Check for Heartbleed
        self._check_heartbleed()
        
        # Calculate security grade
        self._calculate_grade()
        
        # Print results
        self._print_results()
        
        return self.results
    
    def _check_protocols(self):
        """Check which SSL/TLS protocols are supported."""
        print(colorize("\n[1] Checking SSL/TLS Protocols...", Colors.BLUE))
        
        protocols_to_test = [
            ('SSLv2', ssl.PROTOCOL_SSLv23),  # Note: May not be available in newer Python
            ('SSLv3', ssl.PROTOCOL_SSLv23),
            ('TLSv1.0', ssl.PROTOCOL_TLSv1),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
            ('TLSv1.3', getattr(ssl, 'PROTOCOL_TLSv1_3', None))
        ]
        
        for proto_name, proto_const in protocols_to_test:
            if proto_const is None:
                continue
            
            try:
                context = ssl.SSLContext(proto_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        version = ssock.version()
                        self.results['protocols'][proto_name] = {
                            'supported': True,
                            'version': version
                        }
                        
                        # Check if deprecated
                        if proto_name in self.DEPRECATED_PROTOCOLS:
                            severity = self.DEPRECATED_PROTOCOLS[proto_name]
                            self._add_vulnerability(
                                'Deprecated Protocol',
                                severity,
                                f"{proto_name} is supported and should be disabled",
                                f"Disable {proto_name} and use TLS 1.2 or higher"
                            )
                            print(colorize(f"  [-] {proto_name}: SUPPORTED (DEPRECATED - {severity})", Colors.RED))
                        else:
                            print(colorize(f"  [+] {proto_name}: SUPPORTED", Colors.GREEN))
                            
            except ssl.SSLError as e:
                self.results['protocols'][proto_name] = {'supported': False, 'error': str(e)}
                print(colorize(f"  [-] {proto_name}: NOT SUPPORTED", Colors.YELLOW))
            except Exception as e:
                self.results['protocols'][proto_name] = {'supported': False, 'error': str(e)}
                print(colorize(f"  [!] {proto_name}: ERROR - {str(e)}", Colors.RED))
    
    def _check_ciphers(self):
        """Check for weak cipher suites."""
        print(colorize("\n[2] Checking Cipher Suites...", Colors.BLUE))
        
        # Connect with TLS 1.2 to get cipher list
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        self.results['ciphers'].append(cipher_name)
                        
                        # Check if weak
                        is_weak = any(weak in cipher_name.upper() for weak in self.WEAK_CIPHER_PATTERNS)
                        is_strong = any(strong in cipher_name.upper() for strong in self.STRONG_CIPHER_PATTERNS)
                        
                        if is_weak:
                            self._add_vulnerability(
                                'Weak Cipher Suite',
                                'HIGH',
                                f"Weak cipher in use: {cipher_name}",
                                "Disable weak ciphers and enable only strong AEAD ciphers"
                            )
                            print(colorize(f"  [-] Current Cipher: {cipher_name} (WEAK)", Colors.RED))
                        elif is_strong:
                            print(colorize(f"  [+] Current Cipher: {cipher_name} (STRONG)", Colors.GREEN))
                        else:
                            print(colorize(f"  [*] Current Cipher: {cipher_name}", Colors.WHITE))
                            
        except Exception as e:
            print(colorize(f"  [!] Error checking ciphers: {e}", Colors.RED))
    
    def _check_certificate(self):
        """Check certificate validity and properties."""
        print(colorize("\n[3] Checking Certificate...", Colors.BLUE))
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cert_binary = ssock.getpeercert(binary_form=True)
                    
                    # Parse certificate info
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    valid_from = cert.get('notBefore')
                    valid_to = cert.get('notAfter')
                    
                    self.results['certificate'] = {
                        'subject': subject.get('commonName', 'N/A'),
                        'issuer': issuer.get('commonName', 'N/A'),
                        'valid_from': valid_from,
                        'valid_to': valid_to,
                        'serial_number': cert.get('serialNumber', 'N/A'),
                        'version': cert.get('version', 'N/A')
                    }
                    
                    print(colorize(f"  [*] Subject: {subject.get('commonName', 'N/A')}", Colors.WHITE))
                    print(colorize(f"  [*] Issuer: {issuer.get('commonName', 'N/A')}", Colors.WHITE))
                    print(colorize(f"  [*] Valid From: {valid_from}", Colors.WHITE))
                    print(colorize(f"  [*] Valid To: {valid_to}", Colors.WHITE))
                    
                    # Check expiration
                    not_after = datetime.strptime(valid_to, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 0:
                        self._add_vulnerability(
                            'Expired Certificate',
                            'CRITICAL',
                            f"Certificate expired {abs(days_until_expiry)} days ago",
                            "Renew the certificate immediately"
                        )
                        print(colorize(f"  [-] EXPIRED ({abs(days_until_expiry)} days ago)", Colors.RED))
                    elif days_until_expiry < 30:
                        self._add_vulnerability(
                            'Certificate Expiring Soon',
                            'MEDIUM',
                            f"Certificate expires in {days_until_expiry} days",
                            "Renew the certificate before expiration"
                        )
                        print(colorize(f"  [!] Expiring soon ({days_until_expiry} days)", Colors.YELLOW))
                    else:
                        print(colorize(f"  [+] Valid for {days_until_expiry} more days", Colors.GREEN))
                    
                    # Check signature algorithm
                    sig_alg = cert.get('signatureAlgorithm', '')
                    if 'sha1' in sig_alg.lower() or 'md5' in sig_alg.lower():
                        self._add_vulnerability(
                            'Weak Signature Algorithm',
                            'HIGH',
                            f"Certificate uses weak signature algorithm: {sig_alg}",
                            "Reissue certificate with SHA-256 or SHA-384"
                        )
                        print(colorize(f"  [-] Weak signature algorithm: {sig_alg}", Colors.RED))
                    else:
                        print(colorize(f"  [+] Signature algorithm: {sig_alg}", Colors.GREEN))
                        
        except Exception as e:
            print(colorize(f"  [!] Error checking certificate: {e}", Colors.RED))
            self.results['certificate'] = {'error': str(e)}
    
    def _check_heartbleed(self):
        """Check for Heartbleed vulnerability (CVE-2014-0160)."""
        print(colorize("\n[4] Checking for Heartbleed (CVE-2014-0160)...", Colors.BLUE))
        
        # Heartbleed test payload
        heartbeat_extension = bytes([
            0x18,  # TLS Heartbeat
            0x03, 0x03,  # TLS 1.2
            0x00, 0x03,  # Length
            0x01,  # Type: Request
            0x40, 0x00  # Payload length (fake large value)
        ])
        
        try:
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                # Wrap with SSL
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    # Send heartbeat request
                    ssock.send(heartbeat_extension)
                    
                    # Try to receive response
                    try:
                        response = ssock.recv(1024)
                        if len(response) > 5:
                            self._add_vulnerability(
                                'Heartbleed',
                                'CRITICAL',
                                "Server is vulnerable to Heartbleed (CVE-2014-0160)",
                                "Upgrade OpenSSL to version 1.0.1g or later"
                            )
                            print(colorize("  [-] VULNERABLE to Heartbleed!", Colors.RED))
                        else:
                            print(colorize("  [+] Not vulnerable to Heartbleed", Colors.GREEN))
                    except ssl.SSLError:
                        print(colorize("  [+] Not vulnerable to Heartbleed", Colors.GREEN))
                        
        except Exception as e:
            print(colorize(f"  [!] Error checking Heartbleed: {e}", Colors.YELLOW))
            self.results['heartbleed'] = {'checked': False, 'error': str(e)}
    
    def _add_vulnerability(self, vuln_type: str, severity: str, description: str, remediation: str):
        """Add vulnerability to results."""
        self.results['vulnerabilities'].append({
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'remediation': remediation
        })
    
    def _calculate_grade(self):
        """Calculate overall security grade."""
        grade_scores = {'A': 100, 'B': 80, 'C': 60, 'D': 40, 'F': 0}
        current_score = 100
        
        for vuln in self.results['vulnerabilities']:
            if vuln['severity'] == 'CRITICAL':
                current_score -= 40
            elif vuln['severity'] == 'HIGH':
                current_score -= 25
            elif vuln['severity'] == 'MEDIUM':
                current_score -= 15
            elif vuln['severity'] == 'LOW':
                current_score -= 5
        
        if current_score >= 90:
            self.results['grade'] = 'A'
        elif current_score >= 70:
            self.results['grade'] = 'B'
        elif current_score >= 50:
            self.results['grade'] = 'C'
        elif current_score >= 30:
            self.results['grade'] = 'D'
        else:
            self.results['grade'] = 'F'
    
    def _print_results(self):
        """Print formatted scan results."""
        print(colorize("\n" + "=" * 70, Colors.WHITE))
        print(colorize("SCAN RESULTS SUMMARY", Colors.BOLD + Colors.CYAN))
        print(colorize("=" * 70, Colors.WHITE))
        
        # Security Grade
        grade_color = {
            'A': Colors.GREEN,
            'B': Colors.GREEN,
            'C': Colors.YELLOW,
            'D': Colors.RED,
            'F': Colors.RED
        }.get(self.results['grade'], Colors.WHITE)
        
        print(colorize(f"\nOverall Security Grade: {self.results['grade']}", grade_color + Colors.BOLD))
        
        # Vulnerabilities
        if self.results['vulnerabilities']:
            print(colorize(f"\nVulnerabilities Found: {len(self.results['vulnerabilities'])}", Colors.RED + Colors.BOLD))
            for i, vuln in enumerate(self.results['vulnerabilities'], 1):
                severity_color = {
                    'CRITICAL': Colors.RED,
                    'HIGH': Colors.RED,
                    'MEDIUM': Colors.YELLOW,
                    'LOW': Colors.BLUE
                }.get(vuln['severity'], Colors.WHITE)
                
                print(colorize(f"\n  [{i}] {vuln['type']} ({vuln['severity']})", severity_color + Colors.BOLD))
                print(colorize(f"      Description: {vuln['description']}", Colors.WHITE))
                print(colorize(f"      Remediation: {vuln['remediation']}", Colors.CYAN))
        else:
            print(colorize("\n[+] No vulnerabilities detected!", Colors.GREEN + Colors.BOLD))
        
        # Recommendations
        print(colorize("\nRecommendations:", Colors.BOLD + Colors.MAGENTA))
        if not self.results['vulnerabilities']:
            print(colorize("  [+] SSL/TLS configuration appears secure", Colors.GREEN))
        else:
            for vuln in self.results['vulnerabilities']:
                print(colorize(f"  • {vuln['remediation']}", Colors.YELLOW))
        
        print(colorize("\n" + "=" * 70, Colors.WHITE))
        
        # Save to JSON if needed
        print(colorize(f"\n[*] Scan completed at {self.results['scan_time']}", Colors.CYAN))

def main():
    parser = argparse.ArgumentParser(
        description='Enhanced SSL/TLS Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 ssl_scanner.py -t example.com
  python3 ssl_scanner.py -t example.com -p 443
  python3 ssl_scanner.py -t example.com -p 8443 -T 15
  python3 ssl_scanner.py -t example.com --json output.json
        '''
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target domain or IP address')
    parser.add_argument('-p', '--port', type=int, default=443, help='Target port (default: 443)')
    parser.add_argument('-T', '--timeout', type=int, default=10, help='Connection timeout in seconds (default: 10)')
    parser.add_argument('-j', '--json', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    # Validate target
    target = args.target.replace('https://', '').replace('http://', '').split('/')[0]
    
    try:
        scanner = SSLScanner(target, args.port, args.timeout)
        results = scanner.scan()
        
        # Save to JSON if requested
        if args.json:
            with open(args.json, 'w') as f:
                json.dump(results, f, indent=2)
            print(colorize(f"\n[*] Results saved to {args.json}", Colors.GREEN))
        
        # Exit with error code if vulnerabilities found
        if results['vulnerabilities']:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print(colorize("\n[!] Scan interrupted by user", Colors.YELLOW))
        sys.exit(130)
    except Exception as e:
        print(colorize(f"\n[!] Fatal error: {e}", Colors.RED))
        sys.exit(1)

if __name__ == '__main__':
    main()   
