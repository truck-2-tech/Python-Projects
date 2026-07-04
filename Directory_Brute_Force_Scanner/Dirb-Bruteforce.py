#!/usr/bin/env python3
"""
Dirb-Bruteforce.py - Enhanced Directory Brute-Force Scanner
Features: Multi-threading, proxy support, extensions, rate limiting, false positive reduction
"""

import requests
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning
import threading
import os

# Disable SSL warnings for testing environments
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Global variables for thread coordination
stop_flag = threading.Event()
found_directories = []
lock = threading.Lock()
progress_counter = [0]

def load_wordlist(filepath):
    """Load directory/file names from external wordlist file."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            entries = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"[*] Loaded {len(entries)} entries from {filepath}")
        return entries
    except FileNotFoundError:
        print(f"[-] Error: Wordlist file '{filepath}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading wordlist: {e}")
        sys.exit(1)

def generate_targets(base_entry, extensions, force_extensions):
    """Generate target paths with extensions."""
    targets = []
    
    if not extensions:
        targets.append(base_entry)
        return targets
    
    # If entry already has an extension
    if '.' in base_entry and not base_entry.endswith('/'):
        if force_extensions:
            # Remove existing extension and add new ones
            base = base_entry.rsplit('.', 1)[0]
            for ext in extensions:
                targets.append(f"{base}.{ext}")
            targets.append(base_entry)  # Keep original
        else:
            targets.append(base_entry)  # Keep as-is
    else:
        # Add extensions to entries without extensions
        for ext in extensions:
            targets.append(f"{base_entry}.{ext}")
        if not force_extensions:
            targets.append(base_entry)  # Also test without extension
    
    return targets

def check_false_positive(response, baseline_size):
    """Detect false positives by comparing response sizes."""
    if baseline_size is None:
        return False
    
    # If response size is very close to baseline (custom 404), likely false positive
    size_diff = abs(len(response.content) - baseline_size)
    if size_diff < 50:  # Within 50 bytes
        return True
    
    return False

def get_baseline_404(url, timeout, proxy, user_agent):
    """Get baseline 404 response size for false positive detection."""
    import random
    import string
    random_path = ''.join(random.choices(string.ascii_lowercase, k=15)) + '.nonexistent'
    test_url = f"{url}/{random_path}"
    
    proxies = None
    if proxy:
        proxies = {'http': proxy, 'https': proxy}
    
    headers = {'User-Agent': user_agent}
    
    try:
        response = requests.get(
            test_url,
            proxies=proxies,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers=headers
        )
        return len(response.content)
    except:
        return None

def scan_directory(url, entry, extensions, force_extensions, status_codes, 
                   exclude_codes, timeout, proxy, user_agent, baseline_size, 
                   delay, verbose):
    """Scan a single directory/file entry."""
    
    if stop_flag.is_set():
        return None
    
    # Rate limiting
    if delay > 0:
        time.sleep(delay)
    
    # Generate targets with extensions
    targets = generate_targets(entry, extensions, force_extensions)
    
    proxies = None
    if proxy:
        proxies = {'http': proxy, 'https': proxy}
    
    headers = {'User-Agent': user_agent}
    
    results = []
    
    for target in targets:
        if stop_flag.is_set():
            break
        
        full_url = f"{url}/{target}"
        
        try:
            response = requests.get(
                full_url,
                proxies=proxies,
                timeout=timeout,
                allow_redirects=False,
                verify=False,
                headers=headers
            )
            
            status_code = response.status_code
            response_size = len(response.content)
            
            # Check if status code should be reported
            if status_code in exclude_codes:
                continue
            
            if status_code in status_codes:
                # Check for false positives
                if baseline_size and check_false_positive(response, baseline_size):
                    if verbose:
                        print(f"[~] False positive filtered: {full_url}")
                    continue
                
                # Determine status label
                if status_code == 200:
                    label = "200"
                elif status_code in [301, 302, 307, 308]:
                    label = f"{status_code} -> {response.headers.get('Location', 'N/A')}"
                elif status_code == 403:
                    label = "403 (Forbidden)"
                else:
                    label = str(status_code)
                
                result = {
                    'url': full_url,
                    'status': status_code,
                    'size': response_size,
                    'label': label
                }
                results.append(result)
                
                if verbose:
                    print(f"[+] {label.ljust(30)} - {full_url} (Size: {response_size})")
        
        except requests.exceptions.Timeout:
            if verbose:
                print(f"[!] Timeout: {full_url}")
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error: {full_url}")
            stop_flag.set()
            break
        except Exception as e:
            if verbose:
                print(f"[!] Error scanning {full_url}: {e}")
    
    # Update progress
    with lock:
        progress_counter[0] += 1
    
    return results

def run_scan(url, wordlist_path, extensions, force_extensions, threads, delay,
             status_codes, exclude_codes, timeout, proxy, user_agent, 
             output_file, verbose, no_baseline):
    """Execute multi-threaded directory scan."""
    
    print("=" * 70)
    print("DIRB-BRUTEFORCE - Enhanced Directory Scanner")
    print("=" * 70)
    print(f"[*] Target URL: {url}")
    print(f"[*] Wordlist: {wordlist_path}")
    print(f"[*] Extensions: {extensions if extensions else 'None'}")
    print(f"[*] Force Extensions: {force_extensions}")
    print(f"[*] Threads: {threads}")
    print(f"[*] Delay: {delay}s per request")
    print(f"[*] Proxy: {proxy if proxy else 'None'}")
    print(f"[*] Status Codes: {status_codes}")
    print(f"[*] Exclude Codes: {exclude_codes}")
    print(f"[*] Timeout: {timeout}s")
    print("=" * 70)
    
    # Load wordlist
    entries = load_wordlist(wordlist_path)
    total_entries = len(entries)
    
    # Get baseline 404 for false positive detection
    baseline_size = None
    if not no_baseline:
        print("[*] Getting baseline 404 response size...")
        baseline_size = get_baseline_404(url, timeout, proxy, user_agent)
        if baseline_size:
            print(f"[*] Baseline 404 size: {baseline_size} bytes")
        else:
            print("[!] Could not determine baseline, false positive filtering disabled")
    
    print(f"[*] Starting scan with {threads} threads...\n")
    
    all_results = []
    
    def worker(entry):
        """Worker function for thread pool."""
        if stop_flag.is_set():
            return []
        
        results = scan_directory(
            url, entry, extensions, force_extensions,
            status_codes, exclude_codes, timeout, proxy,
            user_agent, baseline_size, delay, verbose
        )
        
        # Progress indicator
        with lock:
            if not stop_flag.is_set():
                sys.stdout.write(f"[*] Progress: {progress_counter[0]}/{total_entries} ({(progress_counter[0]/total_entries*100):.2f}%)\r")
                sys.stdout.flush()
        
        return results if results else []
    
    # Execute with thread pool
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(worker, entry): entry for entry in entries}
        
        for future in as_completed(futures):
            if stop_flag.is_set():
                break
            
            results = future.result()
            if results:
                with lock:
                    all_results.extend(results)
                    for result in results:
                        if result not in found_directories:
                            found_directories.append(result)
    
    # Print summary
    print(f"\n\n{'=' * 70}")
    print("SCAN COMPLETE")
    print(f"{'=' * 70}")
    
    if found_directories:
        print(f"\n[+] Found {len(found_directories)} valid directories/files:\n")
        for result in sorted(found_directories, key=lambda x: x['status']):
            print(f"  {result['label'].ljust(30)} - {result['url']} (Size: {result['size']})")
    else:
        print("\n[-] No valid directories/files found")
    
    # Save to file if requested
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(f"Dirb-Bruteforce Scan Results\n")
                f.write(f"Target: {url}\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 70 + "\n\n")
                for result in sorted(found_directories, key=lambda x: x['status']):
                    f.write(f"{result['url']} - {result['label']} (Size: {result['size']})\n")
            print(f"\n[*] Results saved to: {output_file}")
        except Exception as e:
            print(f"[-] Error saving results: {e}")
    
    print(f"{'=' * 70}\n")
    
    return found_directories

def main():
    parser = argparse.ArgumentParser(
        description='Dirb-Bruteforce - Enhanced Directory Brute-Force Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 Dirb-Bruteforce.py -u http://target.com -w common.txt
  python3 Dirb-Bruteforce.py -u http://target.com -w directories.txt -e php,html,bak
  python3 Dirb-Bruteforce.py -u http://target.com -w raft-large.txt -t 20 -d 0.2
  python3 Dirb-Bruteforce.py -u http://target.com -w dirs.txt -p http://127.0.0.1:8080
  python3 Dirb-Bruteforce.py -u http://target.com -w dirs.txt -e php -f -o results.txt
        '''
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target base URL (e.g., http://target.com)')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to directory wordlist file')
    parser.add_argument('-e', '--extensions', help='File extensions to test (comma-separated, e.g., php,html,bak)')
    parser.add_argument('-f', '--force-extensions', action='store_true', help='Force extensions on all entries')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    parser.add_argument('-d', '--delay', type=float, default=0.0, help='Delay between requests in seconds (default: 0.0)')
    parser.add_argument('-c', '--status-codes', default='200,301,302,307,308,403', help='Status codes to report (comma-separated, default: 200,301,302,307,308,403)')
    parser.add_argument('-x', '--exclude-codes', default='404', help='Status codes to exclude (comma-separated, default: 404)')
    parser.add_argument('-T', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-A', '--user-agent', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', help='User-Agent string')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all attempts including filtered results')
    parser.add_argument('--no-baseline', action='store_true', help='Disable baseline 404 detection')
    
    args = parser.parse_args()
    
    # Validate inputs
    if args.threads < 1:
        print("[-] Error: Thread count must be at least 1")
        sys.exit(1)
    
    if args.delay < 0:
        print("[-] Error: Delay cannot be negative")
        sys.exit(1)
    
    # Parse extensions
    extensions = None
    if args.extensions:
        extensions = [ext.strip() for ext in args.extensions.split(',')]
    
    # Parse status codes
    try:
        status_codes = [int(code.strip()) for code in args.status_codes.split(',')]
        exclude_codes = [int(code.strip()) for code in args.exclude_codes.split(',')]
    except ValueError:
        print("[-] Error: Invalid status code format")
        sys.exit(1)
    
    # Ensure URL doesn't end with slash
    url = args.url.rstrip('/')
    
    # Run scan
    run_scan(
        url=url,
        wordlist_path=args.wordlist,
        extensions=extensions,
        force_extensions=args.force_extensions,
        threads=args.threads,
        delay=args.delay,
        status_codes=status_codes,
        exclude_codes=exclude_codes,
        timeout=args.timeout,
        proxy=args.proxy,
        user_agent=args.user_agent,
        output_file=args.output,
        verbose=args.verbose,
        no_baseline=args.no_baseline
    )

if __name__ == '__main__':
    main()   
