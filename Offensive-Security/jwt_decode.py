#!/usr/bin/env python3
"""
JWT Decoder for CTFs
Decodes JWT tokens without verifying the signature.
Usage: 
  echo "TOKEN" | python3 jwt_decode.py
  python3 jwt_decode.py "TOKEN"
"""

import sys
import base64
import json

def base64url_decode(data):
    """Decode Base64URL with automatic padding fix."""
    # JWT uses Base64URL which omits padding '='
    # Add padding if missing
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    
    # Replace URL-safe characters with standard Base64 characters
    data = data.replace('-', '+').replace('_', '/')
    
    try:
        decoded_bytes = base64.b64decode(data)
        return json.loads(decoded_bytes.decode('utf-8'))
    except Exception as e:
        return f"Error decoding: {e}"

def decode_jwt(token):
    """Split and decode JWT parts."""
    parts = token.strip().split('.')
    
    if len(parts) != 3:
        print(f"[-] Invalid JWT format. Expected 3 parts, got {len(parts)}")
        sys.exit(1)
    
    header, payload, signature = parts
    
    print("=" * 60)
    print("JWT DECODED")
    print("=" * 60)
    
    print("\n[1] HEADER:")
    print(json.dumps(base64url_decode(header), indent=2))
    
    print("\n[2] PAYLOAD:")
    print(json.dumps(base64url_decode(payload), indent=2))
    
    print(f"\n[3] SIGNATURE (Raw):")
    print(signature)
    
    print("\n" + "=" * 60)

def main():
    if len(sys.argv) > 1:
        token = sys.argv[1]
    elif not sys.stdin.isatty():
        token = sys.stdin.read().strip()
    else:
        print("Usage: echo 'TOKEN' | python3 jwt_decode.py")
        print("   or: python3 jwt_decode.py 'TOKEN'")
        sys.exit(1)
    
    decode_jwt(token)

if __name__ == '__main__':
    main()   
