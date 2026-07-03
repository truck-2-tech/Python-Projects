#!/usr/bin/env python3
"""
Convert PuTTY PPK (PuTTY-User-Key-File-3) format to OpenSSH private key format.
Usage: python3 ppk_to_openssh.py <input_ppk_file> <output_openssh_file>
"""

import sys
import base64
import struct
import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def parse_ppk_file(ppk_content):
    """Parse PuTTY PPK file format and extract key components."""
    lines = ppk_content.strip().split('\n')
    
    key_data = {
        'type': None,
        'encryption': None,
        'comment': None,
        'public_lines': [],
        'private_lines': [],
        'private_mac': None
    }
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        if line.startswith('PuTTY-User-Key-File-'):
            key_data['version'] = line.split(': ')[1]
        elif line.startswith('Encryption:'):
            key_data['encryption'] = line.split(': ')[1]
        elif line.startswith('Comment:'):
            key_data['comment'] = line.split(': ')[1]
        elif line.startswith('Public-Lines:'):
            num_public_lines = int(line.split(': ')[1])
            i += 1
            for _ in range(num_public_lines):
                key_data['public_lines'].append(lines[i].strip())
                i += 1
            continue
        elif line.startswith('Private-Lines:'):
            num_private_lines = int(line.split(': ')[1])
            i += 1
            for _ in range(num_private_lines):
                key_data['private_lines'].append(lines[i].strip())
                i += 1
            continue
        elif line.startswith('Private-MAC:'):
            key_data['private_mac'] = line.split(': ')[1]
        
        i += 1
    
    return key_data


def decode_key_data(key_data):
    """Decode the base64-encoded public and private key data."""
    public_blob = base64.b64decode(''.join(key_data['public_lines']))
    private_blob = base64.b64decode(''.join(key_data['private_lines']))
    
    return public_blob, private_blob


def parse_rsa_public_key(public_blob):
    """Parse RSA public key blob to extract modulus and exponent."""
    # SSH RSA key format:
    # uint32 length, "ssh-rsa"
    # uint32 length, exponent e
    # uint32 length, modulus n
    
    offset = 0
    
    # Skip key type string
    type_len = struct.unpack('>I', public_blob[offset:offset+4])[0]
    offset += 4
    key_type = public_blob[offset:offset+type_len].decode('ascii')
    offset += type_len
    
    if key_type != 'ssh-rsa':
        raise ValueError(f"Unsupported key type: {key_type}")
    
    # Get exponent e
    e_len = struct.unpack('>I', public_blob[offset:offset+4])[0]
    offset += 4
    e = int.from_bytes(public_blob[offset:offset+e_len], 'big')
    offset += e_len
    
    # Get modulus n
    n_len = struct.unpack('>I', public_blob[offset:offset+4])[0]
    offset += 4
    n = int.from_bytes(public_blob[offset:offset+n_len], 'big')
    
    return n, e


def parse_rsa_private_key(private_blob, n, e):
    """Parse RSA private key blob to extract private exponent and other components."""
    # PuTTY private key format for RSA:
    # uint32 length, private exponent d
    # uint32 length, prime p
    # uint32 length, prime q
    # uint32 length, inverse of q mod p (iqmp)
    
    offset = 0
    
    # Get private exponent d
    d_len = struct.unpack('>I', private_blob[offset:offset+4])[0]
    offset += 4
    d = int.from_bytes(private_blob[offset:offset+d_len], 'big')
    offset += d_len
    
    # Get prime p
    p_len = struct.unpack('>I', private_blob[offset:offset+4])[0]
    offset += 4
    p = int.from_bytes(private_blob[offset:offset+p_len], 'big')
    offset += p_len
    
    # Get prime q
    q_len = struct.unpack('>I', private_blob[offset:offset+4])[0]
    offset += 4
    q = int.from_bytes(private_blob[offset:offset+q_len], 'big')
    offset += q_len
    
    # Get iqmp (inverse of q mod p)
    iqmp_len = struct.unpack('>I', private_blob[offset:offset+4])[0]
    offset += 4
    iqmp = int.from_bytes(private_blob[offset:offset+iqmp_len], 'big')
    
    return d, p, q, iqmp


def create_rsa_private_key(n, e, d, p, q, iqmp):
    """Create RSA private key object from components."""
    # Calculate additional RSA parameters
    # dp = d mod (p-1)
    dp = d % (p - 1)
    # dq = d mod (q-1)
    dq = d % (q - 1)
    
    # Create RSA private numbers
    public_numbers = rsa.RSAPublicNumbers(e, n)
    private_numbers = rsa.RSAPrivateNumbers(p, q, d, dp, dq, iqmp, public_numbers)
    
    # Create private key object
    private_key = private_numbers.private_key(default_backend())
    
    return private_key


def export_to_openssh(private_key, comment=None):
    """Export RSA private key to OpenSSH format."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return pem.decode('utf-8')


def convert_ppk_to_openssh(ppk_content):
    """Main conversion function."""
    # Parse PPK file
    key_data = parse_ppk_file(ppk_content)
    
    if key_data['encryption'] != 'none':
        raise ValueError("Encrypted keys are not supported in this script")
    
    # Decode key blobs
    public_blob, private_blob = decode_key_data(key_data)
    
    # Parse RSA public key
    n, e = parse_rsa_public_key(public_blob)
    
    # Parse RSA private key
    d, p, q, iqmp = parse_rsa_private_key(private_blob, n, e)
    
    # Create RSA private key object
    private_key = create_rsa_private_key(n, e, d, p, q, iqmp)
    
    # Export to OpenSSH format
    openssh_key = export_to_openssh(private_key, key_data['comment'])
    
    return openssh_key


def main():
    parser = argparse.ArgumentParser(
        description='Convert PuTTY PPK format to OpenSSH private key format'
    )
    parser.add_argument('input_file', help='Input PPK file')
    parser.add_argument('output_file', help='Output OpenSSH private key file')
    
    args = parser.parse_args()
    
    # Read input PPK file
    with open(args.input_file, 'r') as f:
        ppk_content = f.read()
    
    # Convert to OpenSSH format
    try:
        openssh_key = convert_ppk_to_openssh(ppk_content)
        
        # Write output file
        with open(args.output_file, 'w') as f:
            f.write(openssh_key)
        
        print(f"Successfully converted {args.input_file} to {args.output_file}")
        print(f"Set permissions with: chmod 600 {args.output_file}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()   
