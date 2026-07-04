# JWT Decoder for CTFs

A lightweight Python script designed for Capture The Flag (CTF) competitions to decode JSON Web Tokens (JWT) without verifying their signatures. This tool allows security researchers and participants to inspect the header and payload of JWTs quickly.

## Features

- **Automatic Padding Correction**: Handles Base64URL strings missing standard padding characters.
- **Dual Input Methods**: Accepts tokens via command-line arguments or standard input (piping).
- **Formatted Output**: Displays decoded Header and Payload as formatted JSON, alongside the raw signature.
- **Error Handling**: Validates JWT structure and reports decoding errors gracefully.

## Requirements

- Python 3.6+
- No external dependencies (uses only standard libraries: `sys`, `base64`, `json`).

## Usage

### Option 1: Command Line Argument
Pass the JWT directly as an argument:
```bash
python3 jwt_decode.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Option 2: Piped Input
Echo the token and pipe it into the script:
```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | python3 jwt_decode.py
```

### Option 3: From a File
Read a token from a file:
```bash
cat token.txt | python3 jwt_decode.py
```

## How It Works

1. **Input Parsing**: The script checks for command-line arguments first; if none are found, it reads from `stdin`.
2. **Validation**: Ensures the token consists of exactly three parts separated by dots (`.`).
3. **Decoding**:
   - Replaces URL-safe characters (`-`, `_`) with standard Base64 characters (`+`, `/`).
   - Adds necessary padding (`=`) if missing.
   - Decodes the Base64 string and parses the resulting JSON.
4. **Output**: Prints the Header, Payload, and raw Signature in a readable format.

## Example Output

```text
============================================================
JWT DECODED
============================================================

[1] HEADER:
{
  "alg": "HS256",
  "typ": "JWT"
}

[2] PAYLOAD:
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}

[3] SIGNATURE (Raw):
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

============================================================
```

## Security Note

This tool **does not verify signatures**. It is intended for educational purposes and CTF challenges where the goal is to inspect token contents or manipulate claims. Do not use this to validate tokens in production environments.



