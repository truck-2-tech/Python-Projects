# JWT Privilege Escalation Tool

## Overview

A Python script for automating JWT `alg:none` privilege escalation attacks. It logs in with user credentials, detects restricted admin access, and forges an unsigned admin token to bypass authentication.

## Vulnerability Background

The `alg:none` vulnerability occurs when a JWT verifier trusts the `alg` header field and accepts `"alg": "none"` as valid. This allows attackers to forge tokens by changing the header to `{"alg": "none"}`, modifying the payload (e.g., `"role": "admin"`), and removing the signature.

## Requirements

- Python 3.6+
- `requests` library

```bash
pip install requests
```

## Usage

```bash
python3 jwt_escalate.py -t <TARGET_URL> -u <USERNAME> -p <PASSWORD>
```

### Example

```bash
python3 jwt_escalate.py -t http://10.129.244.214:30080 -u langflow-bot -p 'Langfl0w@mcp2026!'
```

### Arguments

- `-t, --target`: Target base URL (required)
- `-u, --username`: Username for login (default: `user`)
- `-p, --password`: Password for login (required)

## How It Works

1. **Authentication**: Sends POST request to `/api/v1/auth`
2. **Token Extraction**: Parses `access_token` from response
3. **Privilege Test**: Attempts admin endpoints with user token
4. **Token Forgery**: If blocked, creates token with `{"alg": "none"}` and `"role": "admin"`
5. **Verification**: Tests forged token against `/api/v1/tools`, `/api/v1/admin`, `/api/v1/users`, and `/admin`

## Output

On success, the tool provides:
- Forged admin JWT token
- Confirmed working endpoint
- Ready-to-use `curl` command

## Customization

**Add Custom Endpoints**: Edit the `endpoints` list in `test_admin_access()`.

**Change Claims**: Modify parameters in `forge_none_token(sub="...", role="...")`.

## Mitigation

Developers should:
1. Pin algorithms explicitly (e.g., `algorithms=["HS256"]`)
2. Never trust the token header for algorithm selection
3. Reject `none` algorithm explicitly
4. Validate standard claims (`iss`, `aud`, `exp`)

## References

- RFC 7515 - JSON Web Signature
- Auth0: Critical Vulnerabilities in JWT Libraries
- OWASP JWT Security Cheat Sheet

*For educational and authorized security testing only.*

